//! hbbs-compat <command> [args]
//!
//!   peer      --id ID --uuid UUID [--hold SECS]     register over UDP like a controlled device,
//!                                                   then print what hbbs forwards (JSON lines)
//!   punch     --id ID [--token T] [--kx]            punch-hole request like a controlling client
//!   relay     --id ID [--token T] [--kx]            relay request
//!   change-id --old ID --new ID --uuid UUID [--kx]  ID change
//!
//! Common: --server HOST:PORT (default 127.0.0.1:21116) --key PUBKEY_BASE64
//! `--kx` runs the client's key exchange (rustdesk/src/common.rs `key_exchange`) first.

use hbb_common::{
    anyhow::{anyhow, Context},
    bail,
    bytes::Bytes,
    protobuf::Message as _,
    rendezvous_proto::*,
    sodiumoxide::crypto::{box_, secretbox, sign},
    tcp::{FramedStream, KxTranscript},
    tokio,
    udp::FramedSocket,
    ResultType,
};
use std::{collections::HashMap, time::Duration};

fn args() -> (String, HashMap<String, String>) {
    let mut it = std::env::args().skip(1);
    let cmd = it.next().unwrap_or_default();
    let mut map = HashMap::new();
    let rest: Vec<String> = it.collect();
    let mut i = 0;
    while i < rest.len() {
        let k = rest[i].trim_start_matches("--").to_owned();
        if i + 1 < rest.len() && !rest[i + 1].starts_with("--") {
            map.insert(k, rest[i + 1].clone());
            i += 2;
        } else {
            map.insert(k, String::new());
            i += 1;
        }
    }
    (cmd, map)
}

fn print(kind: &str, v: hbb_common::serde_json::Value) {
    let mut v = v;
    v["event"] = kind.into();
    println!("{}", v);
}

/// Verbatim logic of rustdesk/src/common.rs `key_exchange` (client side).
async fn key_exchange(conn: &mut FramedStream, key: &str) -> ResultType<u32> {
    let pk = hbb_common::base64::decode(key)?;
    if pk.len() != 32 {
        bail!("invalid key");
    }
    let mut tmp = [0u8; 32];
    tmp.copy_from_slice(&pk);
    let rs_pk = sign::PublicKey(tmp);
    let bytes = conn
        .next_timeout(5_000)
        .await
        .context("no key exchange from server")??;
    let msg_in = RendezvousMessage::parse_from_bytes(&bytes)?;
    let Some(rendezvous_message::Union::KeyExchange(ex)) = msg_in.union else {
        bail!("server sent something else first");
    };
    if ex.keys.len() != 1 {
        bail!("invalid key exchange message");
    }
    let their_pk_b = sign::verify(&ex.keys[0], &rs_pk).map_err(|_| anyhow!("Signature mismatch in key exchange"))?;
    let mut their = [0u8; 32];
    their.copy_from_slice(&their_pk_b);
    if their[31] & 0x80 != 0 || !ex.signed_params.is_empty() {
        let signed = sign::verify(&ex.signed_params, &rs_pk).map_err(|_| anyhow!("bad signed params"))?;
        let params = signed
            .strip_prefix(hbb_common::tcp::KX_PARAMS_DOMAIN)
            .ok_or_else(|| anyhow!("missing params domain"))?;
        let params = KxParams::parse_from_bytes(params)?;
        if params.pk[..] != their[..] || params.version != ex.version {
            bail!("Key exchange version or public key does not match its signature");
        }
    }
    let their_pk = box_::PublicKey(their);
    let (our_pk_b, our_sk_b) = box_::gen_keypair();
    let key = secretbox::gen_key();
    let sealed = box_::seal(&key.0, &box_::Nonce([0u8; box_::NONCEBYTES]), &their_pk, &our_sk_b);
    let asymmetric_value: Bytes = our_pk_b.0.to_vec().into();
    let forced = std::env::var("KX_VERSION").ok().and_then(|v| v.parse::<u32>().ok());
    let picked = forced.unwrap_or_else(|| hbb_common::tcp::kx_version_for(ex.version));
    let mut msg_out = RendezvousMessage::new();
    msg_out.set_key_exchange(KeyExchange {
        keys: vec![asymmetric_value.clone(), sealed.into()],
        version: picked,
        ..Default::default()
    });
    conn.send(&msg_out).await?;
    if picked == 0 {
        conn.set_key(key);
    } else {
        conn.set_key_split(
            key,
            true,
            &KxTranscript {
                initiator_pk: &asymmetric_value,
                responder_pk: &their,
                advertised: ex.version,
                picked,
            },
        )?;
    }
    Ok(picked)
}

/// Like rustdesk `get_next_nonkeyexchange_msg`.
async fn next_msg(conn: &mut FramedStream, ms: u64) -> Option<RendezvousMessage> {
    for _ in 0..2 {
        let bytes = conn.next_timeout(ms).await?.ok()?;
        let msg = RendezvousMessage::parse_from_bytes(&bytes).ok()?;
        if let Some(rendezvous_message::Union::KeyExchange(_)) = msg.union {
            continue;
        }
        return Some(msg);
    }
    None
}

async fn connect(a: &HashMap<String, String>) -> ResultType<(FramedStream, String)> {
    let server = a.get("server").cloned().unwrap_or("127.0.0.1:21116".into());
    let key = a.get("key").cloned().unwrap_or_default();
    let mut conn = FramedStream::new(&server, None, 5_000).await?;
    if a.contains_key("kx") {
        let v = key_exchange(&mut conn, &key).await?;
        print("kx", hbb_common::serde_json::json!({ "version": v }));
    }
    Ok((conn, key))
}

#[tokio::main]
async fn main() -> ResultType<()> {
    hbb_common::sodiumoxide::init().ok();
    let (cmd, a) = args();
    let id = a.get("id").cloned().unwrap_or_default();
    let token = a.get("token").cloned().unwrap_or_default();
    let conn_type: ConnType = a
        .get("conn-type")
        .and_then(|x| x.parse::<i32>().ok())
        .and_then(|n| <ConnType as hbb_common::protobuf::Enum>::from_i32(n))
        .unwrap_or_default();
    match cmd.as_str() {
        "punch" => {
            let (mut conn, key) = connect(&a).await?;
            let mut m = RendezvousMessage::new();
            m.set_punch_hole_request(PunchHoleRequest {
                id: id.clone(),
                token,
                licence_key: key,
                conn_type: conn_type.into(),
                version: "1.4.3".into(),
                ..Default::default()
            });
            conn.send(&m).await?;
            match next_msg(&mut conn, 3_000).await {
                Some(RendezvousMessage { union: Some(rendezvous_message::Union::PunchHoleResponse(r)), .. }) => {
                    print("punch_response", hbb_common::serde_json::json!({
                        "other_failure": r.other_failure,
                        "failure": r.failure.value(),
                        "relay_server": r.relay_server,
                    }))
                }
                Some(other) => print("other", hbb_common::serde_json::json!({ "msg": format!("{:?}", other) })),
                None => print("forwarded", hbb_common::serde_json::json!({})),
            }
        }
        "relay" => {
            let (mut conn, key) = connect(&a).await?;
            let mut m = RendezvousMessage::new();
            m.set_request_relay(RequestRelay {
                id,
                token,
                uuid: "compat-relay-uuid".into(),
                licence_key: key,
                conn_type: conn_type.into(),
                ..Default::default()
            });
            conn.send(&m).await?;
            match next_msg(&mut conn, 3_000).await {
                Some(RendezvousMessage { union: Some(rendezvous_message::Union::RelayResponse(r)), .. }) => {
                    print("relay_response", hbb_common::serde_json::json!({ "refuse_reason": r.refuse_reason }))
                }
                Some(other) => print("other", hbb_common::serde_json::json!({ "msg": format!("{:?}", other) })),
                None => print("forwarded", hbb_common::serde_json::json!({})),
            }
        }
        "change-id" => {
            let (mut conn, _) = connect(&a).await?;
            let mut m = RendezvousMessage::new();
            m.set_register_pk(RegisterPk {
                old_id: a.get("old").cloned().unwrap_or_default(),
                id: a.get("new").cloned().unwrap_or_default(),
                uuid: a.get("uuid").cloned().unwrap_or_default().into_bytes().into(),
                ..Default::default()
            });
            conn.send(&m).await?;
            match next_msg(&mut conn, 5_000).await {
                Some(RendezvousMessage { union: Some(rendezvous_message::Union::RegisterPkResponse(r)), .. }) => {
                    print("register_pk_response", hbb_common::serde_json::json!({ "result": format!("{:?}", r.result.enum_value()) }))
                }
                other => print("other", hbb_common::serde_json::json!({ "msg": format!("{:?}", other) })),
            }
        }
        "peer" => {
            let server = a.get("server").cloned().unwrap_or("127.0.0.1:21116".into());
            let addr: std::net::SocketAddr = server.parse()?;
            let uuid = a.get("uuid").cloned().unwrap_or_default();
            let hold: u64 = a.get("hold").and_then(|x| x.parse().ok()).unwrap_or(60);
            let mut socket = FramedSocket::new("0.0.0.0:0").await?;
            let (pk, _) = sign::gen_keypair();
            let register_pk = |id: &str| {
                let mut m = RendezvousMessage::new();
                m.set_register_pk(RegisterPk {
                    id: id.to_owned(),
                    uuid: uuid.clone().into_bytes().into(),
                    pk: pk.0.to_vec().into(),
                    ..Default::default()
                });
                m
            };
            let mut current_id = id.clone();
            // Like the client after NOT_DEPLOYED: keep re-sending RegisterPk (throttled).
            let mut needs_deploy = false;
            socket.send(&register_pk(&current_id), addr).await?;
            let deadline = std::time::Instant::now() + Duration::from_secs(hold);
            let mut tick = tokio::time::interval(Duration::from_secs(3));
            loop {
                if std::time::Instant::now() > deadline {
                    break;
                }
                tokio::select! {
                    _ = tick.tick() => {
                        // A changed ID is picked up from a file, like the client re-reading its config.
                        if let Ok(new_id) = std::fs::read_to_string(format!("/tmp/hbbs-compat-{}.id", id)) {
                            let new_id = new_id.trim().to_owned();
                            if !new_id.is_empty() && new_id != current_id {
                                current_id = new_id;
                                socket.send(&register_pk(&current_id), addr).await?;
                            }
                        }
                        if needs_deploy {
                            socket.send(&register_pk(&current_id), addr).await?;
                            continue;
                        }
                        let mut m = RendezvousMessage::new();
                        m.set_register_peer(RegisterPeer { id: current_id.clone(), serial: 0, ..Default::default() });
                        socket.send(&m, addr).await?;
                    }
                    res = socket.next() => {
                        let Some(Ok((bytes, _))) = res else { continue };
                        let Ok(msg) = RendezvousMessage::parse_from_bytes(&bytes) else { continue };
                        match msg.union {
                            Some(rendezvous_message::Union::RegisterPkResponse(r)) => {
                                needs_deploy = r.result.enum_value() == Ok(register_pk_response::Result::NOT_DEPLOYED);
                                print("register_pk_response",
                                    hbb_common::serde_json::json!({ "id": current_id, "result": format!("{:?}", r.result.enum_value()) }))
                            }
                            Some(rendezvous_message::Union::RegisterPeerResponse(r)) => {
                                if r.request_pk {
                                    print("request_pk", hbb_common::serde_json::json!({ "id": current_id }));
                                    socket.send(&register_pk(&current_id), addr).await?;
                                }
                            }
                            Some(rendezvous_message::Union::PunchHole(p)) => print("punch_hole", hbb_common::serde_json::json!({
                                "relay_server": p.relay_server,
                                "permissions": p.control_permissions.as_ref().map(|c| c.permissions).unwrap_or(0),
                                "audit_ref": p.controlled_context.as_ref().map(|c| c.conn_audit_ref.clone()).unwrap_or_default(),
                            })),
                            Some(rendezvous_message::Union::FetchLocalAddr(p)) => print("fetch_local_addr", hbb_common::serde_json::json!({
                                "relay_server": p.relay_server,
                                "permissions": p.control_permissions.as_ref().map(|c| c.permissions).unwrap_or(0),
                                "audit_ref": p.controlled_context.as_ref().map(|c| c.conn_audit_ref.clone()).unwrap_or_default(),
                            })),
                            Some(rendezvous_message::Union::RequestRelay(p)) => print("request_relay", hbb_common::serde_json::json!({
                                "permissions": p.control_permissions.as_ref().map(|c| c.permissions).unwrap_or(0),
                                "audit_ref": p.controlled_context.as_ref().map(|c| c.conn_audit_ref.clone()).unwrap_or_default(),
                            })),
                            _ => {}
                        }
                    }
                }
            }
        }
        _ => bail!("unknown command {}", cmd),
    }
    Ok(())
}
