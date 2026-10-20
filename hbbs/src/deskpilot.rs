//! DeskPilot integration: everything this fork adds on top of the open-source hbbs lives here.
//!
//! When `DESKPILOT_URL` is not set, none of this is active and hbbs behaves exactly as upstream.
//!
//! * Key exchange with clients (v0 and v1, signed parameters), so that logged-in clients can
//!   send their access token to hbbs.
//! * Policy pulled from DeskPilot every few seconds (blocked devices, mandatory deployment,
//!   IDs to release), applied locally so the UDP loop never waits on HTTP.
//! * Connection authorization: every punch-hole / relay request is checked against DeskPilot,
//!   which may refuse it, pick a relay, restrict permissions and tag it for the audit log.
//! * ID change requested by the client (`RegisterPk.old_id`).
//! * Presence: IDs currently registered are reported to DeskPilot.

use crate::common::get_arg;
use crate::peer::PeerMap;
use hbb_common::{
    bail,
    bytes::{BufMut, BytesMut},
    log,
    protobuf::{Message as _, MessageField},
    rendezvous_proto::*,
    tokio::{self, time::Duration},
    ResultType,
};
use serde_derive::{Deserialize, Serialize};
use sodiumoxide::crypto::{box_, generichash, secretbox, sign};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex, RwLock},
    time::Instant,
};

const SYNC_INTERVAL: Duration = Duration::from_secs(10);
const HTTP_TIMEOUT: Duration = Duration::from_secs(4);
const DECISION_TTL_SECS: u64 = 15;
/// A peer is reported online while it re-registered within this window (same as hbbs REG_TIMEOUT).
const ONLINE_WINDOW_MS: u128 = 30_000;

// ---------------------------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------------------------

struct Hook {
    url: String,
    secret: String,
    fail_open: bool,
    http: reqwest::Client,
    policy: RwLock<Option<Policy>>,
    decisions: Mutex<HashMap<(String, String, i32), (Instant, Decision)>>,
}

lazy_static::lazy_static! {
    static ref HOOK: Option<Arc<Hook>> = Hook::from_env();
}

impl Hook {
    fn from_env() -> Option<Arc<Hook>> {
        let url = get_arg("DESKPILOT_URL").trim().trim_end_matches('/').to_owned();
        if url.is_empty() {
            return None;
        }
        let secret = get_arg("DESKPILOT_SECRET");
        if secret.is_empty() {
            log::warn!("DESKPILOT_SECRET is empty, DeskPilot will refuse hbbs calls");
        }
        let fail_open = get_arg("DESKPILOT_FAIL_MODE").to_lowercase() != "closed";
        let http = match reqwest::Client::builder().timeout(HTTP_TIMEOUT).build() {
            Ok(c) => c,
            Err(err) => {
                log::error!("DeskPilot integration disabled, cannot build HTTP client: {}", err);
                return None;
            }
        };
        log::info!(
            "DeskPilot integration enabled: {} (fail mode: {})",
            url,
            if fail_open { "open" } else { "closed" }
        );
        Some(Arc::new(Hook {
            url,
            secret,
            fail_open,
            http,
            policy: RwLock::new(None),
            decisions: Mutex::new(HashMap::new()),
        }))
    }

    async fn post<B: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> ResultType<R> {
        let rsp = self
            .http
            .post(format!("{}{}", self.url, path))
            .bearer_auth(&self.secret)
            .json(body)
            .send()
            .await?;
        let status = rsp.status();
        if !status.is_success() {
            bail!("DeskPilot {} returned HTTP {}", path, status);
        }
        Ok(rsp.json::<R>().await?)
    }
}

#[inline]
pub fn enabled() -> bool {
    HOOK.is_some()
}

// ---------------------------------------------------------------------------------------------
// Policy (pulled) and presence (pushed)
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
struct Policy {
    #[serde(default)]
    require_deploy: bool,
    #[serde(default)]
    deployed: HashSet<String>,
    #[serde(default)]
    blocked: HashSet<String>,
    #[serde(default)]
    remove: Vec<String>,
}

#[derive(Serialize)]
struct SyncRequest<'a> {
    online: &'a [String],
    removed: &'a [String],
}

/// Whether hbbs must refuse to register `id`. Answered from the last policy, never blocks.
pub fn refuse_register(id: &str) -> bool {
    let Some(hook) = HOOK.as_ref() else {
        return false;
    };
    let Ok(policy) = hook.policy.read() else {
        return false;
    };
    match policy.as_ref() {
        Some(p) => p.blocked.contains(id) || (p.require_deploy && !p.deployed.contains(id)),
        None => false,
    }
}

/// Result to send to a `RegisterPk` that must be refused. `NOT_DEPLOYED` makes the client stop
/// announcing itself and retry slowly; never answer `UUID_MISMATCH`, which makes it pick a new ID.
pub fn register_refusal(id: &str) -> Option<register_pk_response::Result> {
    if refuse_register(id) {
        Some(register_pk_response::Result::NOT_DEPLOYED)
    } else {
        None
    }
}

pub fn spawn_sync(pm: PeerMap) {
    let Some(hook) = HOOK.clone() else {
        return;
    };
    tokio::spawn(async move {
        let mut removed: Vec<String> = Vec::new();
        loop {
            let online = pm.online_ids(ONLINE_WINDOW_MS).await;
            let req = SyncRequest {
                online: &online,
                removed: &removed,
            };
            match hook.post::<_, Policy>("/api/hbbs/sync", &req).await {
                Ok(mut policy) => {
                    removed.clear();
                    for id in std::mem::take(&mut policy.remove) {
                        match pm.remove(&id).await {
                            Ok(()) => {
                                log::info!("DeskPilot released id {}", id);
                                removed.push(id);
                            }
                            Err(err) => log::error!("Failed to release id {}: {}", id, err),
                        }
                    }
                    if let Ok(mut lock) = hook.policy.write() {
                        *lock = Some(policy);
                    }
                }
                Err(err) => log::warn!("DeskPilot sync failed: {}", err),
            }
            tokio::time::sleep(SYNC_INTERVAL).await;
        }
    });
}

// ---------------------------------------------------------------------------------------------
// Connection authorization
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Decision {
    #[serde(default)]
    pub allow: bool,
    #[serde(default)]
    pub reason: String,
    /// Relay server to use for this connection, empty to keep the hbbs choice.
    #[serde(default)]
    pub relay: String,
    /// `ControlPermissions.permissions` bit field (2 bits per permission), 0 for none.
    #[serde(default)]
    pub permissions: u64,
    /// Sent to the controlled side, which echoes it in its connection audit.
    #[serde(default)]
    pub audit_ref: String,
}

impl Decision {
    pub fn control_permissions(&self) -> MessageField<ControlPermissions> {
        if self.permissions == 0 {
            MessageField::none()
        } else {
            MessageField::some(ControlPermissions {
                permissions: self.permissions,
                ..Default::default()
            })
        }
    }

    pub fn controlled_context(&self) -> MessageField<ControlledContext> {
        if self.audit_ref.is_empty() {
            MessageField::none()
        } else {
            MessageField::some(ControlledContext {
                conn_audit_ref: self.audit_ref.clone(),
                ..Default::default()
            })
        }
    }
}

#[derive(Serialize)]
struct ConnectRequest<'a> {
    id: &'a str,
    token: &'a str,
    ip: &'a str,
    conn_type: i32,
    relay: bool,
}

/// Asks DeskPilot whether the holder of `token` (possibly empty) may connect to `id`.
/// `None` when the integration is off. A punch and the relay request that follows it within a
/// few seconds share one decision, hence one audit reference.
pub async fn check_connect(id: &str, token: &str, ip: &str, conn_type: i32, relay: bool) -> Option<Decision> {
    let hook = HOOK.as_ref()?;
    let key = (id.to_owned(), token.to_owned(), conn_type);
    if let Ok(mut cache) = hook.decisions.lock() {
        cache.retain(|_, (tm, _)| tm.elapsed().as_secs() < DECISION_TTL_SECS);
        if let Some((_, d)) = cache.get(&key) {
            return Some(d.clone());
        }
    }
    let req = ConnectRequest {
        id,
        token,
        ip,
        conn_type,
        relay,
    };
    let decision = match hook.post::<_, Decision>("/api/hbbs/connect", &req).await {
        Ok(d) => d,
        Err(err) => {
            log::warn!("DeskPilot authorization unavailable for {}: {}", id, err);
            return Some(Decision {
                allow: hook.fail_open,
                reason: "Authorization server unavailable, try again later".to_owned(),
                ..Default::default()
            });
        }
    };
    if !decision.allow {
        log::info!("Connection to {} from {} refused: {}", id, ip, decision.reason);
    }
    if let Ok(mut cache) = hook.decisions.lock() {
        cache.insert(key, (Instant::now(), decision.clone()));
    }
    Some(decision)
}

/// Adds the decision's permissions and audit reference to what is forwarded to the controlled side.
pub fn apply_decision(msg: &mut RendezvousMessage, d: &Decision) {
    match msg.union.as_mut() {
        Some(rendezvous_message::Union::PunchHole(ph)) => {
            ph.control_permissions = d.control_permissions();
            ph.controlled_context = d.controlled_context();
        }
        Some(rendezvous_message::Union::FetchLocalAddr(fla)) => {
            fla.control_permissions = d.control_permissions();
            fla.controlled_context = d.controlled_context();
        }
        _ => {}
    }
}

pub fn refused_punch(reason: &str) -> RendezvousMessage {
    let mut msg_out = RendezvousMessage::new();
    msg_out.set_punch_hole_response(PunchHoleResponse {
        other_failure: non_empty(reason, "Access denied by the server"),
        ..Default::default()
    });
    msg_out
}

pub fn refused_relay(rf: &RequestRelay, reason: &str) -> RendezvousMessage {
    let mut msg_out = RendezvousMessage::new();
    msg_out.set_relay_response(RelayResponse {
        uuid: rf.uuid.clone(),
        refuse_reason: non_empty(reason, "Access denied by the server"),
        ..Default::default()
    });
    msg_out
}

fn non_empty(s: &str, fallback: &str) -> String {
    if s.is_empty() {
        fallback.to_owned()
    } else {
        s.to_owned()
    }
}

// ---------------------------------------------------------------------------------------------
// ID change (RegisterPk with old_id, sent by the client over TCP)
// ---------------------------------------------------------------------------------------------

#[derive(Serialize)]
struct ChangeIdRequest<'a> {
    old_id: &'a str,
    new_id: &'a str,
    uuid: String,
    ip: &'a str,
}

#[derive(Deserialize)]
struct ChangeIdResponse {
    #[serde(default)]
    result: String,
}

pub async fn change_id(pm: &PeerMap, rk: &RegisterPk, ip: &str) -> register_pk_response::Result {
    use register_pk_response::Result::*;
    let Some(hook) = HOOK.as_ref() else {
        return NOT_SUPPORT;
    };
    let old_id = rk.old_id.as_str();
    let new_id = rk.id.as_str();
    if old_id.is_empty() || rk.uuid.is_empty() {
        return NOT_SUPPORT;
    }
    if !hbb_common::is_valid_custom_id(new_id) {
        return INVALID_ID_FORMAT;
    }
    if old_id == new_id {
        return OK;
    }
    let Some(old_peer) = pm.get(old_id).await else {
        return UUID_MISMATCH;
    };
    if old_peer.read().await.uuid != rk.uuid {
        log::warn!("ID change {} -> {} refused: uuid mismatch", old_id, new_id);
        return UUID_MISMATCH;
    }
    if let Some(other) = pm.get(new_id).await {
        if other.read().await.uuid != rk.uuid {
            return ID_EXISTS;
        }
    }
    let req = ChangeIdRequest {
        old_id,
        new_id,
        uuid: base64::encode(&rk.uuid),
        ip,
    };
    match hook.post::<_, ChangeIdResponse>("/api/hbbs/change-id", &req).await {
        Ok(r) if r.result == "OK" => {}
        Ok(r) if r.result == "ID_EXISTS" => return ID_EXISTS,
        Ok(r) => {
            log::info!("ID change {} -> {} refused by DeskPilot: {}", old_id, new_id, r.result);
            return NOT_SUPPORT;
        }
        Err(err) => {
            log::warn!("ID change {} -> {}: DeskPilot unavailable: {}", old_id, new_id, err);
            return SERVER_ERROR;
        }
    }
    match pm.rename(old_id, new_id).await {
        Ok(()) => {
            log::info!("ID changed {} -> {}", old_id, new_id);
            OK
        }
        Err(err) => {
            log::error!("ID change {} -> {} failed: {}", old_id, new_id, err);
            SERVER_ERROR
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Key exchange (server side of the client's `secure_tcp`)
// ---------------------------------------------------------------------------------------------

/// Newest key exchange version this server speaks.
const KX_VERSION: u32 = 1;
const KX_PARAMS_DOMAIN: &[u8] = b"rdkx-params";
const KX_SPLIT_CONTEXT: &[u8] = b"rdkx-spl";
const KX_SPLIT_INITIATOR: u8 = 1;
const KX_SPLIT_RESPONDER: u8 = 2;

/// The server's half of a pending exchange, kept until the client answers.
pub struct KxOffer {
    sent_pk: [u8; box_::PUBLICKEYBYTES],
    sk: box_::SecretKey,
}

/// Key exchange is offered on TCP connections when the integration is on and hbbs has a
/// signing key. Clients that do not want it skip the offer; it costs one message.
pub fn kx_offer(server_sk: Option<&sign::SecretKey>) -> Option<(RendezvousMessage, KxOffer)> {
    if !enabled() {
        return None;
    }
    let server_sk = server_sk?;
    let (pk, sk) = box_::gen_keypair();
    let mut sent_pk = pk.0;
    // Bit 255 tells the client that the parameters below are signed and must be checked.
    // X25519 ignores that bit, so the key itself is unchanged.
    sent_pk[31] |= 0x80;
    let params = KxParams {
        pk: sent_pk.to_vec().into(),
        version: KX_VERSION,
        ..Default::default()
    };
    let params = params.write_to_bytes().ok()?;
    let mut signed_input = KX_PARAMS_DOMAIN.to_vec();
    signed_input.extend_from_slice(&params);
    let mut msg_out = RendezvousMessage::new();
    msg_out.set_key_exchange(KeyExchange {
        keys: vec![sign::sign(&sent_pk, server_sk).into()],
        version: KX_VERSION,
        signed_params: sign::sign(&signed_input, server_sk).into(),
        ..Default::default()
    });
    Some((msg_out, KxOffer { sent_pk, sk }))
}

/// Completes the exchange from the client's `KeyExchange { keys: [its pk, sealed key], version }`.
pub fn kx_accept(offer: &KxOffer, ex: &KeyExchange) -> ResultType<(SendCipher, RecvCipher)> {
    if ex.keys.len() != 2 {
        bail!("invalid key exchange from client");
    }
    let their_pk = &ex.keys[0];
    if their_pk.len() != box_::PUBLICKEYBYTES {
        bail!("invalid client public key length");
    }
    let mut pk = [0u8; box_::PUBLICKEYBYTES];
    pk.copy_from_slice(their_pk);
    let nonce = box_::Nonce([0u8; box_::NONCEBYTES]);
    let symmetric = box_::open(&ex.keys[1], &nonce, &box_::PublicKey(pk), &offer.sk)
        .map_err(|_| hbb_common::anyhow::anyhow!("key exchange: box decryption failure"))?;
    if symmetric.len() != secretbox::KEYBYTES {
        bail!("key exchange: invalid symmetric key length");
    }
    let mut key = [0u8; secretbox::KEYBYTES];
    key.copy_from_slice(&symmetric);
    let key = secretbox::Key(key);
    match ex.version {
        0 => Ok((SendCipher::new(key.clone()), RecvCipher::new(key))),
        1 => {
            // The client sealed the key, so it is the initiator: we send under the responder
            // subkey and receive under the initiator subkey.
            let t = Transcript {
                initiator_pk: their_pk,
                responder_pk: &offer.sent_pk,
                advertised: KX_VERSION,
                picked: 1,
            };
            let initiator = derive_subkey(&key, KX_SPLIT_INITIATOR, &t)?;
            let responder = derive_subkey(&key, KX_SPLIT_RESPONDER, &t)?;
            Ok((SendCipher::new(responder), RecvCipher::new(initiator)))
        }
        v => bail!("unsupported key exchange version {}", v),
    }
}

struct Transcript<'a> {
    initiator_pk: &'a [u8],
    responder_pk: &'a [u8],
    advertised: u32,
    picked: u32,
}

fn derive_subkey(key: &secretbox::Key, direction: u8, t: &Transcript) -> ResultType<secretbox::Key> {
    let failed = |_| hbb_common::anyhow::anyhow!("key derivation failed");
    let mut h = generichash::State::new(Some(secretbox::KEYBYTES), Some(&key.0)).map_err(failed)?;
    for part in [
        KX_SPLIT_CONTEXT,
        &[direction],
        &t.advertised.to_le_bytes(),
        &t.picked.to_le_bytes(),
        t.initiator_pk,
        t.responder_pk,
    ] {
        h.update(part).map_err(failed)?;
    }
    let digest = h.finalize().map_err(failed)?;
    let mut subkey = [0u8; secretbox::KEYBYTES];
    subkey.copy_from_slice(digest.as_ref());
    Ok(secretbox::Key(subkey))
}

fn nonce(seq: u64) -> secretbox::Nonce {
    let mut n = secretbox::Nonce([0u8; secretbox::NONCEBYTES]);
    n.0[..8].copy_from_slice(&seq.to_le_bytes());
    n
}

/// Same framing as the client's `Encrypt`: one secretbox per frame, nonce = frame counter.
pub struct SendCipher {
    key: secretbox::Key,
    seq: u64,
}

impl SendCipher {
    fn new(key: secretbox::Key) -> Self {
        Self { key, seq: 0 }
    }

    pub fn enc(&mut self, data: &[u8]) -> Vec<u8> {
        self.seq += 1;
        secretbox::seal(data, &nonce(self.seq), &self.key)
    }
}

pub struct RecvCipher {
    key: secretbox::Key,
    seq: u64,
}

impl RecvCipher {
    fn new(key: secretbox::Key) -> Self {
        Self { key, seq: 0 }
    }

    pub fn dec(&mut self, bytes: &mut BytesMut) -> ResultType<()> {
        if bytes.len() <= 1 {
            return Ok(());
        }
        self.seq += 1;
        match secretbox::open(bytes, &nonce(self.seq), &self.key) {
            Ok(plain) => {
                bytes.clear();
                bytes.put_slice(&plain);
                Ok(())
            }
            Err(()) => bail!("decryption error"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs the client side of the exchange exactly as rustdesk/src/common.rs does and checks
    /// both directions decrypt.
    #[test]
    fn key_exchange_v1_roundtrip() {
        sodiumoxide::init().unwrap();
        let (server_pk, server_sk) = sign::gen_keypair();
        let (pk, sk) = box_::gen_keypair();
        let mut sent_pk = pk.0;
        sent_pk[31] |= 0x80;
        let offer = KxOffer { sent_pk, sk };
        let signed = sign::sign(&sent_pk, &server_sk);

        // Client
        let their_pk_b = sign::verify(&signed, &server_pk).unwrap();
        let mut their = [0u8; 32];
        their.copy_from_slice(&their_pk_b);
        let (client_pk, client_sk) = box_::gen_keypair();
        let key = secretbox::gen_key();
        let sealed = box_::seal(
            &key.0,
            &box_::Nonce([0u8; box_::NONCEBYTES]),
            &box_::PublicKey(their),
            &client_sk,
        );
        let ex = KeyExchange {
            keys: vec![client_pk.0.to_vec().into(), sealed.into()],
            version: 1,
            ..Default::default()
        };
        let (mut send, mut recv) = kx_accept(&offer, &ex).unwrap();

        let t = Transcript {
            initiator_pk: &client_pk.0,
            responder_pk: &their,
            advertised: 1,
            picked: 1,
        };
        let c_send = derive_subkey(&key, KX_SPLIT_INITIATOR, &t).unwrap();
        let c_recv = derive_subkey(&key, KX_SPLIT_RESPONDER, &t).unwrap();

        let from_client = secretbox::seal(b"hello", &nonce(1), &c_send);
        let mut buf = BytesMut::from(&from_client[..]);
        recv.dec(&mut buf).unwrap();
        assert_eq!(&buf[..], b"hello");

        let from_server = send.enc(b"world");
        assert_eq!(secretbox::open(&from_server, &nonce(1), &c_recv).unwrap(), b"world");
    }
}
