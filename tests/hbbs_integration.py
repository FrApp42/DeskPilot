#!/usr/bin/env python3
"""
End-to-end test of the DeskPilot hbbs fork against DeskPilot, using hbbs-compat (built on the
current RustDesk client networking code) for both the controlled device and the controlling client.

Prerequisites: DeskPilot on DESKPILOT (default http://127.0.0.1:21114) with DeskPilot__HbbsSecret set,
the forked hbbs on 127.0.0.1:21116 with DESKPILOT_URL / DESKPILOT_SECRET, psql access to the database.

    python3 tests/hbbs_integration.py --compat tests/hbbs-compat/target/debug/hbbs-compat \
        --key <hbbs public key> --admin admin --password 'Admin123!' --psql 'psql -d deskpilot'
"""
import argparse
import base64
import json
import os
import shlex
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid

p = argparse.ArgumentParser()
p.add_argument("--compat", required=True)
p.add_argument("--key", required=True)
p.add_argument("--admin", default="admin")
p.add_argument("--password", required=True)
p.add_argument("--psql", default="psql -d deskpilot")
p.add_argument("--deskpilot", default="http://127.0.0.1:21114")
args = p.parse_args()

FAILED = 0
SYNC_WAIT = 12  # hbbs syncs every 10 s


def check(name, cond, detail=""):
    global FAILED
    print(("  ok   " if cond else "  FAIL ") + name + ("" if cond else f"  -> {detail}"))
    if not cond:
        FAILED += 1


def sql(q):
    out = subprocess.run(shlex.split(args.psql) + ["-tAc", q], capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(out.stderr)
    return out.stdout.strip()


def api(path, body):
    req = urllib.request.Request(args.deskpilot + path, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r:
        t = r.read().decode()
        return json.loads(t) if t.strip().startswith(("{", "[")) else t


def compat(*a, env=None):
    e = dict(os.environ, **(env or {}))
    out = subprocess.run([args.compat, *a, "--key", args.key], capture_output=True, text=True, env=e, timeout=30)
    events = [json.loads(l) for l in out.stdout.splitlines() if l.startswith("{")]
    if out.returncode != 0:
        events.append({"event": "error", "stderr": out.stderr.strip()[-300:]})
    return events


def last(events, kind):
    return next((e for e in reversed(events) if e["event"] == kind), None)


def setting(key, value):
    sql(f"insert into \"Settings\"(\"Key\",\"Value\") values('{key}','{value}') "
        f"on conflict (\"Key\") do update set \"Value\"=excluded.\"Value\"")
    time.sleep(6)  # DeskPilot settings cache


class Peer:
    """Controlled device: registers over UDP and logs what hbbs forwards to it."""

    def __init__(self, rid, uid):
        self.rid, self.uid = rid, uid
        self.log = tempfile.NamedTemporaryFile("w+", delete=False, suffix=".jsonl")
        self.proc = subprocess.Popen([args.compat, "peer", "--id", rid, "--uuid", uid, "--hold", "600"],
                                     stdout=self.log, stderr=subprocess.DEVNULL)

    def events(self):
        with open(self.log.name) as f:
            return [json.loads(l) for l in f if l.startswith("{")]

    def wait(self, kind, after=0, timeout=8, pred=lambda e: True):
        end = time.time() + timeout
        while time.time() < end:
            evs = self.events()[after:]
            for e in evs:
                if e["event"] == kind and pred(e):
                    return e
            time.sleep(0.3)
        return None

    def mark(self):
        return len(self.events())

    def stop(self):
        self.proc.kill()


suffix = uuid.uuid4().hex[:6]
B = "1" + str(uuid.uuid4().int)[:9]
B_UUID = "compat-uuid-" + suffix
NEW_ID = "dp" + suffix + "x"

for k in ("access.mode", "device.require_known", "device.allow_id_change"):
    sql(f"delete from \"Settings\" where \"Key\"='{k}'")

print("registration and presence")
peer = Peer(B, B_UUID)
e = peer.wait("register_pk_response")
check("device registers", e and e["result"] == "Ok(OK)", e)
api("/api/sysinfo", {"id": B, "uuid": base64.b64encode(B_UUID.encode()).decode(), "hostname": "compat-b",
                     "os": "linux / test", "version": "1.4.3"})
sql(f"update \"Devices\" set \"LastSeenAt\" = now() - interval '1 hour' where \"RustdeskId\"='{B}'")
time.sleep(SYNC_WAIT)
age = float(sql(f"select extract(epoch from now() - \"LastSeenAt\") from \"Devices\" where \"RustdeskId\"='{B}'"))
check("presence reported by hbbs", age < 15, age)

admin = api("/api/login", {"username": args.admin, "password": args.password, "type": "account",
                           "id": "999000111", "uuid": "compat-admin"})["access_token"]

print("open mode")
m = peer.mark()
r = compat("punch", "--id", B)
fwd = peer.wait("fetch_local_addr", m)
check("anonymous punch forwarded", fwd is not None, r)
check("audit reference attached", fwd and len(fwd["audit_ref"]) == 32, fwd)

print("account required")
setting("access.mode", "login")
# hbbs caches a decision 15 s per (id, token, conn type): vary the conn type between modes.
resp = last(compat("punch", "--id", B, "--conn-type", "1"), "punch_response")
check("anonymous punch refused with reason", resp and "Connectez-vous" in resp["other_failure"], resp)
m = peer.mark()
r = compat("punch", "--id", B, "--token", admin, "--kx")
kx = last(r, "kx")
check("key exchange v1 with the client code", kx and kx["version"] == 1, r)
check("logged-in punch forwarded", peer.wait("fetch_local_addr", m) is not None, r)
m = peer.mark()
r = compat("punch", "--id", B, "--token", admin + "", "--kx", env={"KX_VERSION": "0"})
# Same (id, token) as above is cached in hbbs; the forward still has to happen.
check("key exchange v0 accepted", last(r, "kx") and last(r, "kx")["version"] == 0, r)
check("v0 punch forwarded", peer.wait("fetch_local_addr", m) is not None, r)
bad = last(compat("punch", "--id", B, "--token", "not-a-token", "--kx"), "punch_response")
check("invalid token refused", bad and "Connectez-vous" in bad["other_failure"], bad)

print("account and groups")
setting("access.mode", "groups")
uid = sql("select \"Id\" from \"Users\" where \"Name\"='bob'") or None
if not uid:
    sql("insert into \"UserGroups\"(\"Name\",\"DeniedPermissions\") values('compat-group','{file,clipboard}') on conflict do nothing")
    gid = sql("select \"Id\" from \"UserGroups\" where \"Name\"='compat-group'")
    # Password "Bob-password-1" hashed by DeskPilot is not reachable from here: give bob a token directly.
    sql(f"insert into \"Users\"(\"Name\",\"IsAdmin\",\"Status\",\"TotpEnabled\",\"UserGroupId\",\"CreatedAt\") "
        f"values('bob',false,1,false,{gid},now())")
    uid = sql("select \"Id\" from \"Users\" where \"Name\"='bob'")
gid = sql("select \"UserGroupId\" from \"Users\" where \"Name\"='bob'")
bob_token = "compat-bob-" + suffix
import hashlib
sql(f"insert into \"AccessTokens\"(\"TokenHash\",\"UserId\",\"CreatedAt\",\"ExpiresAt\",\"LastUsedAt\") values("
    f"'{hashlib.sha256(bob_token.encode()).hexdigest().upper()}',{uid},now(),now()+interval '1 day',now())")
resp = last(compat("punch", "--id", B, "--token", bob_token, "--kx"), "punch_response")
check("user without access refused", resp and "pas accès" in resp["other_failure"], resp)

sql("insert into \"DeviceGroups\"(\"Name\",\"RelayServer\") values('compat-dg','relay.example.org:21117') on conflict do nothing")
dg = sql("select \"Id\" from \"DeviceGroups\" where \"Name\"='compat-dg'")
sql(f"update \"Devices\" set \"DeviceGroupId\"={dg} where \"RustdeskId\"='{B}'")
sql(f"insert into \"DeviceGroupAccesses\"(\"UserGroupId\",\"DeviceGroupId\") values({gid},{dg}) on conflict do nothing")
bob_token2 = bob_token + "b"
sql(f"insert into \"AccessTokens\"(\"TokenHash\",\"UserId\",\"CreatedAt\",\"ExpiresAt\",\"LastUsedAt\") values("
    f"'{hashlib.sha256(bob_token2.encode()).hexdigest().upper()}',{uid},now(),now()+interval '1 day',now())")
m = peer.mark()
compat("punch", "--id", B, "--token", bob_token2, "--kx")
fwd = peer.wait("fetch_local_addr", m)
check("access through device group", fwd is not None)
check("permissions restricted (file, clipboard)", fwd and fwd["permissions"] == (1 << 6) | (1 << 4), fwd)
check("relay of the device group", fwd and fwd["relay_server"] == "relay.example.org:21117", fwd)
who = sql(f"select \"UserName\" from \"ConnectDecisions\" where \"AuditRef\"='{fwd['audit_ref'] if fwd else ''}'")
check("decision logged with the account", who == "bob", who)
m = peer.mark()
r = compat("relay", "--id", B, "--token", bob_token2, "--kx")
rel = peer.wait("request_relay", m)
check("relay request forwarded with permissions", rel and rel["permissions"] == 80, (r, rel))
r = last(compat("relay", "--id", B, "--conn-type", "2"), "relay_response")
check("anonymous relay refused", r and r["refuse_reason"], r)

print("blocking")
setting("access.mode", "off")
sql(f"update \"Devices\" set \"Blocked\"=true where \"RustdeskId\"='{B}'")
m = peer.mark()
e = peer.wait("register_pk_response", m, timeout=SYNC_WAIT + 8, pred=lambda e: e["result"] == "Ok(NOT_DEPLOYED)")
check("blocked device is refused (NOT_DEPLOYED)", e is not None)
resp = last(compat("punch", "--id", B, "--conn-type", "3"), "punch_response")
check("connection to blocked device refused", resp and ("bloqué" in resp["other_failure"] or resp["failure"] == 2), resp)
sql(f"update \"Devices\" set \"Blocked\"=false where \"RustdeskId\"='{B}'")
m = peer.mark()
e = peer.wait("register_pk_response", m, timeout=SYNC_WAIT + 10, pred=lambda e: e["result"] == "Ok(OK)")
check("unblocked device registers again", e is not None)

print("ID change")
sql(f"insert into \"AddressBooks\"(\"Guid\",\"Name\",\"IsPersonal\",\"OwnerId\",\"CreatedAt\") "
    f"select 'compat-ab-{suffix}','compat',false,\"Id\",now() from \"Users\" where \"Name\"='{args.admin}'")
ab = sql(f"select \"Id\" from \"AddressBooks\" where \"Guid\"='compat-ab-{suffix}'")
sql(f"insert into \"AbPeers\"(\"AddressBookId\",\"PeerId\",\"Tags\",\"ForceAlwaysRelay\",\"CreatedAt\") values({ab},'{B}','{{}}',false,now())")
r = last(compat("change-id", "--old", B, "--new", NEW_ID, "--uuid", "someone-else"), "register_pk_response")
check("wrong uuid refused", r and r["result"] == "Ok(UUID_MISMATCH)", r)
setting("device.allow_id_change", "false")
r = last(compat("change-id", "--old", B, "--new", NEW_ID, "--uuid", B_UUID, "--kx"), "register_pk_response")
check("refused when disabled", r and r["result"] == "Ok(NOT_SUPPORT)", r)
setting("device.allow_id_change", "true")
r = last(compat("change-id", "--old", B, "--new", "1bad id", "--uuid", B_UUID), "register_pk_response")
check("invalid format refused", r and r["result"] == "Ok(INVALID_ID_FORMAT)", r)
r = last(compat("change-id", "--old", B, "--new", NEW_ID, "--uuid", B_UUID, "--kx"), "register_pk_response")
check("ID change accepted", r and r["result"] == "Ok(OK)", r)
check("device renamed in DeskPilot", sql(f"select count(*) from \"Devices\" where \"RustdeskId\"='{NEW_ID}'") == "1")
check("address book follows", sql(f"select \"PeerId\" from \"AbPeers\" where \"AddressBookId\"={ab}") == NEW_ID)
check("history recorded", sql(f"select count(*) from \"DeviceIdChanges\" where \"NewId\"='{NEW_ID}'") == "1")
with open(f"/tmp/hbbs-compat-{B}.id", "w") as f:
    f.write(NEW_ID)
m = peer.mark()
e = peer.wait("register_pk_response", m, timeout=8, pred=lambda e: e["id"] == NEW_ID)
check("device registers under its new ID", e and e["result"] == "Ok(OK)", e)
m = peer.mark()
compat("punch", "--id", NEW_ID)
check("new ID reachable", peer.wait("fetch_local_addr", m) is not None)
resp = last(compat("punch", "--id", B), "punch_response")
check("old ID gone", resp and resp["failure"] == 0, resp)

print("ID release")
peer.stop()
os.remove(f"/tmp/hbbs-compat-{B}.id")
sql(f"insert into \"IdReleases\"(\"RustdeskId\",\"CreatedAt\") values('{NEW_ID}',now())")
time.sleep(2 * SYNC_WAIT)
check("release acknowledged by hbbs", sql(f"select count(*) from \"IdReleases\" where \"RustdeskId\"='{NEW_ID}'") == "0")
resp = last(compat("punch", "--id", NEW_ID), "punch_response")
check("released ID no longer exists", resp and resp["failure"] == 0, resp)

print(f"\n{'ALL PASSED' if FAILED == 0 else f'{FAILED} FAILED'}")
sys.exit(1 if FAILED else 0)
