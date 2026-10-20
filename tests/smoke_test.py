#!/usr/bin/env python3
"""
End-to-end check of the API as the RustDesk client calls it (same paths, verbs and payloads
as rustdesk/src/hbbs_http and flutter/lib/models). Usage:

    python3 tests/smoke_test.py http://127.0.0.1:21114 admin 'password'
"""
import json
import sys
import urllib.error
import urllib.request
import uuid

BASE, USER, PASSWORD = sys.argv[1].rstrip("/"), sys.argv[2], sys.argv[3]
TOKEN = None
FAILED = 0


def call(method, path, body=None, auth=True, raw=False):
    data = None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
    req = urllib.request.Request(BASE + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if data is None and method in ("POST", "PUT", "DELETE"):
        req.add_header("Content-Length", "0")
    if auth and TOKEN:
        req.add_header("Authorization", "Bearer " + TOKEN)
    try:
        with urllib.request.urlopen(req) as r:
            status, text = r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        status, text = e.code, e.read().decode()
    if raw:
        return status, text
    return status, (json.loads(text) if text.strip() else None)


def check(name, cond, detail=""):
    global FAILED
    print(("  ok   " if cond else "  FAIL ") + name + ("" if cond else f"  -> {detail}"))
    if not cond:
        FAILED += 1


dev_id = "1" + str(uuid.uuid4().int)[:8]
dev_uuid = "dXVpZC0" + uuid.uuid4().hex[:12]

print("auth")
s, r = call("GET", "/api/login-options", auth=False)
check("login-options is a list", s == 200 and isinstance(r, list), r)
s, r = call("POST", "/api/login", {"username": USER, "password": "wrong", "id": dev_id, "uuid": dev_uuid,
                                   "type": "account", "deviceInfo": {"os": "linux", "type": "client", "name": "smoke"}})
check("bad password -> error", s == 200 and "error" in r, r)
s, r = call("POST", "/api/login", {"username": USER, "password": PASSWORD, "id": dev_id, "uuid": dev_uuid,
                                   "autoLogin": True, "type": "account",
                                   "deviceInfo": {"os": "linux", "type": "client", "name": "smoke"}})
check("login returns access_token", s == 200 and r.get("type") == "access_token" and r.get("access_token"), r)
check("user payload has info", isinstance(r.get("user", {}).get("info"), dict), r)
TOKEN = r["access_token"]
s, r = call("POST", "/api/currentUser", {"id": dev_id, "uuid": dev_uuid})
check("currentUser", s == 200 and r["name"].lower() == USER.lower(), r)

print("device sync")
s, r = call("POST", "/api/heartbeat", {"id": dev_id, "uuid": dev_uuid, "ver": 1004000, "modified_at": 0}, auth=False)
check("unknown device asked for sysinfo", s == 200 and r.get("sysinfo") is True, r)
s, r = call("POST", "/api/sysinfo", {"id": dev_id, "uuid": dev_uuid, "version": "1.4.0", "hostname": "smoke-host",
                                    "os": "linux / Ubuntu 24.04", "cpu": "x, 4/2 cores", "memory": "8GB",
                                    "username": "bob"}, auth=False, raw=True)
check("sysinfo -> SYSINFO_UPDATED", r == "SYSINFO_UPDATED", r)
s, r = call("POST", "/api/sysinfo_ver", auth=False, raw=True)
check("sysinfo_ver", s == 200 and r != "", r)
s, r = call("POST", "/api/heartbeat", {"id": dev_id, "uuid": dev_uuid, "ver": 1004000, "conns": [7], "modified_at": 0}, auth=False)
check("heartbeat ok", s == 200 and "sysinfo" not in r and r.get("modified_at") == 0, r)

print("groups")
s, r = call("GET", "/api/users?current=1&pageSize=100&accessible=&status=1")
check("users", s == 200 and r["total"] >= 1 and isinstance(r["data"], list), r)
s, r = call("GET", "/api/peers?current=1&pageSize=100&accessible=&status=1")
check("peers contains device", s == 200 and any(p["id"] == dev_id for p in r["data"]), r)
s, r = call("GET", "/api/device-group/accessible?current=1&pageSize=100")
check("device groups", s == 200 and "total" in r, r)

print("address book")
s, r = call("POST", "/api/ab/settings")
check("ab settings", s == 200 and "max_peer_one_ab" in r, r)
s, r = call("POST", "/api/ab/personal")
check("personal guid", s == 200 and r.get("guid"), r)
guid = r["guid"]
s, r = call("POST", "/api/ab/shared/profiles?current=1&pageSize=100")
check("shared profiles", s == 200 and "total" in r, r)
s, r = call("POST", f"/api/ab/peer/add/{guid}", {"id": "123456789", "alias": "srv", "tags": ["prod"], "hash": "h1",
                                                  "username": "u", "hostname": "h", "platform": "Linux"}, raw=True)
check("add peer", s == 200 and r == "", r)
s, r = call("POST", f"/api/ab/peer/add/{guid}", {"id": dev_id, "alias": "me"}, raw=True)
check("add known device", s == 200 and r == "", r)
s, r = call("PUT", f"/api/ab/peer/update/{guid}", {"id": "123456789", "note": "hello", "forceAlwaysRelay": "true"}, raw=True)
check("update peer", s == 200 and r == "", r)
s, r = call("POST", f"/api/ab/tag/add/{guid}", {"name": "prod", "color": 4280391411}, raw=True)
check("add tag", s == 200 and r == "", r)
s, r = call("PUT", f"/api/ab/tag/rename/{guid}", {"old": "prod", "new": "production"}, raw=True)
check("rename tag", s == 200 and r == "", r)
s, r = call("POST", f"/api/ab/peers?current=1&pageSize=100&ab={guid}")
peer = next((p for p in r["data"] if p["id"] == "123456789"), {})
check("peers listed", s == 200 and r["total"] == 2, r)
check("partial update kept alias", peer.get("alias") == "srv" and peer.get("note") == "hello", peer)
check("tag renamed on peer", peer.get("tags") == ["production"], peer)
check("forceAlwaysRelay string", peer.get("forceAlwaysRelay") == "true", peer)
known = next((p for p in r["data"] if p["id"] == dev_id), {})
check("same_server + hostname from sysinfo", known.get("same_server") is True and known.get("hostname") == "smoke-host", known)
s, r = call("POST", f"/api/ab/tags/{guid}")
check("tags list", s == 200 and r == [{"name": "production", "color": 4280391411}], r)
s, r = call("DELETE", f"/api/ab/tag/{guid}", ["production"], raw=True)
check("delete tag", s == 200 and r == "", r)
s, r = call("DELETE", f"/api/ab/peer/{guid}", ["123456789", dev_id], raw=True)
check("delete peers", s == 200 and r == "", r)
s, r = call("GET", "/api/ab")
check("legacy ab get", s == 200 and "data" in r, r)

print("audit")
nonce = str(uuid.uuid4())
s, r = call("POST", "/api/audit/conn", {"id": dev_id, "uuid": dev_uuid, "conn_id": 7, "session_id": 18446744073709551615,
                                        "ip": "10.0.0.5", "action": "new", "nonce": nonce}, auth=False, raw=True)
check("conn new", s == 200 and r == "", r)
s, r = call("POST", "/api/audit/conn", {"id": dev_id, "uuid": dev_uuid, "conn_id": 7, "session_id": 18446744073709551615,
                                        "ip": "10.0.0.5", "action": "new", "nonce": nonce}, auth=False, raw=True)
check("conn replay ignored", s == 200 and r == "", r)
s, r = call("POST", "/api/audit/conn", {"id": dev_id, "uuid": dev_uuid, "conn_id": 7, "session_id": 18446744073709551615,
                                        "peer": ["987654321", "alice"], "type": 0, "nonce": str(uuid.uuid4())}, auth=False, raw=True)
check("conn authed", s == 200 and r == "", r)
s, r = call("POST", "/api/audit/conn", {"id": dev_id, "session_id": 18446744073709551615, "note": "fixed printer"}, auth=False, raw=True)
check("conn note", s == 200 and r == "", r)
s, r = call("POST", "/api/audit/file", {"id": dev_id, "uuid": dev_uuid, "peer_id": "987654321", "conn_id": 7, "type": 0,
                                        "path": "/tmp", "is_file": False, "info": "{\"files\":[]}", "nonce": str(uuid.uuid4())},
            auth=False, raw=True)
check("file audit", s == 200 and r == "", r)
s, r = call("POST", "/api/audit/alarm", {"id": dev_id, "uuid": dev_uuid, "typ": 2, "info": "{}", "conn_id": 7,
                                         "nonce": str(uuid.uuid4())}, auth=False, raw=True)
check("alarm audit", s == 200 and r == "", r)
s, r = call("POST", "/api/audit/conn", {"id": dev_id, "uuid": dev_uuid, "conn_id": 7, "action": "close",
                                        "nonce": str(uuid.uuid4())}, auth=False, raw=True)
check("conn close", s == 200 and r == "", r)

print("logout")
s, r = call("POST", "/api/logout", {"id": dev_id, "uuid": dev_uuid}, raw=True)
check("logout", s == 200, r)
s, r = call("POST", "/api/currentUser", {"id": dev_id, "uuid": dev_uuid})
check("token revoked -> 401", s == 401, r)

print(f"\n{'ALL PASSED' if FAILED == 0 else f'{FAILED} FAILED'}")
sys.exit(1 if FAILED else 0)
