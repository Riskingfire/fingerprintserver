import base64, gzip, json, os, importlib, sys, urllib.parse

os.environ.update(GITHUB_TOKEN="x", API_KEY="legacy-secret-key-12345",
    API_KEY1="reader-key-aaaaaaaaaaaa", API_KEY1_PERM="38",
    API_KEY2="uploader-key-bbbbbbbbbbb", API_KEY2_PERM="upload_fingerprints,view_status,read_fingerprints",
    API_KEY2_NAME="desktop uploader",
    API_KEY3="keymgr-key-cccccccccccccc", API_KEY3_PERM=str(4 + 8 + 256))
sys.path.insert(0, ".")
import server

FILES = {}   # path -> bytes
def fake(method, path, payload=None, retries=3):
    p = path.split("?")[0]
    assert p.startswith("contents/"), p
    p = urllib.parse.unquote(p[len("contents/"):])
    if method == "GET":
        if p in FILES:
            return 200, {"type": "file", "encoding": "base64", "path": p, "name": p.split("/")[-1],
                         "content": base64.b64encode(FILES[p]).decode(), "sha": str(hash(FILES[p]))}
        kids = [k for k in FILES if k.startswith(p + "/")]
        if kids:
            return 200, [{"type": "file", "name": k.split("/")[-1], "path": k} for k in kids]
        return 404, {}
    if method == "PUT":
        FILES[p] = base64.b64decode(payload["content"]); return 200, {"commit": {"html_url": "http://c/" + payload["message"]}}
    if method == "DELETE":
        del FILES[p]; return 200, {"commit": {"html_url": "http://c/" + payload["message"]}}
server.github_request = fake
c = server.app.test_client()
H = lambda k: {"Authorization": "Bearer " + k}
LEG, RD, UP, KM = "legacy-secret-key-12345", "reader-key-aaaaaaaaaaaa", "uploader-key-bbbbbbbbbbb", "keymgr-key-cccccccccccccc"

def fp(name, shift=0):
    return gzip.compress(json.dumps({"format": "play-fingerprint", "name": name, "updated": "now",
        "feature_names": [f"f{i}" for i in range(6)], "windows": [[i + shift + j for j in range(6)] for i in range(6)]}).encode())

def chk(label, resp, code):
    ok = resp.status_code == code
    print(("PASS" if ok else "FAIL"), label, resp.status_code, "" if ok else resp.get_data(as_text=True)[:200])
    assert ok
    return resp

# ---- backwards compat: legacy key behaves exactly as before (admin) ----
chk("no key -> 401", c.get("/api/status"), 401)
chk("bad key -> 401", c.get("/api/status", headers=H("nope")), 401)
chk("legacy status", c.get("/api/status", headers=H(LEG)), 200)
chk("legacy upload", c.put("/api/fingerprints/alice", data=fp("alice"), headers=H(LEG)), 200)
r = chk("legacy upload (new)", c.put("/api/fingerprints/bob", data=fp("bob", 1), headers=H(LEG)), 200)
assert set(c.get("/api/fingerprints", headers=H(LEG)).json[0]) == {"name", "updated", "sha256"}
chk("legacy download", c.get("/api/fingerprints/alice", headers=H(LEG)), 200)
chk("legacy ban", c.put("/api/banlist/bob", json={"reason": "cheat"}, headers=H(LEG)), 200)
assert "bob" in c.get("/api/banlist", headers=H(LEG)).json
chk("legacy analysis", c.post("/api/analysis", json={}, headers=H(LEG)), 200)
chk("health public", c.get("/health"), 200)

# ---- permissions ----
chk("reader list", c.get("/api/fingerprints", headers=H(RD)), 200)
chk("reader banlist", c.get("/api/banlist", headers=H(RD)), 200)
chk("reader cannot upload", c.put("/api/fingerprints/x", data=fp("x"), headers=H(RD)), 403)
chk("reader cannot delete", c.delete("/api/fingerprints/alice", headers=H(RD)), 403)
chk("reader cannot ban", c.put("/api/banlist/alice", json={}, headers=H(RD)), 403)
chk("reader cannot analyse", c.post("/api/analysis", json={}, headers=H(RD)), 403)
chk("reader cannot list keys", c.get("/api/keys", headers=H(RD)), 403)
chk("uploader upload", c.put("/api/fingerprints/carol", data=fp("carol", 2), headers=H(UP)), 200)
chk("uploader cannot delete", c.delete("/api/fingerprints/carol", headers=H(UP)), 403)
chk("uploader cannot see banlist", c.get("/api/banlist", headers=H(UP)), 403)
me = chk("me", c.get("/api/me", headers=H(UP)), 200).json
assert me["name"] == "desktop uploader" and me["permissions"] == 4 + 8 + 2 and not me["admin"], me
assert chk("me legacy", c.get("/api/me", headers=H(LEG)), 200).json["admin"]
chk("permissions list", c.get("/api/permissions", headers=H(RD)), 200)

# ---- new endpoints ----
info = chk("info", c.get("/api/fingerprints/alice/info", headers=H(RD)), 200).json
assert info["windows"] == 6 and info["banned"] is False, info
assert chk("info banned", c.get("/api/fingerprints/bob/info", headers=H(RD)), 200).json["banned"]
chk("info 404", c.get("/api/fingerprints/ghost/info", headers=H(RD)), 404)
assert [x["name"] for x in c.get("/api/fingerprints?q=AL", headers=H(RD)).json] == ["alice"]
assert chk("check ban", c.get("/api/banlist/bob", headers=H(RD)), 200).json["banned"]
assert not c.get("/api/banlist/alice", headers=H(RD)).json["banned"]
chk("rename needs delete perm", c.post("/api/fingerprints/carol/rename", json={"new_name": "dave"}, headers=H(UP)), 403)
rr = chk("rename", c.post("/api/fingerprints/carol/rename", json={"new_name": "dave"}, headers=H(LEG)), 200).json
chk("rename conflict", c.post("/api/fingerprints/dave/rename", json={"new_name": "alice"}, headers=H(LEG)), 409)
chk("renamed exists", c.get("/api/fingerprints/dave", headers=H(LEG)), 200)
chk("old gone", c.get("/api/fingerprints/carol", headers=H(LEG)), 404)
rr = chk("rename banned warns", c.post("/api/fingerprints/bob/rename", json={"new_name": "bobby"}, headers=H(LEG)), 200).json
assert rr["ban_not_moved"] is True

# ---- delete ----
chk("delete", c.delete("/api/fingerprints/dave", headers=H(LEG)), 200)
chk("delete 404", c.delete("/api/fingerprints/dave", headers=H(LEG)), 404)
FILES_BEFORE = len([k for k in FILES if k.startswith("fingerprints/")])
for n in ("n1", "n2", "n3"):
    c.put(f"/api/fingerprints/{n}", data=fp(n), headers=H(LEG))
bd = chk("bulk delete", c.post("/api/fingerprints/bulk-delete", json={"names": ["n1", "n2", "nope"]}, headers=H(LEG)), 200).json
assert bd["deleted"] == ["n1", "n2"] and bd["not_found"] == ["nope"], bd
chk("bulk delete needs perm", c.post("/api/fingerprints/bulk-delete", json={"names": ["n3"]}, headers=H(UP)), 403)
chk("bulk delete too many", c.post("/api/fingerprints/bulk-delete", json={"names": [f"a{i}" for i in range(30)]}, headers=H(LEG)), 400)

# ---- runtime keys ----
chk("reader cannot create key", c.post("/api/keys", json={"name": "x", "permissions": 4}, headers=H(RD)), 403)
chk("mgr cannot grant admin", c.post("/api/keys", json={"name": "x", "permissions": 1}, headers=H(KM)), 403)
chk("mgr cannot grant perm it lacks", c.post("/api/keys", json={"name": "x", "permissions": 16}, headers=H(KM)), 403)
chk("bad perms", c.post("/api/keys", json={"name": "x", "permissions": 99999}, headers=H(LEG)), 400)
chk("bad perm name", c.post("/api/keys", json={"name": "x", "permissions": ["fly"]}, headers=H(LEG)), 400)
created = chk("mgr creates key", c.post("/api/keys", json={"name": "friend bot", "permissions": ["read_fingerprints"]}, headers=H(KM)), 201).json
sec, kid = created["key"], created["id"]
assert sec.startswith("pfk_") and created["permissions"] == 4
stored = FILES["apikeys.json"].decode()
assert sec not in stored and "hash" in stored, "secret must not be stored in plaintext"
chk("new key works", c.get("/api/fingerprints", headers=H(sec)), 200)
chk("new key limited", c.get("/api/banlist", headers=H(sec)), 403)
ls = chk("list keys", c.get("/api/keys", headers=H(LEG)), 200).json
assert all("key" not in k and "hash" not in k for k in ls) and len(ls) == 5, ls
admin_key = chk("admin creates admin key", c.post("/api/keys", json={"name": "boss", "permissions": 1}, headers=H(LEG)), 201).json
chk("mgr cannot revoke stronger key", c.delete(f"/api/keys/{admin_key['id']}", headers=H(KM)), 403)
chk("edit key", c.patch(f"/api/keys/{kid}", json={"permissions": 4 + 32}, headers=H(LEG)), 200)
chk("edited key can read bans", c.get("/api/banlist", headers=H(sec)), 200)
chk("cannot edit env key", c.patch("/api/keys/env:API_KEY1", json={"permissions": 1}, headers=H(LEG)), 400)
chk("revoke", c.delete(f"/api/keys/{kid}", headers=H(LEG)), 200)
chk("revoked key rejected", c.get("/api/fingerprints", headers=H(sec)), 401)
chk("revoke 404", c.delete(f"/api/keys/{kid}", headers=H(LEG)), 404)

# survives "restart": cache cleared, key still validates from the stored hash
server._keys_cache.update(data=None, loaded=0.0)
chk("admin runtime key after cache reset", c.get("/api/keys", headers=H(admin_key["key"])), 200)

# ---- perm parsing ----
P = server.parse_perms
assert P(14) == 14 and P("14") == 14 and P("upload_fingerprints, view-status") == 10 and P("all") == 1
for bad in ("", "abc", -1, 512, True, None, 2.5):
    try: P(bad); raise SystemExit(f"should reject {bad!r}")
    except ValueError: pass
print("ALL TESTS PASSED")
