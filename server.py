"""Play Fingerprint API backed by GitHub commits (no SQL database required).

Fingerprints are stored as gzip files in the configured GitHub repository under
fingerprints/. The ban list is stored in banlist.json. GitHub credentials stay
on the server in environment variables and are never sent to desktop clients.
"""
import base64
import gzip
import hashlib
import hmac
import json
import math
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from flask import Flask, request, jsonify, abort

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

API_KEY = os.environ.get("API_KEY", "").strip()
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "").strip()
GITHUB_REPO = os.environ.get("GITHUB_REPO", "Riskingfire/fingerprints").strip().strip("/")
GITHUB_BRANCH = os.environ.get("GITHUB_BRANCH", "main").strip() or "main"
FINGERPRINT_DIR = os.environ.get("GITHUB_FINGERPRINT_DIR", "fingerprints").strip("/") or "fingerprints"
BANLIST_PATH = os.environ.get("GITHUB_BANLIST_PATH", "banlist.json").strip("/") or "banlist.json"
GITHUB_API = "https://api.github.com"
GITHUB_API_VERSION = "2022-11-28"
_repo_lock = threading.RLock()

if not API_KEY:
    raise RuntimeError("Set API_KEY in the Render environment.")
if not GITHUB_TOKEN:
    raise RuntimeError("Set GITHUB_TOKEN in the Render environment.")
if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", GITHUB_REPO):
    raise RuntimeError("GITHUB_REPO must look like owner/repository.")


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def authorized():
    supplied = request.headers.get("Authorization", "")
    if not supplied.startswith("Bearer ") or not hmac.compare_digest(supplied[7:].strip(), API_KEY):
        abort(401, description="Invalid or missing API key")


def clean_name(value):
    value = "".join(ch for ch in str(value) if ch.isalnum() or ch in "-_ ").strip()
    if not value or len(value) > 100:
        abort(400, description="Invalid fingerprint name")
    return value


def fingerprint_path(name):
    # Keep the display name in the fingerprint payload; use a stable URL-safe filename.
    filename = re.sub(r"\s+", "_", name).strip("._")
    return f"{FINGERPRINT_DIR}/{urllib.parse.quote(filename, safe='-_')}.json.gz"


def github_request(method, path, payload=None, retries=3):
    url = f"{GITHUB_API}/repos/{GITHUB_REPO}/{path.lstrip('/')}"
    data = None if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("Authorization", "Bearer " + GITHUB_TOKEN)
    req.add_header("X-GitHub-Api-Version", GITHUB_API_VERSION)
    req.add_header("User-Agent", "play-fingerprint-server/3")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    last_error = None
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                raw = response.read()
                return response.status, json.loads(raw.decode("utf-8")) if raw else {}
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                detail = json.loads(raw.decode("utf-8"))
            except Exception:
                detail = {"message": raw.decode("utf-8", "replace")[:500]}
            if exc.code == 404:
                return 404, detail
            if exc.code in (409, 422) and attempt + 1 < retries:
                last_error = (exc.code, detail)
                time.sleep(0.4 * (attempt + 1))
                # Rebuild request because the contents API may have a changed SHA.
                req = urllib.request.Request(url, data=data, method=method)
                req.add_header("Accept", "application/vnd.github+json")
                req.add_header("Authorization", "Bearer " + GITHUB_TOKEN)
                req.add_header("X-GitHub-Api-Version", GITHUB_API_VERSION)
                req.add_header("User-Agent", "play-fingerprint-server/3")
                if data is not None:
                    req.add_header("Content-Type", "application/json")
                continue
            raise RuntimeError(f"GitHub API returned HTTP {exc.code}: {detail.get('message', 'request failed')}")
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Could not reach GitHub API: {exc.reason}") from exc
    raise RuntimeError(f"GitHub API conflict: {last_error}")


def contents_path(path):
    return "contents/" + urllib.parse.quote(path, safe="/") + "?ref=" + urllib.parse.quote(GITHUB_BRANCH, safe="")


def read_repo_file(path):
    code, obj = github_request("GET", contents_path(path))
    if code == 404:
        return None, None
    if not isinstance(obj, dict) or obj.get("type") != "file":
        return None, None
    content = obj.get("content", "")
    if obj.get("encoding") != "base64":
        # For files >1MB GitHub can omit encoded content; fingerprint files are expected to be small.
        raise RuntimeError(f"GitHub did not return base64 content for {path}; keep each file under 1 MB.")
    return base64.b64decode(content), obj.get("sha")


def write_repo_file(path, raw, message):
    # GitHub Contents API creates a commit per file update. Lock prevents races within this instance.
    with _repo_lock:
        _, old_sha = read_repo_file(path)
        payload = {
            "message": message,
            "content": base64.b64encode(raw).decode("ascii"),
            "branch": GITHUB_BRANCH,
        }
        if old_sha:
            payload["sha"] = old_sha
        code, result = github_request("PUT", "contents/" + urllib.parse.quote(path, safe="/"), payload)
        if code not in (200, 201):
            raise RuntimeError(f"Unexpected GitHub status {code}: {result}")
        return code, result


def list_repo_fingerprints():
    path = contents_path(FINGERPRINT_DIR)
    code, obj = github_request("GET", path)
    if code == 404:
        return []
    if not isinstance(obj, list):
        raise RuntimeError("GitHub fingerprint directory is not a directory.")
    files = []
    for item in obj:
        if item.get("type") == "file" and item.get("name", "").endswith(".json.gz"):
            files.append(item)
    return files


def unpack_profile(blob):
    try:
        raw = gzip.decompress(blob) if blob[:2] == b"\x1f\x8b" else blob
        if len(raw) > 2 * 1024 * 1024:
            abort(413, description="Fingerprint too large after decompression")
        data = json.loads(raw.decode("utf-8"))
        if data.get("format") != "play-fingerprint" or not isinstance(data.get("windows"), list):
            abort(400, description="Not a valid Play Fingerprint file")
        if len(data.get("feature_names", [])) > 300 or len(data["windows"]) > 800:
            abort(400, description="Fingerprint exceeds supported feature/window limits")
        data["name"] = clean_name(data.get("name", ""))
        return data
    except (ValueError, UnicodeError, OSError, json.JSONDecodeError):
        abort(400, description="Invalid or corrupt fingerprint data")


def get_fp_rows():
    rows = []
    for item in list_repo_fingerprints():
        raw, _ = read_repo_file(item["path"])
        if raw is None:
            continue
        try:
            profile = unpack_profile(raw)
            rows.append({"name": profile["name"], "blob": raw,
                         "updated": str(profile.get("updated", item.get("updated_at", ""))),
                         "digest": hashlib.sha256(raw).hexdigest(), "path": item["path"]})
        except Exception:
            app.logger.exception("Skipping invalid repository fingerprint %s", item.get("path"))
    rows.sort(key=lambda row: row["name"].casefold())
    return rows


def get_bans():
    raw, _ = read_repo_file(BANLIST_PATH)
    if raw is None:
        return {}
    try:
        data = json.loads(raw.decode("utf-8"))
        return data if isinstance(data, dict) else {}
    except (ValueError, UnicodeError):
        app.logger.exception("Invalid banlist JSON in repository")
        return {}


def save_bans(data, message):
    raw = (json.dumps(data, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    write_repo_file(BANLIST_PATH, raw, message)


@app.get("/health")
def health():
    # Public health route wakes Render; GitHub credentials remain server-side.
    return jsonify(status="ok", service="play-fingerprint", storage="github-commits",
                   repository=GITHUB_REPO, utc=utc_now())


@app.get("/api/status")
def status():
    authorized()
    return jsonify(fingerprints=len(get_fp_rows()), bans=len(get_bans()),
                   storage="github-commits", repository=GITHUB_REPO, branch=GITHUB_BRANCH)


@app.get("/api/fingerprints")
def list_fingerprints():
    authorized()
    rows = get_fp_rows()
    return jsonify([{"name": row["name"], "updated": row["updated"], "sha256": row["digest"]} for row in rows])


@app.get("/api/fingerprints/<path:name>")
def download_fingerprint(name):
    authorized()
    name = clean_name(name)
    for row in get_fp_rows():
        if row["name"] == name:
            return app.response_class(row["blob"], mimetype="application/octet-stream")
    abort(404, description="Fingerprint not found")


@app.put("/api/fingerprints/<path:name>")
def upload_fingerprint(name):
    authorized()
    name = clean_name(name)
    blob = request.get_data(cache=False)
    if not blob or len(blob) > 2 * 1024 * 1024:
        abort(413, description="Fingerprint must be 1 byte to 2 MB")
    profile = unpack_profile(blob)
    if profile["name"] != name:
        profile["name"] = name
        blob = gzip.compress(json.dumps(profile, separators=(",", ":")).encode("utf-8"), compresslevel=6)
    # Verify the target is a single expected file path; GitHub's API performs the commit.
    path = fingerprint_path(name)
    try:
        code, result = write_repo_file(path, blob, f"Update Play Fingerprint: {name}")
    except RuntimeError as exc:
        app.logger.exception("Fingerprint commit failed")
        abort(502, description=str(exc))
    updated = str(profile.get("updated") or utc_now())[:80]
    return jsonify(name=name, updated=updated, sha256=hashlib.sha256(blob).hexdigest(),
                   commit=result.get("commit", {}).get("html_url")), code


@app.delete("/api/fingerprints/<path:name>")
def delete_fingerprint(name):
    authorized()
    name = clean_name(name)
    path = fingerprint_path(name)
    with _repo_lock:
        raw, sha = read_repo_file(path)
        if raw is None or not sha:
            abort(404, description="Fingerprint not found")
        payload = {"message": f"Delete Play Fingerprint: {name}", "sha": sha, "branch": GITHUB_BRANCH}
        code, result = github_request("DELETE", "contents/" + urllib.parse.quote(path, safe="/"), payload)
    return jsonify(deleted=name, commit=result.get("commit", {}).get("html_url"))


@app.get("/api/banlist")
def list_bans():
    authorized()
    return jsonify(get_bans())


@app.put("/api/banlist/<path:name>")
def put_ban(name):
    authorized()
    name = clean_name(name)
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        abort(400, description="Expected JSON object")
    record = {"reason": str(data.get("reason", ""))[:1000],
              "date": str(data.get("date") or utc_now())[:80]}
    with _repo_lock:
        bans = get_bans()
        bans[name] = record
        try:
            save_bans(bans, f"Update Play Fingerprint banlist: {name}")
        except RuntimeError as exc:
            abort(502, description=str(exc))
    return jsonify(name=name, ban=record)


@app.delete("/api/banlist/<path:name>")
def delete_ban(name):
    authorized()
    name = clean_name(name)
    with _repo_lock:
        bans = get_bans()
        existed = name in bans
        bans.pop(name, None)
        try:
            save_bans(bans, f"Remove Play Fingerprint ban: {name}")
        except RuntimeError as exc:
            abort(502, description=str(exc))
    return jsonify(removed=name, existed=existed)


def summary_vector(profile):
    names, rows = profile.get("feature_names", []), profile.get("windows", [])
    result = {}
    for i, fname in enumerate(names):
        vals = [float(row[i]) for row in rows if i < len(row) and isinstance(row[i], (int, float)) and math.isfinite(row[i])]
        if len(vals) >= 5:
            vals.sort()
            result[fname] = vals[len(vals) // 2]
    return result


def distance(a, b):
    common = sorted(set(a) & set(b))
    if len(common) < 5:
        return None, len(common)
    diffs = []
    for key in common:
        scale = max(abs(a[key]) * 0.10, abs(b[key]) * 0.10, 0.05)
        diffs.append(min(abs(a[key] - b[key]) / scale, 10.0))
    return sum(diffs) / len(diffs), len(common)


@app.post("/api/analysis")
def analyze_bans():
    """Approximate server-side screening; results are leads for human review, never automatic bans."""
    authorized()
    body = request.get_json(silent=True) or {}
    requested_name = body.get("name")
    candidate_name = clean_name(requested_name) if requested_name else None
    rows = get_fp_rows()
    profiles = {}
    for row in rows:
        try:
            profiles[row["name"]] = unpack_profile(row["blob"])
        except Exception:
            app.logger.exception("Skipping invalid fingerprint %s", row["name"])
    if candidate_name and candidate_name not in profiles:
        abort(404, description="Candidate fingerprint not found on server")
    banned = get_bans()
    candidates = [candidate_name] if candidate_name else [n for n in profiles if n not in banned]
    vectors = {name: summary_vector(profile) for name, profile in profiles.items()}
    results = []
    for candidate in candidates:
        for banned_name in banned:
            if banned_name == candidate or banned_name not in vectors:
                continue
            d, shared = distance(vectors.get(candidate, {}), vectors[banned_name])
            if d is None:
                continue
            flag = "HIGH" if d < 0.18 else ("REVIEW" if d < 0.45 else "NONE")
            results.append({"candidate": candidate, "banned": banned_name, "distance": round(d, 4),
                            "shared_features": shared, "flag": flag,
                            "reason": "Approximate summary-feature comparison; human review required."})
    results.sort(key=lambda item: item["distance"])
    return jsonify(candidate=candidate_name or "all non-banned fingerprints", results=results,
                   disclaimer="Heuristic only. Do not auto-ban from fingerprint similarity; shared devices, similar playstyles, and noisy samples can cause false positives.")


@app.errorhandler(404)
def not_found(e):
    return jsonify(error=getattr(e, "description", "Not found")), 404


@app.errorhandler(400)
def bad_request(e):
    return jsonify(error=getattr(e, "description", "Bad request")), 400


@app.errorhandler(401)
def unauthorized_error(e):
    return jsonify(error=getattr(e, "description", "Unauthorized")), 401


@app.errorhandler(413)
def too_large(e):
    return jsonify(error="Request too large"), 413


@app.errorhandler(502)
def upstream_error(e):
    return jsonify(error=getattr(e, "description", "GitHub storage error")), 502


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "10000")))
