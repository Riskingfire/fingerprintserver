"""Play Fingerprint API backed by GitHub commits (no SQL database required).

Fingerprints are stored as gzip files in the configured GitHub repository under
fingerprints/. The ban list is stored in banlist.json. GitHub credentials stay
on the server in environment variables and are never sent to desktop clients.

API keys and permissions
------------------------
Every key carries a permission number (a bitfield, like Discord's bot
permissions). Each permission is a power of two, so any combination adds up to
a number that decodes back to exactly one set of permissions. Permission 1 is
ADMIN and grants everything.

Keys come from two places:

* Environment variables (set in Render):
      API_KEY             legacy key, always ADMIN (keeps old clients working)
      API_KEY1            secret for key 1
      API_KEY1_PERM       permission number (e.g. 14) or names (e.g. "read_fingerprints,upload_fingerprints")
      API_KEY1_NAME       optional label shown in logs / commit messages
      API_KEY2, API_KEY2_PERM, ...   and so on, any number of them
* Created at runtime through POST /api/keys (needs MANAGE_KEYS). Only a SHA-256
  hash of those keys is stored (in apikeys.json in the repository), so you can
  add and revoke keys on Render's free tier without redeploying.
"""
import base64
import gzip
import hashlib
import hmac
import json
import logging
import math
import os
import re
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from flask import Flask, request, jsonify, abort, g

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024
app.logger.setLevel(logging.INFO)

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "").strip()
GITHUB_REPO = os.environ.get("GITHUB_REPO", "Riskingfire/fingerprints").strip().strip("/")
GITHUB_BRANCH = os.environ.get("GITHUB_BRANCH", "main").strip() or "main"
FINGERPRINT_DIR = os.environ.get("GITHUB_FINGERPRINT_DIR", "fingerprints").strip("/") or "fingerprints"
BANLIST_PATH = os.environ.get("GITHUB_BANLIST_PATH", "banlist.json").strip("/") or "banlist.json"
KEYS_PATH = os.environ.get("GITHUB_KEYS_PATH", "apikeys.json").strip("/") or "apikeys.json"
GITHUB_API = "https://api.github.com"
GITHUB_API_VERSION = "2022-11-28"
_repo_lock = threading.RLock()
_keys_lock = threading.RLock()

KEY_PREFIX = "pfk_"          # runtime-created keys always start with this
KEYS_CACHE_SECONDS = 30      # how long the runtime key list is cached in memory
MAX_RUNTIME_KEYS = 100
BULK_DELETE_LIMIT = 25
MAX_KEY_DAYS = 3650


def _default_key_days():
    """KEY_DEFAULT_DAYS: lifetime of API-created keys when the request doesn't say (60 = about 2 months).
    Set to "never" or 0 to make keys non-expiring by default."""
    raw = os.environ.get("KEY_DEFAULT_DAYS", "60").strip().lower()
    if raw in ("never", "0", "none", ""):
        return None
    try:
        days = float(raw)
    except ValueError:
        raise RuntimeError('KEY_DEFAULT_DAYS must be a number of days or "never"')
    if not 0 < days <= MAX_KEY_DAYS:
        raise RuntimeError(f"KEY_DEFAULT_DAYS must be between 0 and {MAX_KEY_DAYS}")
    return days


DEFAULT_KEY_DAYS = _default_key_days()

# --------------------------------------------------------------------------
# Permissions. Each value is a power of two so they can be summed freely.
# ADMIN (1) overrides everything, including permissions added later.
# --------------------------------------------------------------------------
PERMISSIONS = {
    "ADMIN":               (1,   "Every permission, including ones added in the future."),
    "VIEW_STATUS":         (2,   "GET /api/status"),
    "READ_FINGERPRINTS":   (4,   "List, search, inspect and download fingerprints."),
    "UPLOAD_FINGERPRINTS": (8,   "Upload / overwrite fingerprints."),
    "DELETE_FINGERPRINTS": (16,  "Delete fingerprints (single and bulk)."),
    "READ_BANLIST":        (32,  "View the ban list and check single names."),
    "MANAGE_BANS":         (64,  "Add and remove bans."),
    "RUN_ANALYSIS":        (128, "Run the ban-evasion similarity analysis."),
    "MANAGE_KEYS":         (256, "Create, edit and revoke API keys (only up to your own permissions)."),
}
PERM = {name: value for name, (value, _) in PERMISSIONS.items()}
ADMIN = PERM["ADMIN"]
ALL_BITS = sum(PERM.values())

P_STATUS = PERM["VIEW_STATUS"]
P_READ_FP = PERM["READ_FINGERPRINTS"]
P_UPLOAD_FP = PERM["UPLOAD_FINGERPRINTS"]
P_DELETE_FP = PERM["DELETE_FINGERPRINTS"]
P_READ_BANS = PERM["READ_BANLIST"]
P_MANAGE_BANS = PERM["MANAGE_BANS"]
P_ANALYSIS = PERM["RUN_ANALYSIS"]
P_KEYS = PERM["MANAGE_KEYS"]

READ_ONLY_DEFAULT = P_STATUS | P_READ_FP | P_READ_BANS


def parse_perms(value):
    """Turn 14, "14", "upload_fingerprints,view_status" or a list into a permission number."""
    if isinstance(value, bool):
        raise ValueError("permissions must be a number or a list of permission names")
    if isinstance(value, int):
        number = value
    elif isinstance(value, str) and re.fullmatch(r"\s*\d+\s*", value):
        number = int(value)
    elif isinstance(value, (str, list, tuple)):
        tokens = re.split(r"[,\s|+]+", value.strip()) if isinstance(value, str) else list(value)
        number = 0
        for token in tokens:
            token = str(token).strip().upper().replace("-", "_")
            if not token:
                continue
            if token == "ALL":
                token = "ADMIN"
            if token not in PERM:
                raise ValueError(f"unknown permission '{token}'")
            number |= PERM[token]
        if number == 0:
            raise ValueError("no permissions given")
    else:
        raise ValueError("permissions must be a number or a list of permission names")
    if number < 0 or number & ~ALL_BITS:
        raise ValueError(f"permission number {number} contains unknown bits (max valid value is {ALL_BITS})")
    return number


def perm_names(perms):
    if perms & ADMIN:
        return ["ADMIN"]
    return [name for name, bit in PERM.items() if bit != ADMIN and perms & bit]


def effective_perm_names(perms):
    if perms & ADMIN:
        return list(PERM)
    return perm_names(perms)


@dataclass(frozen=True)
class Principal:
    id: str
    name: str
    perms: int
    source: str  # "env" or "runtime"
    expires: Optional[datetime] = None  # None = never expires

    def expired(self):
        return self.expires is not None and datetime.now(timezone.utc) >= self.expires

    def can(self, *flags):
        if self.perms & ADMIN:
            return True
        return all(self.perms & flag for flag in flags)


def _digest(secret):
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def _label(value, fallback):
    value = "".join(ch for ch in str(value or "") if ch.isalnum() or ch in "-_. ").strip()[:60]
    return value or fallback


def parse_expiry(value):
    """'2027-01-31' (valid through the end of that day, UTC) or an ISO time -> aware UTC datetime.
    'never' / empty -> None. Raises ValueError for anything else."""
    text = str(value or "").strip()
    if text.lower() in ("", "never", "none"):
        return None
    try:
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
            return datetime.strptime(text, "%Y-%m-%d").replace(hour=23, minute=59, second=59, tzinfo=timezone.utc)
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("expiry must look like 2027-01-31 or 2027-01-31T12:00:00Z, or be 'never'")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def default_expiry():
    if DEFAULT_KEY_DAYS is None:
        return None
    return datetime.now(timezone.utc) + timedelta(days=DEFAULT_KEY_DAYS)


def load_env_keys():
    """Read API_KEY (legacy admin) and API_KEY<n> / API_KEY<n>_PERM from the environment."""
    found = []
    numbered = []
    for var in os.environ:
        match = re.fullmatch(r"API_KEY(\d+)", var)
        if match:
            numbered.append((int(match.group(1)), var))
    for _, var in sorted(numbered):
        secret = os.environ[var].strip()
        if not secret:
            continue
        perm_raw = os.environ.get(var + "_PERM", "").strip()
        if perm_raw:
            try:
                perms = parse_perms(perm_raw)
            except ValueError as exc:
                raise RuntimeError(f"{var}_PERM is invalid: {exc}")
        else:
            perms = READ_ONLY_DEFAULT
            logging.warning("%s_PERM is not set; %s defaults to read-only (%d).", var, var, perms)
        name = _label(os.environ.get(var + "_NAME"), var)
        try:
            expires = parse_expiry(os.environ.get(var + "_EXPIRES"))
        except ValueError as exc:
            raise RuntimeError(f"{var}_EXPIRES is invalid: {exc}")
        found.append((_digest(secret), Principal(f"env:{var}", name, perms, "env", expires)))
        if len(secret) < 16:
            logging.warning("%s is shorter than 16 characters; use a long random value.", var)
    legacy = os.environ.get("API_KEY", "").strip()
    if legacy:
        found.append((_digest(legacy), Principal("env:API_KEY", "API_KEY (legacy admin)", ADMIN, "env")))
    seen = set()
    unique = []
    for digest, principal in found:
        if digest in seen:
            logging.warning("%s has the same secret as an earlier key and is ignored.", principal.id)
            continue
        seen.add(digest)
        unique.append((digest, principal))
    return unique


if not GITHUB_TOKEN:
    raise RuntimeError("Set GITHUB_TOKEN in the Render environment.")
if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", GITHUB_REPO):
    raise RuntimeError("GITHUB_REPO must look like owner/repository.")
ENV_KEYS = load_env_keys()
if not ENV_KEYS:
    raise RuntimeError("Set API_KEY (or API_KEY1 and API_KEY1_PERM) in the Render environment.")


def utc_now():
    return datetime.now(timezone.utc).isoformat()


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
    req.add_header("User-Agent", "play-fingerprint-server/4")
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
                req.add_header("User-Agent", "play-fingerprint-server/4")
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


def delete_repo_file(path, message):
    """Delete a file; returns the commit URL, or None if the file did not exist."""
    with _repo_lock:
        raw, sha = read_repo_file(path)
        if raw is None or not sha:
            return None, False
        payload = {"message": message, "sha": sha, "branch": GITHUB_BRANCH}
        _, result = github_request("DELETE", "contents/" + urllib.parse.quote(path, safe="/"), payload)
        return result.get("commit", {}).get("html_url"), True


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


# --------------------------------------------------------------------------
# Runtime-created API keys (stored hashed in apikeys.json in the repository)
# --------------------------------------------------------------------------
_keys_cache = {"data": None, "loaded": 0.0}


def load_runtime_keys(force=False):
    with _keys_lock:
        fresh = time.monotonic() - _keys_cache["loaded"] < KEYS_CACHE_SECONDS
        if not force and _keys_cache["data"] is not None and fresh:
            return _keys_cache["data"]
        try:
            raw, _ = read_repo_file(KEYS_PATH)
        except RuntimeError:
            if not force and _keys_cache["data"] is not None:
                app.logger.warning("Could not refresh API keys from GitHub; using cached copy")
                return _keys_cache["data"]
            raise
        data = {"keys": {}}
        if raw is not None:
            try:
                parsed = json.loads(raw.decode("utf-8"))
                if isinstance(parsed, dict) and isinstance(parsed.get("keys"), dict):
                    data = {"keys": parsed["keys"]}
            except (ValueError, UnicodeError):
                app.logger.exception("Invalid %s in repository", KEYS_PATH)
        _keys_cache["data"] = data
        _keys_cache["loaded"] = time.monotonic()
        return data


def save_runtime_keys(data, message):
    raw = (json.dumps(data, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    write_repo_file(KEYS_PATH, raw, message)
    _keys_cache["data"] = data
    _keys_cache["loaded"] = time.monotonic()


def runtime_principal(key_id, record):
    try:
        perms = parse_perms(record.get("permissions", 0))
    except ValueError:
        perms = 0
    expires = None
    if record.get("expires"):  # a missing/null field means the key predates expiry and never expires
        try:
            expires = parse_expiry(record["expires"])
        except ValueError:
            expires = datetime.fromtimestamp(0, timezone.utc)  # unreadable value: treat as expired
    return Principal(f"key:{key_id}", _label(record.get("name"), key_id), perms, "runtime", expires)


def authenticate(token):
    if not token:
        return None
    token_digest = _digest(token)
    match = None
    for digest, principal in ENV_KEYS:  # no early exit: keeps timing uniform
        if hmac.compare_digest(digest, token_digest) and match is None:
            match = principal
    if match:
        return match
    if token.startswith(KEY_PREFIX):  # only runtime keys carry this prefix, so junk never hits GitHub
        for key_id, record in load_runtime_keys()["keys"].items():
            if isinstance(record, dict) and hmac.compare_digest(str(record.get("hash", "")), token_digest):
                return runtime_principal(key_id, record)
    return None


def authorized(*needed):
    """Require a valid key that has every permission in `needed`. With no arguments any valid key passes."""
    header = request.headers.get("Authorization", "")
    principal = authenticate(header[7:].strip()) if header.startswith("Bearer ") else None
    if principal is None:
        abort(401, description="Invalid or missing API key")
    if principal.expired():
        abort(401, description="This API key has expired")
    if needed and not principal.can(*needed):
        missing = [name for name, bit in PERM.items() if bit in needed and not principal.perms & bit]
        abort(403, description="This API key lacks the required permission: " + ", ".join(missing))
    g.principal = principal
    return principal


def by():
    principal = getattr(g, "principal", None)
    return f" [by {principal.name}]" if principal else ""


def audit(action, target=""):
    principal = getattr(g, "principal", None)
    app.logger.info("AUDIT key=%s action=%s target=%s", principal.id if principal else "-", action, target)


def check_grantable(principal, perms):
    """Non-admins can only hand out permissions they hold themselves, and never ADMIN."""
    if principal.perms & ADMIN:
        return
    if perms & ADMIN or perms & ~principal.perms:
        abort(403, description="You can only grant permissions that your own key has")


def key_public(principal, record=None):
    public_id = principal.id[4:] if principal.source == "runtime" else principal.id
    out = {"id": public_id, "name": principal.name, "source": principal.source,
           "permissions": principal.perms, "permission_names": perm_names(principal.perms)}
    out["expires"] = principal.expires.isoformat() if principal.expires else None
    out["expired"] = principal.expired()
    out["days_left"] = None
    if principal.expires and not out["expired"]:
        out["days_left"] = round((principal.expires - datetime.now(timezone.utc)).total_seconds() / 86400, 1)
    if record:
        out["created"] = record.get("created")
        out["created_by"] = record.get("created_by")
    return out


# --------------------------------------------------------------------------
# Public + info routes
# --------------------------------------------------------------------------
@app.get("/health")
def health():
    # Public health route wakes Render; GitHub credentials remain server-side.
    return jsonify(status="ok", service="play-fingerprint", storage="github-commits",
                   repository=GITHUB_REPO, utc=utc_now())


@app.get("/api/me")
def whoami():
    """Shows which key you are using and what it is allowed to do (any valid key)."""
    me = authorized()
    return jsonify(**key_public(me), admin=bool(me.perms & ADMIN),
                   can=effective_perm_names(me.perms))


@app.get("/api/permissions")
def list_permissions():
    """Lists every permission and its number (any valid key)."""
    authorized()
    return jsonify(admin_value=ADMIN, max_value=ALL_BITS, default_key_lifetime_days=DEFAULT_KEY_DAYS,
                   permissions=[{"name": n, "value": v, "description": d} for n, (v, d) in PERMISSIONS.items()],
                   note="Add the numbers together. Example: READ_FINGERPRINTS (4) + UPLOAD_FINGERPRINTS (8) = 12. "
                        "ADMIN (1) grants everything.")


@app.get("/api/status")
def status():
    authorized(P_STATUS)
    return jsonify(fingerprints=len(get_fp_rows()), bans=len(get_bans()),
                   storage="github-commits", repository=GITHUB_REPO, branch=GITHUB_BRANCH)


# --------------------------------------------------------------------------
# Fingerprints
# --------------------------------------------------------------------------
@app.get("/api/fingerprints")
def list_fingerprints():
    authorized(P_READ_FP)
    rows = get_fp_rows()
    query = request.args.get("q", "").strip().casefold()
    if query:
        rows = [row for row in rows if query in row["name"].casefold()]
    return jsonify([{"name": row["name"], "updated": row["updated"], "sha256": row["digest"]} for row in rows])


@app.get("/api/fingerprints/<name>/info")
def fingerprint_info(name):
    """Metadata about one fingerprint without downloading it."""
    authorized(P_READ_FP)
    name = clean_name(name)
    path = fingerprint_path(name)
    raw, _ = read_repo_file(path)
    if raw is None:
        abort(404, description="Fingerprint not found")
    profile = unpack_profile(raw)
    return jsonify(name=profile["name"], updated=str(profile.get("updated", "")),
                   sha256=hashlib.sha256(raw).hexdigest(), size_bytes=len(raw),
                   features=len(profile.get("feature_names", [])), windows=len(profile["windows"]),
                   banned=profile["name"] in get_bans(), path=path)


@app.get("/api/fingerprints/<path:name>")
def download_fingerprint(name):
    authorized(P_READ_FP)
    name = clean_name(name)
    for row in get_fp_rows():
        if row["name"] == name:
            return app.response_class(row["blob"], mimetype="application/octet-stream")
    abort(404, description="Fingerprint not found")


@app.put("/api/fingerprints/<path:name>")
def upload_fingerprint(name):
    authorized(P_UPLOAD_FP)
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
        code, result = write_repo_file(path, blob, f"Update Play Fingerprint: {name}{by()}")
    except RuntimeError as exc:
        app.logger.exception("Fingerprint commit failed")
        abort(502, description=str(exc))
    audit("upload", name)
    updated = str(profile.get("updated") or utc_now())[:80]
    return jsonify(name=name, updated=updated, sha256=hashlib.sha256(blob).hexdigest(),
                   commit=result.get("commit", {}).get("html_url")), code


@app.delete("/api/fingerprints/<path:name>")
def delete_fingerprint(name):
    authorized(P_DELETE_FP)
    name = clean_name(name)
    commit, existed = delete_repo_file(fingerprint_path(name), f"Delete Play Fingerprint: {name}{by()}")
    if not existed:
        abort(404, description="Fingerprint not found")
    audit("delete", name)
    return jsonify(deleted=name, commit=commit)


@app.post("/api/fingerprints/bulk-delete")
def bulk_delete_fingerprints():
    """Body: {"names": ["a", "b"]}. Each delete is its own commit, so the batch is capped."""
    authorized(P_DELETE_FP)
    body = request.get_json(silent=True)
    names = body.get("names") if isinstance(body, dict) else None
    if not isinstance(names, list) or not names:
        abort(400, description='Expected JSON like {"names": ["profile one", "profile two"]}')
    if len(names) > BULK_DELETE_LIMIT:
        abort(400, description=f"At most {BULK_DELETE_LIMIT} fingerprints per request")
    deleted, not_found, failed = [], [], []
    for raw_name in dict.fromkeys(str(n) for n in names):
        try:
            name = clean_name(raw_name)
        except Exception:
            failed.append({"name": raw_name[:100], "error": "Invalid fingerprint name"})
            continue
        try:
            _, existed = delete_repo_file(fingerprint_path(name), f"Delete Play Fingerprint: {name}{by()}")
        except RuntimeError as exc:
            failed.append({"name": name, "error": str(exc)})
            continue
        (deleted if existed else not_found).append(name)
        if existed:
            audit("delete", name)
    return jsonify(deleted=deleted, not_found=not_found, failed=failed)


@app.post("/api/fingerprints/<name>/rename")
def rename_fingerprint(name):
    """Body: {"new_name": "..."}. Needs both upload and delete permission."""
    authorized(P_UPLOAD_FP, P_DELETE_FP)
    old_name = clean_name(name)
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or "new_name" not in body:
        abort(400, description='Expected JSON like {"new_name": "..."}')
    new_name = clean_name(body["new_name"])
    if new_name == old_name:
        abort(400, description="New name is the same as the old name")
    old_path, new_path = fingerprint_path(old_name), fingerprint_path(new_name)
    with _repo_lock:
        raw, _ = read_repo_file(old_path)
        if raw is None:
            abort(404, description="Fingerprint not found")
        if new_path != old_path and read_repo_file(new_path)[0] is not None:
            abort(409, description="A fingerprint with the new name already exists")
        profile = unpack_profile(raw)
        profile["name"] = new_name
        blob = gzip.compress(json.dumps(profile, separators=(",", ":")).encode("utf-8"), compresslevel=6)
        write_repo_file(new_path, blob, f"Rename Play Fingerprint: {old_name} -> {new_name}{by()}")
        if new_path != old_path:
            delete_repo_file(old_path, f"Rename Play Fingerprint (remove old): {old_name}{by()}")
        was_banned = old_name in get_bans()
    audit("rename", f"{old_name} -> {new_name}")
    return jsonify(old_name=old_name, new_name=new_name, sha256=hashlib.sha256(blob).hexdigest(),
                   ban_not_moved=was_banned)


# --------------------------------------------------------------------------
# Ban list
# --------------------------------------------------------------------------
@app.get("/api/banlist")
def list_bans():
    authorized(P_READ_BANS)
    return jsonify(get_bans())


@app.get("/api/banlist/<path:name>")
def check_ban(name):
    """Is this one name banned? Always 200; look at the `banned` field."""
    authorized(P_READ_BANS)
    name = clean_name(name)
    ban = get_bans().get(name)
    return jsonify(name=name, banned=ban is not None, ban=ban)


@app.put("/api/banlist/<path:name>")
def put_ban(name):
    authorized(P_MANAGE_BANS)
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
            save_bans(bans, f"Update Play Fingerprint banlist: {name}{by()}")
        except RuntimeError as exc:
            abort(502, description=str(exc))
    audit("ban", name)
    return jsonify(name=name, ban=record)


@app.delete("/api/banlist/<path:name>")
def delete_ban(name):
    authorized(P_MANAGE_BANS)
    name = clean_name(name)
    with _repo_lock:
        bans = get_bans()
        existed = name in bans
        bans.pop(name, None)
        try:
            save_bans(bans, f"Remove Play Fingerprint ban: {name}{by()}")
        except RuntimeError as exc:
            abort(502, description=str(exc))
    audit("unban", name)
    return jsonify(removed=name, existed=existed)


# --------------------------------------------------------------------------
# Analysis
# --------------------------------------------------------------------------
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
    authorized(P_ANALYSIS)
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


# --------------------------------------------------------------------------
# API key management (needs MANAGE_KEYS)
# --------------------------------------------------------------------------
def _perms_from_body(value):
    if value is None:
        abort(400, description='"permissions" is required (a number like 14, or a list of names)')
    try:
        return parse_perms(value)
    except ValueError as exc:
        abort(400, description=str(exc))


def _expiry_from_body(body):
    """Reads expires_in_days / expires_at / never_expires. Returns (was_given, datetime_or_None)."""
    given = [k for k in ("expires_in_days", "expires_at", "never_expires")
             if k in body and not (k == "never_expires" and body[k] in (False, None))]
    if not given:
        return False, None
    if len(given) > 1:
        abort(400, description="Use only one of expires_in_days, expires_at, never_expires")
    field = given[0]
    value = body[field]
    if field == "never_expires":
        if value is not True:
            abort(400, description='"never_expires" must be true or false')
        return True, None
    if field == "expires_in_days":
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 < value <= MAX_KEY_DAYS:
            abort(400, description=f'"expires_in_days" must be a number between 0 and {MAX_KEY_DAYS}')
        return True, datetime.now(timezone.utc) + timedelta(days=value)
    try:
        when = parse_expiry(value)
    except ValueError as exc:
        abort(400, description=str(exc))
    if when is None:
        abort(400, description='Use "never_expires": true for a key that does not expire')
    if when <= datetime.now(timezone.utc):
        abort(400, description='"expires_at" must be in the future')
    return True, when


def check_expiry_grantable(principal, expires):
    """A key can't create or extend a key that outlives itself."""
    if principal.expires is None:
        return
    if expires is None or expires > principal.expires:
        abort(403, description="A key can't make a key that outlives itself (this key expires "
                               + principal.expires.isoformat() + ")")


@app.get("/api/keys")
def list_keys():
    """Lists keys (never secrets). Environment keys are read-only here."""
    authorized(P_KEYS)
    out = [key_public(principal) for _, principal in ENV_KEYS]
    for key_id, record in load_runtime_keys()["keys"].items():
        out.append(key_public(runtime_principal(key_id, record), record))
    return jsonify(out)


@app.post("/api/keys")
def create_key():
    """Body: {"name": "label", "permissions": 14, optional expiry}. Expiry is one of expires_in_days,
    expires_at or never_expires; with none of them the key expires after KEY_DEFAULT_DAYS (60).
    The secret is shown ONCE in the response."""
    me = authorized(P_KEYS)
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        abort(400, description="Expected JSON object")
    name = _label(body.get("name"), "")
    if not name:
        abort(400, description='"name" is required')
    perms = _perms_from_body(body.get("permissions"))
    check_grantable(me, perms)
    given, expires = _expiry_from_body(body)
    if not given:
        expires = default_expiry()
    check_expiry_grantable(me, expires)
    secret = KEY_PREFIX + secrets.token_urlsafe(32)
    with _keys_lock:
        data = load_runtime_keys(force=True)
        if len(data["keys"]) >= MAX_RUNTIME_KEYS:
            abort(409, description=f"Key limit reached ({MAX_RUNTIME_KEYS}); revoke one first")
        key_id = secrets.token_hex(4)
        while key_id in data["keys"]:
            key_id = secrets.token_hex(4)
        record = {"name": name, "hash": _digest(secret), "permissions": perms,
                  "created": utc_now(), "created_by": me.id,
                  "expires": expires.isoformat() if expires else None}
        data["keys"][key_id] = record
        try:
            save_runtime_keys(data, f"Create API key {key_id} ({name}){by()}")
        except RuntimeError:
            _keys_cache["loaded"] = 0.0
            raise
    audit("key_create", key_id)
    principal = runtime_principal(key_id, record)
    return jsonify(**key_public(principal, record), key=secret,
                   warning="Copy this key now. It is stored only as a hash and cannot be shown again."), 201


def _bare_id(key_id):
    return key_id[4:] if key_id.startswith("key:") else key_id


def _runtime_key_or_404(key_id):
    if key_id.startswith("env:"):
        abort(400, description="Environment keys are managed in Render's environment variables, not through the API")
    record = load_runtime_keys(force=True)["keys"].get(_bare_id(key_id))
    if not isinstance(record, dict):
        abort(404, description="API key not found")
    return record


@app.patch("/api/keys/<key_id>")
def edit_key(key_id):
    """Body: any of name, permissions, and one of expires_in_days / expires_at / never_expires."""
    me = authorized(P_KEYS)
    body = request.get_json(silent=True)
    fields = {"name", "permissions", "expires_in_days", "expires_at", "never_expires"}
    if not isinstance(body, dict) or not (fields & set(body)):
        abort(400, description='Expected JSON with "name", "permissions" and/or an expiry field '
                               '(expires_in_days, expires_at or never_expires)')
    # Validate everything before touching anything, so a rejected request changes nothing.
    new_name = None
    if "name" in body:
        new_name = _label(body["name"], "")
        if not new_name:
            abort(400, description='"name" cannot be empty')
    new_perms = _perms_from_body(body["permissions"]) if "permissions" in body else None
    expiry_given, new_expires = _expiry_from_body(body)
    with _keys_lock:
        record = dict(_runtime_key_or_404(key_id))  # a copy: the cached original stays untouched until saved
        key_id = _bare_id(key_id)
        check_grantable(me, runtime_principal(key_id, record).perms)  # can't touch keys stronger than yours
        if new_perms is not None:
            check_grantable(me, new_perms)
        if expiry_given:
            check_expiry_grantable(me, new_expires)
        if new_name is not None:
            record["name"] = new_name
        if new_perms is not None:
            record["permissions"] = new_perms
        if expiry_given:
            record["expires"] = new_expires.isoformat() if new_expires else None
        data = load_runtime_keys()
        data["keys"][key_id] = record
        try:
            save_runtime_keys(data, f"Edit API key {key_id}{by()}")
        except RuntimeError:
            _keys_cache["loaded"] = 0.0
            raise
    audit("key_edit", key_id)
    return jsonify(key_public(runtime_principal(key_id, record), record))


@app.delete("/api/keys/<key_id>")
def revoke_key(key_id):
    me = authorized(P_KEYS)
    with _keys_lock:
        record = _runtime_key_or_404(key_id)
        key_id = _bare_id(key_id)
        check_grantable(me, runtime_principal(key_id, record).perms)
        data = load_runtime_keys()
        data["keys"].pop(key_id, None)
        try:
            save_runtime_keys(data, f"Revoke API key {key_id}{by()}")
        except RuntimeError:
            _keys_cache["loaded"] = 0.0
            raise
    audit("key_revoke", key_id)
    return jsonify(revoked=key_id)


# --------------------------------------------------------------------------
# Error handlers
# --------------------------------------------------------------------------
@app.errorhandler(404)
def not_found(e):
    return jsonify(error=getattr(e, "description", "Not found")), 404


@app.errorhandler(400)
def bad_request(e):
    return jsonify(error=getattr(e, "description", "Bad request")), 400


@app.errorhandler(401)
def unauthorized_error(e):
    return jsonify(error=getattr(e, "description", "Unauthorized")), 401


@app.errorhandler(403)
def forbidden_error(e):
    return jsonify(error=getattr(e, "description", "Forbidden")), 403


@app.errorhandler(409)
def conflict_error(e):
    return jsonify(error=getattr(e, "description", "Conflict")), 409


@app.errorhandler(413)
def too_large(e):
    return jsonify(error="Request too large"), 413


@app.errorhandler(502)
def upstream_error(e):
    return jsonify(error=getattr(e, "description", "GitHub storage error")), 502


@app.errorhandler(RuntimeError)
def github_failure(e):
    app.logger.exception("GitHub storage error")
    return jsonify(error=str(e)), 502


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "10000")))
