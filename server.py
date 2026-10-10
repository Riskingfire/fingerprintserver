import os, json, gzip, hashlib, hmac, sqlite3, io, math
from datetime import datetime, timezone
from flask import Flask, request, jsonify, abort

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024
API_KEY = os.environ.get('API_KEY', '').strip()
DATABASE_URL = os.environ.get('DATABASE_URL', '').strip()

if not API_KEY:
    raise RuntimeError('Set API_KEY in the Render environment before starting the service.')


def connect():
    if DATABASE_URL.startswith(('postgres://', 'postgresql://')):
        import psycopg
        from psycopg.rows import dict_row
        return psycopg.connect(DATABASE_URL.replace('postgres://', 'postgresql://', 1), row_factory=dict_row)
    path = os.environ.get('SQLITE_PATH', '/tmp/play_fingerprint.db')
    c = sqlite3.connect(path, timeout=20)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    with connect() as c:
        if DATABASE_URL.startswith(('postgres://', 'postgresql://')):
            c.execute('CREATE TABLE IF NOT EXISTS fingerprints (name TEXT PRIMARY KEY, blob BYTEA NOT NULL, updated TEXT NOT NULL, digest TEXT NOT NULL)')
            c.execute('CREATE TABLE IF NOT EXISTS bans (name TEXT PRIMARY KEY, data JSONB NOT NULL, updated TEXT NOT NULL)')
        else:
            c.execute('CREATE TABLE IF NOT EXISTS fingerprints (name TEXT PRIMARY KEY, blob BLOB NOT NULL, updated TEXT NOT NULL, digest TEXT NOT NULL)')
            c.execute('CREATE TABLE IF NOT EXISTS bans (name TEXT PRIMARY KEY, data TEXT NOT NULL, updated TEXT NOT NULL)')
        c.commit()


def is_pg():
    return DATABASE_URL.startswith(('postgres://', 'postgresql://'))


def authorized():
    supplied = request.headers.get('Authorization', '')
    if not supplied.startswith('Bearer ') or not hmac.compare_digest(supplied[7:].strip(), API_KEY):
        abort(401, description='Invalid or missing API key')


def clean_name(value):
    value = ''.join(ch for ch in str(value) if ch.isalnum() or ch in '-_ ').strip()
    if not value or len(value) > 100:
        abort(400, description='Invalid fingerprint name')
    return value


def unpack_profile(blob):
    try:
        raw = gzip.decompress(blob) if blob[:2] == b'\x1f\x8b' else blob
        if len(raw) > 2 * 1024 * 1024:
            abort(413, description='Fingerprint too large after decompression')
        d = json.loads(raw.decode('utf-8'))
        if d.get('format') != 'play-fingerprint' or not isinstance(d.get('windows'), list):
            abort(400, description='Not a valid Play Fingerprint file')
        if len(d.get('feature_names', [])) > 300 or len(d['windows']) > 800:
            abort(400, description='Fingerprint exceeds supported feature/window limits')
        d['name'] = clean_name(d.get('name', ''))
        return d
    except (ValueError, UnicodeError, OSError, json.JSONDecodeError):
        abort(400, description='Invalid or corrupt fingerprint data')


def get_fp_rows():
    with connect() as c:
        return c.execute('SELECT name, blob, updated FROM fingerprints ORDER BY name').fetchall()


def get_bans():
    with connect() as c:
        rows = c.execute('SELECT name, data FROM bans ORDER BY name').fetchall()
    out = {}
    for r in rows:
        out[r['name']] = r['data'] if isinstance(r['data'], dict) else json.loads(r['data'])
    return out


@app.get('/health')
def health():
    # Public on purpose: Render health checks and the desktop wake-up ping use this.
    try:
        with connect() as c:
            c.execute('SELECT 1')
        return jsonify(status='ok', service='play-fingerprint', utc=datetime.now(timezone.utc).isoformat())
    except Exception:
        app.logger.exception('health/database check failed')
        return jsonify(status='degraded', error='database unavailable'), 503


@app.get('/api/status')
def status():
    authorized()
    with connect() as c:
        f = c.execute('SELECT COUNT(*) AS n FROM fingerprints').fetchone()['n']
        b = c.execute('SELECT COUNT(*) AS n FROM bans').fetchone()['n']
    return jsonify(fingerprints=f, bans=b, storage='postgresql' if is_pg() else 'sqlite-ephemeral')


@app.get('/api/fingerprints')
def list_fingerprints():
    authorized()
    with connect() as c:
        rows = c.execute('SELECT name, updated, digest FROM fingerprints ORDER BY name').fetchall()
    return jsonify([{'name': r['name'], 'updated': r['updated'], 'sha256': r['digest']} for r in rows])


@app.get('/api/fingerprints/<path:name>')
def download_fingerprint(name):
    authorized(); name = clean_name(name)
    with connect() as c:
        row = c.execute('SELECT blob FROM fingerprints WHERE name=?', (name,)).fetchone()
    if not row: abort(404, description='Fingerprint not found')
    return app.response_class(bytes(row['blob']), mimetype='application/octet-stream')


@app.put('/api/fingerprints/<path:name>')
def upload_fingerprint(name):
    authorized(); name = clean_name(name)
    blob = request.get_data(cache=False)
    if not blob or len(blob) > 2 * 1024 * 1024: abort(413, description='Fingerprint must be 1 byte to 2 MB')
    profile = unpack_profile(blob)
    # Keep URL name and payload name consistent, preventing confusing overwrite behavior.
    if profile['name'] != name:
        profile['name'] = name
        blob = gzip.compress(json.dumps(profile, separators=(',', ':')).encode(), compresslevel=6)
    updated = str(profile.get('updated') or datetime.now(timezone.utc).isoformat())[:80]
    digest = hashlib.sha256(blob).hexdigest()
    with connect() as c:
        old = c.execute('SELECT name FROM fingerprints WHERE name=?' if not is_pg() else 'SELECT name FROM fingerprints WHERE name=%s', (name,)).fetchone()
        if is_pg():
            c.execute('INSERT INTO fingerprints(name,blob,updated,digest) VALUES(%s,%s,%s,%s) ON CONFLICT(name) DO UPDATE SET blob=EXCLUDED.blob, updated=EXCLUDED.updated, digest=EXCLUDED.digest', (name, blob, updated, digest))
        else:
            c.execute('INSERT INTO fingerprints(name,blob,updated,digest) VALUES(?,?,?,?) ON CONFLICT(name) DO UPDATE SET blob=excluded.blob, updated=excluded.updated, digest=excluded.digest', (name, blob, updated, digest))
        c.commit()
    return jsonify(name=name, updated=updated, sha256=digest), (200 if old else 201)


@app.delete('/api/fingerprints/<path:name>')
def delete_fingerprint(name):
    authorized(); name = clean_name(name)
    with connect() as c:
        cur = c.execute('DELETE FROM fingerprints WHERE name=?' if not is_pg() else 'DELETE FROM fingerprints WHERE name=%s', (name,))
        c.commit()
    if cur.rowcount == 0: abort(404, description='Fingerprint not found')
    return jsonify(deleted=name)


@app.get('/api/banlist')
def list_bans():
    authorized(); return jsonify(get_bans())


@app.put('/api/banlist/<path:name>')
def put_ban(name):
    authorized(); name = clean_name(name)
    data = request.get_json(silent=True)
    if not isinstance(data, dict): abort(400, description='Expected JSON object')
    record = {'reason': str(data.get('reason', ''))[:1000], 'date': str(data.get('date') or datetime.now(timezone.utc).isoformat())[:80]}
    with connect() as c:
        if is_pg(): c.execute('INSERT INTO bans(name,data,updated) VALUES(%s,%s,%s) ON CONFLICT(name) DO UPDATE SET data=EXCLUDED.data, updated=EXCLUDED.updated', (name, json.dumps(record), datetime.now(timezone.utc).isoformat()))
        else: c.execute('INSERT INTO bans(name,data,updated) VALUES(?,?,?) ON CONFLICT(name) DO UPDATE SET data=excluded.data, updated=excluded.updated', (name, json.dumps(record), datetime.now(timezone.utc).isoformat()))
        c.commit()
    return jsonify(name=name, ban=record)


@app.delete('/api/banlist/<path:name>')
def delete_ban(name):
    authorized(); name = clean_name(name)
    with connect() as c:
        cur = c.execute('DELETE FROM bans WHERE name=?' if not is_pg() else 'DELETE FROM bans WHERE name=%s', (name,)); c.commit()
    return jsonify(removed=name, existed=cur.rowcount > 0)


def summary_vector(profile):
    names = profile.get('feature_names', [])
    rows = profile.get('windows', [])
    result = {}
    for i, fname in enumerate(names):
        vals = []
        for row in rows:
            if i < len(row) and isinstance(row[i], (int, float)) and math.isfinite(row[i]): vals.append(float(row[i]))
        if len(vals) >= 5:
            vals.sort(); result[fname] = vals[len(vals)//2]
    return result


def distance(a, b):
    common = sorted(set(a) & set(b))
    if len(common) < 5: return None, len(common)
    diffs = []
    for k in common:
        # Robust scale from both profiles' observed windows; avoids one large-unit feature dominating.
        scale = max(abs(a[k]) * 0.10, abs(b[k]) * 0.10, 0.05)
        diffs.append(min(abs(a[k] - b[k]) / scale, 10.0))
    return sum(diffs) / len(diffs), len(common)


@app.post('/api/analysis')
def analyze_bans():
    """Central approximate screening. Results are leads for human review, never automatic bans."""
    authorized()
    body = request.get_json(silent=True) or {}
    requested_name = body.get('name')
    candidate_name = clean_name(requested_name) if requested_name else None
    rows = get_fp_rows()
    all_profiles = {}
    for r in rows:
        try:
            all_profiles[r['name']] = unpack_profile(bytes(r['blob']))
        except Exception:
            app.logger.exception('Skipping invalid stored fingerprint %s', r['name'])
    if candidate_name and candidate_name not in all_profiles:
        abort(404, description='Candidate fingerprint not found on server')
    banned = get_bans()
    candidates = [candidate_name] if candidate_name else [n for n in all_profiles if n not in banned]
    results = []
    vectors = {n: summary_vector(p) for n, p in all_profiles.items()}
    for cand_name in candidates:
        cand_vec = vectors.get(cand_name, {})
        for banned_name in banned:
            if banned_name == cand_name or banned_name not in vectors:
                continue
            d, n = distance(cand_vec, vectors[banned_name])
            if d is None:
                continue
            # Broad heuristic; the local app's full screening is more rigorous.
            flag = 'HIGH' if d < 0.18 else ('REVIEW' if d < 0.45 else 'NONE')
            results.append({'candidate': cand_name, 'banned': banned_name, 'distance': round(d, 4),
                            'shared_features': n, 'flag': flag,
                            'reason': 'Approximate summary-feature comparison; human review required.'})
    results.sort(key=lambda x: x['distance'])
    return jsonify(candidate=candidate_name or 'all non-banned fingerprints', results=results,
                   disclaimer='Heuristic only. Do not auto-ban from fingerprint similarity; shared devices, similar playstyles, and noisy samples can cause false positives.')


@app.errorhandler(HTTPException if False else 404)
def not_found(e):
    return jsonify(error=getattr(e, 'description', 'Not found')), 404

@app.errorhandler(400)
def bad_request(e): return jsonify(error=getattr(e, 'description', 'Bad request')), 400
@app.errorhandler(401)
def unauthorized_error(e): return jsonify(error=getattr(e, 'description', 'Unauthorized')), 401
@app.errorhandler(413)
def too_large(e): return jsonify(error='Request too large'), 413


init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', '10000')))
