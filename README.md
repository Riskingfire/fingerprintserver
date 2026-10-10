# Play Fingerprint Server (Render)

This server implements the API used by `play_fingerprint_improved.py`: wake-up health checks, authenticated fingerprint upload/download/listing, shared ban list, and approximate server-side ban-evasion screening.

## Deploy on Render

1. Put this folder's contents in a GitHub repository (the `server.py`, `requirements.txt`, and `render.yaml` files must be at repository root, or adjust the Render root directory).
2. In Render, create a new Blueprint from that repository. Review the services/database in `render.yaml` and apply.
3. Render generates `API_KEY`. Open the web service's Environment page and copy its `API_KEY` value.
4. Copy the public service URL, e.g. `https://play-fingerprint-server.onrender.com`.
5. In the desktop app click **Server...**, paste URL and API key, keep “Ping the server when the app starts” enabled, then **Save + test connection**.
6. Use **Upload my fingerprints** to seed the central store and **Push my ban list** to seed bans. Turn on automatic upload if desired.

The desktop app's startup `/health` request is deliberately public and causes Render to wake from sleep. API data endpoints require `Authorization: Bearer <API_KEY>`.

## Persistence

The Render Blueprint creates PostgreSQL so uploaded fingerprints and bans survive app restarts/redeploys. SQLite is only a local fallback for testing; on Render's ephemeral filesystem, SQLite data can disappear and should not be used for production storage.

## API endpoints

- `GET /health` — public wake/health endpoint.
- `GET /api/status` — authenticated counts.
- `GET /api/fingerprints` — list names, timestamps, SHA-256.
- `GET|PUT|DELETE /api/fingerprints/<name>` — download/upload/delete compressed `.fpr` data.
- `GET /api/banlist` — get shared ban list.
- `PUT|DELETE /api/banlist/<name>` — add/update/remove ban entry.
- `POST /api/analysis` with `{"name":"candidate-name"}` — compare an uploaded candidate against server-held banned fingerprints.

## Ban-analysis warning

The server endpoint is a lightweight approximate analysis of summary statistics, not a replacement for the desktop app's full local window-based screening. Treat every result as a lead for human review, not proof of identity or grounds for an automatic ban. Shared devices, siblings, similar playstyles, and small samples can cause false positives.

## Security and privacy

Fingerprints are behavioral biometric-like data. Restrict access to the API key, use HTTPS, do not commit secrets, and upload only profiles you are authorized to share. Anyone holding the shared API key can read or modify all fingerprints and bans on this service. Rotate `API_KEY` if exposed. The app's local `server_config.json` contains the key; do not share it.
