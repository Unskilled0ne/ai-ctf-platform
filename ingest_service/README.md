# CTF Dashboard Ingest Service

Receives flag captures from the orchestrator and serves the live
leaderboard shown in `static/index.html`.

## Run locally

```bash
pip install -r requirements.txt
uvicorn main:app --reload
```
Then open http://127.0.0.1:8000

## Run in Docker

```bash
docker build -t ctf-dashboard .
docker run -p 8000:8000 -v $(pwd)/data:/app/data \
  -e DASHBOARD_DB_PATH=/app/data/ctf_dashboard.db \
  ctf-dashboard
```

## Point your orchestrator at it

Set `DASHBOARD_INGEST_URL=http://<this-host>:8000/api/ingest` in the
orchestrator's environment (per the plan doc's env-var spec), and POST:

```json
{"team_id": "FEDORA_PEASEANTS", "flag_name": "IDOR_BREACH", "timestamp": "2026-08-11T14:22:00Z"}
```

`timestamp` is optional — the server stamps it if omitted. Duplicate
`(team_id, flag_name)` pairs are silently deduped and return
`{"status": "duplicate"}` instead of erroring, so the orchestrator doesn't
need its own idempotency check.

`flag_name` must be one of the 10 names in the `FLAGS` list at the top of
`main.py` — that list is the source of truth for scoring (points + phase)
and must stay in sync with the matching `FLAGS` array in
`static/index.html`.

## Endpoints

| Method | Path            | Purpose                                      |
|--------|-----------------|-----------------------------------------------|
| POST   | `/api/ingest`   | Record a flag capture                        |
| GET    | `/api/standings`| Per-team flags/score, sorted by score desc    |
| GET    | `/api/feed`     | Recent captures, newest first (`?limit=`)     |
| POST   | `/api/reset`    | Wipe all captures — dev/testing only, needs `X-Admin-Key` header matching `DASHBOARD_ADMIN_KEY` env var (default `changeme`, **change it**) |

## Notes

- Storage is a single SQLite file (`ctf_dashboard.db` by default). Fine
  for ~30 teams; back it up before the event same as the rest of the VM.
- `/api/reset` is unauthenticated beyond the admin key — don't leave the
  default key in place if this is reachable from the event network.
