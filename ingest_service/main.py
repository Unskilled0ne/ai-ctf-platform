"""
NGDSA CTF — dashboard ingest service.

Receives POST {"team_id", "flag_name", "timestamp"} from the orchestrator
whenever a team submits a correct flag, stores it deduped on
(team_id, flag_name), and serves aggregated standings + a recent-activity
feed for the dashboard to poll.

Run:
    pip install -r requirements.txt
    uvicorn main:app --host 0.0.0.0 --port 8000

Open http://127.0.0.1:8000 — the dashboard in static/index.html is served
from this same app, so its fetch('/api/...') calls are same-origin and
need no CORS setup. Opened as a bare file instead (no server running),
the dashboard just falls back to its own demo mode.
"""

import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

DB_PATH = os.environ.get("DASHBOARD_DB_PATH", str(Path(__file__).parent / "ctf_dashboard.db"))
ADMIN_KEY = os.environ.get("DASHBOARD_ADMIN_KEY", "D3nN17_7t3_K1d")


FLAGS = [
    {"name": "SYS_PROMPT_LEAK",  "phase": 1, "points": 100},
    {"name": "PII_EXFIL",        "phase": 1, "points": 100},
    {"name": "IDOR_BREACH",      "phase": 1, "points": 100},
    {"name": "WS_SIDECHANNEL",   "phase": 1, "points": 100},
    {"name": "LOCAL_FILE",       "phase": 1, "points": 100},
    {"name": "NGDSA_WELCOME",    "phase": 2, "points": 150},
    {"name": "SOURCE_PERISTERI",      "phase": 2, "points": 150},
    {"name": "BOF_MEMLEAK",      "phase": 2, "points": 150},
    {"name": "RAG_IMPERSONATE",  "phase": 2, "points": 150},
    {"name": "BROWSER_ARTIFACT", "phase": 2, "points": 150},
]
FLAG_INDEX = {f["name"]: i for i, f in enumerate(FLAGS)}
FLAG_META = {f["name"]: f for f in FLAGS}


@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with db() as conn:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS captures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                team_id TEXT NOT NULL,
                flag_name TEXT NOT NULL,
                ts TEXT NOT NULL,
                UNIQUE(team_id, flag_name)
            )
            """
        )


app = FastAPI(title="NGDSA CTF Dashboard Ingest")


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class Capture(BaseModel):
    team_id: str = Field(..., min_length=1, max_length=100)
    flag_name: str
    timestamp: Optional[str] = None


@app.on_event("startup")
def _startup():
    init_db()


@app.post("/api/ingest")
def ingest(capture: Capture):
    if capture.flag_name not in FLAG_INDEX:
        raise HTTPException(400, f"unknown flag_name: {capture.flag_name!r}")

    ts = capture.timestamp or datetime.now(timezone.utc).isoformat()

    with db() as conn:
        try:
            conn.execute(
                "INSERT INTO captures (team_id, flag_name, ts) VALUES (?, ?, ?)",
                (capture.team_id, capture.flag_name, ts),
            )
        except sqlite3.IntegrityError:
            return {"status": "duplicate", "team_id": capture.team_id, "flag_name": capture.flag_name}

    return {"status": "recorded", "team_id": capture.team_id, "flag_name": capture.flag_name}


@app.get("/api/standings")
def standings():
    with db() as conn:
        rows = conn.execute("SELECT team_id, flag_name, ts FROM captures").fetchall()

    teams: dict = {}
    for row in rows:
        t = teams.setdefault(
            row["team_id"],
            {"team_id": row["team_id"], "flags": [0] * len(FLAGS), "last_capture": None},
        )
        idx = FLAG_INDEX[row["flag_name"]]
        t["flags"][idx] = 1
        if t["last_capture"] is None or row["ts"] > t["last_capture"]:
            t["last_capture"] = row["ts"]

    out = []
    for t in teams.values():
        score = sum(FLAGS[i]["points"] for i, hit in enumerate(t["flags"]) if hit)
        out.append({**t, "score": score})

    out.sort(key=lambda t: t["score"], reverse=True)
    return out


@app.get("/api/feed")
def feed(limit: int = 20):
    limit = max(1, min(limit, 100))
    with db() as conn:
        rows = conn.execute(
            "SELECT team_id, flag_name, ts FROM captures ORDER BY ts DESC LIMIT ?",
            (limit,),
        ).fetchall()

    return [
        {
            "team": row["team_id"],
            "flag": row["flag_name"],
            "phase": FLAG_META[row["flag_name"]]["phase"],
            "points": FLAG_META[row["flag_name"]]["points"],
            "time": row["ts"],
        }
        for row in rows
    ]


@app.post("/api/reset")
def reset(x_admin_key: Optional[str] = Header(None)):
    """Dev/testing convenience — wipes all captures. Not for event day."""
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(403, "bad admin key")
    with db() as conn:
        conn.execute("DELETE FROM captures")
    return {"status": "cleared"}


static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/", StaticFiles(directory=str(static_dir), html=True), name="static")
