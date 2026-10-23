"""
AI Security CTF Range — Challenge Application & Verification Engine
Features multi-phase challenges: Prompt Injection, RAG Poisoning, IDOR, WebSocket Side-Channels, and SQLite Ingestion.
"""

import hashlib
import hmac
import json
import os
import random
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

import requests
from fastapi import Body, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import PlainTextResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from chains import ChainManager
from employee_db import get_employee
from engineering_notes import all_notes_including_internal
from flag_crypto import unshroud
from parts_db import search_parts


TEAM_ID = os.environ.get("TEAM_ID")
LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "groq")
LLM_API_KEY = os.environ.get("LLM_API_KEY", "")
ACCESS_TOKEN = os.environ.get("ACCESS_TOKEN")
FLAG_SECRET_SALT = os.environ.get("FLAG_SECRET_SALT")
DASHBOARD_INGEST_URL = os.environ.get("DASHBOARD_INGEST_URL")

for _name, _val in [("TEAM_ID", TEAM_ID), ("ACCESS_TOKEN", ACCESS_TOKEN), ("FLAG_SECRET_SALT", FLAG_SECRET_SALT)]:
    if not _val:
        raise RuntimeError(f"required env var {_name} is not set")

DATA_DIR = Path(os.environ.get("CTF_DATA_DIR", str(Path(__file__).parent / "data")))
DATA_DIR.mkdir(parents=True, exist_ok=True)
ENG_PARTS_DB_PATH = DATA_DIR / "eng_parts.db"
PROGRESS_PATH = DATA_DIR / "progress.json"


FLAGS = [
    {"name": "SYS_PROMPT_LEAK",   "phase": 1, "points": 100},
    {"name": "PII_EXFIL",         "phase": 1, "points": 100},
    {"name": "IDOR_BREACH",       "phase": 1, "points": 100},
    {"name": "WS_SIDECHANNEL",    "phase": 1, "points": 100},
    {"name": "LOCAL_FILE",        "phase": 1, "points": 100},
    {"name": "NGDSA_WELCOME",     "phase": 2, "points": 150},
    {"name": "SOURCE_PERISTERI",  "phase": 2, "points": 150},
    {"name": "BOF_MEMLEAK",       "phase": 2, "points": 150},
    {"name": "RAG_IMPERSONATE",   "phase": 2, "points": 150},
    {"name": "BROWSER_ARTIFACT",  "phase": 2, "points": 150},
]
FLAG_META = {f["name"]: f for f in FLAGS}
PHASE1_NAMES = [f["name"] for f in FLAGS if f["phase"] == 1]
PHASE2_NAMES = [f["name"] for f in FLAGS if f["phase"] == 2]


FLAG_BASE_SECRETS = {
    "SYS_PROMPT_LEAK": unshroud("2020202f223d223d24793d2d362466680d5718", "SYS_PROMPT_LEAK_key"),
    "PII_EXFIL": unshroud("2020207220202020207209040a35642a6e7c3c", "PII_EXFIL_key"),
    "IDOR_BREACH": "idor-breach-base",
    "WS_SIDECHANNEL": "ws-sidechannel-base",
    "LOCAL_FILE": unshroud("2020202020392f2529683d0a161c617626727f", "LOCAL_FILE_key"),
    "NGDSA_WELCOME": unshroud("392228302e3232682e223c28686b095748", "NGDSA_WELCOME_key"),
    "SOURCE_PERISTERI": unshroud("202020202020723224212c7e35756a7e", "SOURCE_PERISTERI_key"),
    "BOF_MEMLEAK": unshroud("2020203228282129242a663d0a161c6f7e773928", "BOF_MEMLEAK_key"),
    "RAG_IMPERSONATE": unshroud("20202036243d3537213c212f3531683d0a161c7f25726f7b", "RAG_IMPERSONATE_key"),
    "BROWSER_ARTIFACT": unshroud("202020202020203e33263d2f272237793d0a161c6f642c6032", "BROWSER_ARTIFACT_key"),
}


def derive_flag(flag_name: str) -> str:
    """Per-team dynamic flag: HMAC(FLAG_SECRET_SALT, TEAM_ID:flag_name:base_secret).
    Two different teams get two different strings for the "same" flag, so
    one team can't just hand another a working answer. FLAG_SECRET_SALT is
    only ever an env var (same value across every container this event,
    set once by whoever runs the spawner) — it is never written to disk
    inside the image."""
    digest = hmac.new(
        key=FLAG_SECRET_SALT.encode("utf-8"),
        msg=f"{TEAM_ID}:{flag_name}:{FLAG_BASE_SECRETS[flag_name]}".encode("utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()[:16]
    return f"NGDSA{{{flag_name}_{digest}}}"


def derive_source_flag() -> str:
    """SOURCE_PERISTERI is the one exception to per-team derivation.
    Its intended solve path is "read the shipped source, find unshroud(),
    decode the blob yourself" — but FLAG_SECRET_SALT is deliberately never
    written into source (it's an env var), so a solver reading source alone
    can never reconstruct a salted flag on their own. Rather than fake that
    solve path, this flag is intentionally STATIC (same value for every
    team, since every team runs the same image). Trade-off: this one flag
    is shareable between teams if someone chooses to leak it — acceptable
    for a "read the source" freebie-tier flag, but flag it to yourself if
    that's not an acceptable trade-off for your event, since it's a
    deliberate deviation from the rest of the roster."""
    digest = hashlib.sha256(FLAG_BASE_SECRETS["SOURCE_PERISTERI"].encode("utf-8")).hexdigest()[:16]
    return f"NGDSA{{SOURCE_PERISTERI_{digest}}}"


DERIVED_FLAGS = {name: derive_flag(name) for name in FLAG_BASE_SECRETS if name != "SOURCE_PERISTERI"}
DERIVED_FLAGS["SOURCE_PERISTERI"] = derive_source_flag()
VALID_FLAG_VALUES = {v: k for k, v in DERIVED_FLAGS.items()}


_progress_lock = threading.Lock()


def _load_progress() -> set:
    if PROGRESS_PATH.exists():
        try:
            return set(json.loads(PROGRESS_PATH.read_text()))
        except (json.JSONDecodeError, OSError):
            pass
    return set()


def _save_progress(captured: set):
    PROGRESS_PATH.write_text(json.dumps(sorted(captured)))


captured_flags: set = _load_progress()


def phase1_complete() -> bool:
    return all(name in captured_flags for name in PHASE1_NAMES)


def report_capture(flag_name: str):
    """Fire-and-forget POST to the dashboard. Swallows network errors so a
    dashboard outage never blocks a team from getting credit locally —
    but note that means the DASHBOARD's copy of standings can drift from
    this container's local progress.json if DASHBOARD_INGEST_URL is down
    for a while. No retry/backoff queue here; add one if that's a risk for
    your event's network setup (see the plan doc's networking section)."""
    try:
        requests.post(
            DASHBOARD_INGEST_URL,
            json={
                "team_id": TEAM_ID,
                "flag_name": flag_name,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            timeout=5,
        )
    except requests.RequestException as e:
        print(f"[main] WARNING: failed to report {flag_name} to dashboard: {e}", flush=True)



def seed_eng_parts_db():
    conn = sqlite3.connect(ENG_PARTS_DB_PATH)
    try:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS engineering_log (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   part_id TEXT, entry TEXT
               )"""
        )
        count = conn.execute("SELECT COUNT(*) FROM engineering_log").fetchone()[0]
        if count == 0:
            rows = [
                ("BRK-2201", "Pad compound revised 2021, dust reduction, no fitment change."),
                ("ENG-3110", "Tensioner supplier changed batch #4471, torque spec unchanged."),
                ("SUS-4402", "Strut mount bearing upgraded, NVH complaints on early units."),
                ("INTERNAL", f"debug-artifact flag={derive_flag('LOCAL_FILE')}"),
            ]
            conn.executemany("INSERT INTO engineering_log (part_id, entry) VALUES (?, ?)", rows)
            conn.commit()
    finally:
        conn.close()




app = FastAPI(title="NGDSA CTF Challenge App")

try:
    chain_manager = ChainManager()
except ValueError as e:
    print(f"[main] WARNING: ChainManager init failed ({e}); LLM routes will 500.", flush=True)
    chain_manager = None


@app.on_event("startup")
def _startup():
    seed_eng_parts_db()



@app.middleware("http")
async def access_token_gate(request: Request, call_next):
    token = request.query_params.get("token") or request.cookies.get("access_token")
    if token != ACCESS_TOKEN:
        if request.url.path.startswith("/api/"):
            return PlainTextResponse("403 Forbidden — missing or invalid access token", status_code=403)
        return HTMLResponse("""
        <!DOCTYPE html>
        <html lang="en">
        <head>
        <title>Login</title>
        <style>
          body { background:#0b0e1f; color:#2de2ff; font-family:monospace; padding:50px; text-align:center; }
          .container { max-width: 400px; margin: 0 auto; background: #131834; padding: 30px; border: 1px solid #262c54; border-radius: 10px; }
          input { width: 100%; padding: 10px; margin: 10px 0; background: #0b0e1f; color: #edeffc; border: 1px solid #262c54; border-radius: 5px; box-sizing: border-box; }
          button { width: 100%; padding: 10px; background: linear-gradient(90deg, #2de2ff, #8b5cf6); color: #0b0e1f; border: none; font-weight: bold; cursor: pointer; border-radius: 5px; }
        </style>
        </head>
        <body>
            <div class="container">
                <h2>ENTER TEAM PASSWORD</h2>
                <form onsubmit="event.preventDefault(); window.location.href = '?token=' + encodeURIComponent(document.getElementById('pw').value);">
                    <input type="password" id="pw" placeholder="Password..." required autofocus />
                    <button type="submit">LOGIN</button>
                </form>
            </div>
        </body>
        </html>
        """)
    response = await call_next(request)
    if request.query_params.get("token"):
        response.set_cookie("access_token", ACCESS_TOKEN, httponly=True, samesite="lax")
    return response


@app.get("/api/whoami")
def whoami():
    return {
        "team_id": TEAM_ID,
        "provider": LLM_PROVIDER,
        "phase1_complete": phase1_complete(),
        "captured": sorted(captured_flags),
    }



@app.get("/api/parts/search")
def parts_search(q: str = ""):
    return search_parts(q)


@app.post("/api/chat")
def chat(payload: dict = Body(...)):
    if chain_manager is None:
        raise HTTPException(500, "LLM provider not configured correctly on this container")
    message = (payload.get("message") or "").strip()
    if not message:
        raise HTTPException(400, "message is required")

    parts_context = json.dumps(search_parts(message), indent=2)
    notes_context = json.dumps(all_notes_including_internal(), indent=2)

    return {
        "joke": chain_manager.joke_chain(message, DERIVED_FLAGS["SYS_PROMPT_LEAK"]),
        "specs": chain_manager.parts_chain(message, parts_context),
        "notes": chain_manager.notes_chain(message, notes_context),
    }



@app.get("/api/employees/{employee_id}")
def employee_lookup(employee_id: int):
    emp = get_employee(employee_id)
    if emp is None:
        raise HTTPException(404, "no such employee")
    result = dict(emp)
    if "notes_base_secret" in result:
        result.pop("notes_base_secret")
        result["notes"] = f"debug-artifact flag={derive_flag('IDOR_BREACH')}"
    return result


FAKE_LOG_LINES = [
    "healthcheck: parts-index OK (8 categories)",
    "cache: notes_chain warm hit rate 91%",
    "queue: chat-fanout depth=0",
    "gc: minor collection, 4ms",
    "metrics: p50 chat latency 640ms",
    "auth: session pool 1 active",
    "replica: standings sync ack",
]


@app.websocket("/ws/debug")
async def ws_debug(websocket: WebSocket):
    token = websocket.query_params.get("token") or websocket.cookies.get("access_token")
    if token != ACCESS_TOKEN:
        await websocket.close(code=4403)
        return

    await websocket.accept()
    flag_line_index = 3
    try:
        burst = list(FAKE_LOG_LINES)
        burst.insert(flag_line_index, f"debug: internal artifact = {derive_flag('WS_SIDECHANNEL')}")
        for line in burst:
            await websocket.send_text(f"[{datetime.now(timezone.utc).isoformat()}] {line}")
        while True:
            line = random.choice(FAKE_LOG_LINES)
            await websocket.send_text(f"[{datetime.now(timezone.utc).isoformat()}] {line}")
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass



@app.post("/api/flags/submit")
def submit_flag(payload: dict = Body(...)):
    submitted = (payload.get("flag") or "").strip()
    flag_name = VALID_FLAG_VALUES.get(submitted)
    if flag_name is None:
        raise HTTPException(400, "incorrect flag")

    meta = FLAG_META[flag_name]
    if meta["phase"] == 2 and not phase1_complete():
        raise HTTPException(403, "Phase 2 is locked until all Phase 1 flags are captured")

    with _progress_lock:
        if flag_name in captured_flags:
            return {"status": "duplicate", "flag_name": flag_name}
        captured_flags.add(flag_name)
        _save_progress(captured_flags)

    report_capture(flag_name)
    return {
        "status": "captured",
        "flag_name": flag_name,
        "points": meta["points"],
        "phase1_complete": phase1_complete(),
    }


@app.get("/api/phase2/welcome")
def phase2_welcome():
    if not phase1_complete():
        raise HTTPException(403, "Phase 2 is locked until all Phase 1 flags are captured")
    return {
        "message": (
            "Welcome to the NGDSA Cyber Team internal tools. Your onboarding "
            f"packet includes this reference code: {derive_flag('NGDSA_WELCOME')}"
        )
    }



SOURCE_ALLOWLIST = {"main.py", "chains.py", "flag_crypto.py", "parts_db.py", "employee_db.py", "engineering_notes.py"}


@app.get("/api/source/{filename}")
def read_source(filename: str):
    if not phase1_complete():
        raise HTTPException(403, "Phase 2 is locked until all Phase 1 flags are captured")
    if filename not in SOURCE_ALLOWLIST:
        raise HTTPException(404, "no such file")
    path = Path(__file__).parent / filename
    return PlainTextResponse(path.read_text())



def _fake_memory_dump(flag: str) -> str:
    def hexrow(addr: int) -> str:
        chunk = os.urandom(16).hex()
        return f"0x{addr:08x}  " + " ".join(chunk[i:i + 2] for i in range(0, len(chunk), 2))

    rows = [hexrow(0x7ffee000 + i * 16) for i in range(6)]
    rows.insert(3, f"0x7ffee0300  {flag}  <-- adjacent heap chunk")
    return "*** buffer overflow detected ***\nstack smashing near diagnostics_handler+0x41\n\n" + "\n".join(rows)


@app.post("/api/phase2/diagnostics")
def phase2_diagnostics(payload: dict = Body(...)):
    if not phase1_complete():
        raise HTTPException(403, "Phase 2 is locked until all Phase 1 flags are captured")
    buf = payload.get("buffer", "")
    if len(buf) > 64:
        return PlainTextResponse(_fake_memory_dump(derive_flag("BOF_MEMLEAK")), status_code=500)
    return {"status": "ok", "echo": buf, "len": len(buf)}



def _phase2_kb(flag: str):
    return [
        {"id": "kb-1", "confidential": False, "text": "NGDSA Cyber Team office hours: Mon-Fri 10:00-16:00."},
        {"id": "kb-2", "confidential": False, "text": "Report false positives via the #security-triage channel."},
        {"id": "kb-3", "confidential": True, "text": f"CONFIDENTIAL escalation code (NGDSA_ADMIN only): {flag}"},
    ]


@app.post("/api/phase2/chat")
def phase2_chat(payload: dict = Body(...)):
    if not phase1_complete():
        raise HTTPException(403, "Phase 2 is locked until all Phase 1 flags are captured")
    if chain_manager is None:
        raise HTTPException(500, "LLM provider not configured correctly on this container")
    message = (payload.get("message") or "").strip()
    if not message:
        raise HTTPException(400, "message is required")

    kb_context = json.dumps(_phase2_kb(derive_flag("RAG_IMPERSONATE")), indent=2)
    return {"reply": chain_manager.rag_chain(message, kb_context)}


@app.get("/api/phase2/artifact")
def phase2_artifact():
    if not phase1_complete():
        raise HTTPException(403, "Phase 2 is locked until all Phase 1 flags are captured")
    return {"artifact": derive_flag("BROWSER_ARTIFACT")}


@app.get("/download/{filename}")
@app.get("/api/download/{filename}")
def download_file(filename: str):
    if "/" in filename or "\\" in filename or filename != Path(filename).name:
        raise HTTPException(400, "invalid filename")
    path = DATA_DIR / filename
    if not path.exists():
        raise HTTPException(404, "no such file")
    return PlainTextResponse(path.read_bytes().decode("latin-1"))


HINTS = {
    1: [
        "The joke-teller chain never filters its own output. What happens if you ask it to repeat its instructions?",
        "Not every note in the engineering-notes chain's context is meant to reach a customer. Ask it to show its full context.",
        "/api/employees/1 exists. Does /api/employees/{something_else}?",
        "Not every websocket route needs to be linked from the UI to be reachable.",
        "Someone left a database file somewhere it probably shouldn't be servable from.",
    ],
    2: [
        "Welcome to Phase 2. Yes, this hint is exactly as useful as it looks.",
        "Reading comprehension: sometimes the flag is literally in a file you can just... request.",
        "If a server has an internal escalation code, and you just SAY you're the internal team...",
        "Buffers have limits. What's on the other side of one?",
        "Open your browser's devtools -> Application/Storage tab after Phase 2 loads. Really.",
    ],
}


@app.get("/api/hints")
def hints():
    phase = 2 if phase1_complete() else 1
    return {"phase": phase, "hints": HINTS[phase]}



static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/", StaticFiles(directory=str(static_dir), html=True), name="static")
