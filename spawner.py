
"""
NGDSA CTF — challenge orchestrator / spawner.

Registration form -> spawns one Docker container per team on its own
isolated network, injects TEAM_ID / LLM_PROVIDER / LLM_API_KEY /
ACCESS_TOKEN / FLAG_SECRET_SALT / DASHBOARD_INGEST_URL, then redirects the
browser straight to http://SERVER_IP:PORT/?token=... . A team that already
has a running container gets redirected to its existing instance instead
of getting a second one.

Run:
    pip install fastapi uvicorn docker python-multipart
    uvicorn spawner:app --host 0.0.0.0 --port 9000

Config (env vars on the SPAWNER itself — never on spawned containers):
    CTF_IMAGE               docker image to spawn                 (default: ai-ctf-platform:latest)
    PUBLIC_HOST              IP/hostname participants use to reach containers (REQUIRED — no baked-in default)
    DASHBOARD_INGEST_URL     where spawned containers report flags (default: http://localhost:8000/api/ingest)
    SPAWNER_ADMIN_KEY        gates /api/teardown and /api/reset-all (default: changeme — change it)
    SPAWNER_FLAG_SECRET_SALT shared secret handed to every container for flag hashing.
                             If unset, a random one is generated at startup and printed once —
                             fine for a single long-running spawner process, but if you restart
                             the spawner mid-event, newly spawned containers get a DIFFERENT salt
                             than earlier ones. Set this explicitly before the event.
    CONTAINER_PORT           port the app listens on inside the container (default: 8001)
    MAX_AGE_MINUTES          auto-teardown age limit                (default: 240)
"""

import os
import secrets
import socket
import threading
import time
from datetime import datetime, timezone
from typing import Optional

import docker
from docker.errors import NotFound, APIError
from fastapi import FastAPI, Form, HTTPException, Header, Request
from fastapi.responses import HTMLResponse, RedirectResponse


CTF_IMAGE = os.environ.get("CTF_IMAGE", "ai-ctf-platform:latest")
PUBLIC_HOST = os.environ.get("PUBLIC_HOST", "127.0.0.1")
DASHBOARD_INGEST_URL = os.environ.get("DASHBOARD_INGEST_URL", "http://localhost:8000/api/ingest")
ADMIN_KEY = os.environ.get("SPAWNER_ADMIN_KEY", "changeme")
CONTAINER_PORT = int(os.environ.get("CONTAINER_PORT", 8001))
MAX_AGE_MINUTES = int(os.environ.get("MAX_AGE_MINUTES", 240))

FLAG_SECRET_SALT = os.environ.get("SPAWNER_FLAG_SECRET_SALT")
if not FLAG_SECRET_SALT:
    FLAG_SECRET_SALT = secrets.token_hex(32)
    print(
        "[spawner] WARNING: SPAWNER_FLAG_SECRET_SALT not set — generated an ephemeral one "
        "for this process. Set it explicitly in the environment before the event, or every "
        "spawner restart will hand out a different salt to newly-spawned containers.",
        flush=True,
    )

APPROVED_TEAMS = [
    "FEDORA_PEASEANTS", "CS_ENJOYERS", "PARA_LIGO_OBRELA", "KERNEL_PANIC",
    "ROOT", "SAXO_VTS_125HP", "PEUGEUOT_308_SPORT", "CTRL_ALT_F4", "RUN_TIME_ERROR",
]

PROVIDERS = {
    "groq": "Groq",
    "cerebras": "Cerebras",
}

LABEL_MANAGED = "ctf.managed"
LABEL_TEAM = "ctf.team_id"
LABEL_PROVIDER = "ctf.provider"
LABEL_TOKEN = "ctf.token"

docker_client = docker.from_env()
app = FastAPI(title="NGDSA CTF Orchestrator")

active_teams: dict = {}
REGISTRY_LOCK = threading.Lock()




def get_free_port() -> int:
    """Ask the OS for a free ephemeral port. Called under REGISTRY_LOCK so two
    concurrent spawns can't race each other onto the same port."""
    s = socket.socket()
    s.bind(("", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _network_name(team_name: str) -> str:
    return f"ctf-net-{team_name.lower()}"


def _container_name(team_name: str) -> str:
    return f"ctf-{team_name.lower()}"


def _team_url(port: int, token: str) -> str:
    return f"http://{PUBLIC_HOST}:{port}/?token={token}"


def _rebuild_registry_from_docker():
    """Recover state after a spawner restart by re-reading container labels."""
    containers = docker_client.containers.list(all=True, filters={"label": f"{LABEL_MANAGED}=true"})
    with REGISTRY_LOCK:
        for c in containers:
            if c.status != "running":
                continue
            labels = c.labels or {}
            team_name = labels.get(LABEL_TEAM)
            token = labels.get(LABEL_TOKEN)
            if not team_name or not token:
                continue
            port = None
            try:
                ports = c.attrs["NetworkSettings"]["Ports"].get(f"{CONTAINER_PORT}/tcp")
                if ports:
                    port = int(ports[0]["HostPort"])
            except (KeyError, IndexError, TypeError):
                pass
            active_teams[team_name] = {
                "container_id": c.id,
                "name": c.name,
                "network": _network_name(team_name),
                "port": port,
                "token": token,
                "provider": labels.get(LABEL_PROVIDER, "unknown"),
                "spawned_at": c.attrs["Created"],
            }


def _ensure_team_network(team_name: str) -> str:
    """Per-team isolated bridge network — teams never see each other's containers."""
    network_name = _network_name(team_name)
    try:
        docker_client.networks.get(network_name)
    except NotFound:
        docker_client.networks.create(network_name, driver="bridge")
    return network_name


def _spawn_container(team_name: str, provider: str, api_key: str) -> dict:
    name = _container_name(team_name)

    try:
        existing = docker_client.containers.get(name)
        if existing.status == "running":
            raise HTTPException(409, f"team {team_name} already has a running container")
        existing.remove(force=True)
    except NotFound:
        pass

    network_name = _ensure_team_network(team_name)
    token = secrets.token_hex(16)

    with REGISTRY_LOCK:
        port = get_free_port()
        try:
            container = docker_client.containers.run(
                CTF_IMAGE,
                name=name,
                detach=True,
                ports={f"{CONTAINER_PORT}/tcp": port},
                mem_limit="400m",
                nano_cpus=500_000_000,
                network=network_name,
                environment={
                    "TEAM_ID": team_name,
                    "LLM_PROVIDER": provider,
                    "LLM_API_KEY": api_key,
                    "ACCESS_TOKEN": token,
                    "FLAG_SECRET_SALT": FLAG_SECRET_SALT,
                    "DASHBOARD_INGEST_URL": DASHBOARD_INGEST_URL,
                },
                labels={
                    LABEL_MANAGED: "true",
                    LABEL_TEAM: team_name,
                    LABEL_PROVIDER: provider,
                    LABEL_TOKEN: token,
                },
            )
        except APIError as e:
            raise HTTPException(500, f"docker error: {e}")

        entry = {
            "container_id": container.id,
            "name": name,
            "network": network_name,
            "port": port,
            "token": token,
            "provider": provider,
            "spawned_at": datetime.now(timezone.utc).isoformat(),
        }
        active_teams[team_name] = entry
        return entry


def _teardown_container(team_name: str) -> bool:
    with REGISTRY_LOCK:
        entry = active_teams.pop(team_name, None)
    name = entry["name"] if entry else _container_name(team_name)
    removed = False
    try:
        c = docker_client.containers.get(name)
        c.remove(force=True)
        removed = True
    except NotFound:
        removed = entry is not None
    try:
        docker_client.networks.get(_network_name(team_name)).remove()
    except (NotFound, APIError):
        pass
    return removed


def _reaper_loop():
    while True:
        time.sleep(60)
        now = datetime.now(timezone.utc)
        with REGISTRY_LOCK:
            stale = []
            for team_name, entry in active_teams.items():
                try:
                    spawned = datetime.fromisoformat(entry["spawned_at"].replace("Z", "+00:00"))
                except ValueError:
                    continue
                if (now - spawned).total_seconds() / 60 > MAX_AGE_MINUTES:
                    stale.append(team_name)
        for team_name in stale:
            _teardown_container(team_name)


@app.on_event("startup")
def _startup():
    if not PUBLIC_HOST:
        raise RuntimeError(
            "PUBLIC_HOST env var is required (the IP/hostname participants will use to reach "
            "their container) — set it before starting the spawner, e.g. PUBLIC_HOST=10.20.0.5"
        )
    _rebuild_registry_from_docker()
    threading.Thread(target=_reaper_loop, daemon=True).start()



def _team_options() -> str:
    return "\n".join(f'<option value="{t}">{t}</option>' for t in APPROVED_TEAMS)


def _provider_options() -> str:
    return "\n".join(f'<option value="{val}">{label}</option>' for val, label in PROVIDERS.items())


HTML_FORM = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NGDSA // Spawn Terminal</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Rajdhani:wght@600;700&family=JetBrains+Mono:wght@400;500;700&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  :root{{
    --void:#0b0e1f; --panel:#131834; --panel-alt:#1b2144; --line:#262c54;
    --cyan:#2de2ff; --magenta:#ff3ea5; --violet:#8b5cf6; --text-hi:#edeffc; --text-lo:#7a82ad; --text-mid:#a6adcf;
  }}
  *{{ box-sizing:border-box; }}
  body{{
    margin:0; min-height:100vh;
    background:
      radial-gradient(ellipse 900px 500px at 15% -10%, rgba(45,226,255,0.10), transparent 60%),
      radial-gradient(ellipse 900px 500px at 100% 0%, rgba(255,62,165,0.08), transparent 55%),
      var(--void);
    color:var(--text-hi); font-family:'Inter', sans-serif;
    display:flex; align-items:center; justify-content:center; padding:40px 16px;
  }}
  .card{{
    width:100%; max-width:440px; background:linear-gradient(180deg, var(--panel), var(--panel-alt) 140%);
    border:1px solid var(--line); border-radius:16px; padding:28px 28px 24px;
  }}
  .eyebrow{{ font-family:'JetBrains Mono', monospace; font-size:11px; letter-spacing:0.22em; color:var(--cyan); text-transform:uppercase; margin:0 0 6px; }}
  h1{{
    font-family:'Rajdhani', sans-serif; font-weight:700; font-size:28px; margin:0 0 4px;
    background:linear-gradient(90deg, var(--cyan), var(--violet) 55%, var(--magenta));
    -webkit-background-clip:text; background-clip:text; color:transparent;
  }}
  .sub{{ font-family:'JetBrains Mono', monospace; font-size:12px; color:var(--text-lo); margin:0 0 22px; }}
  label{{ display:block; font-family:'JetBrains Mono', monospace; font-size:11px; letter-spacing:0.1em; text-transform:uppercase; color:var(--text-mid); margin:16px 0 6px; }}
  select, input{{
    width:100%; background:var(--void); border:1px solid var(--line); border-radius:9px;
    padding:11px 13px; color:var(--text-hi); font-family:'JetBrains Mono', monospace; font-size:13px;
  }}
  select:focus, input:focus{{ outline:2px solid var(--cyan); outline-offset:1px; }}
  button{{
    width:100%; margin-top:22px; padding:13px; border:none; border-radius:9px; cursor:pointer;
    font-family:'Rajdhani', sans-serif; font-weight:700; font-size:16px; letter-spacing:0.04em;
    text-transform:uppercase; color:var(--void);
    background:linear-gradient(90deg, var(--cyan), var(--violet));
  }}
</style>
</head>
<body>
  <div class="card">
    <p class="eyebrow">NGDSA // Orchestrator</p>
    <h1>Spawn Terminal</h1>
    <p class="sub">Provision your team's isolated challenge container.</p>
    <form method="post" action="/spawn">
      <label for="team_name">Team</label>
      <select id="team_name" name="team_name" required>
        <option value="" disabled selected>Select team…</option>
        {_team_options()}
      </select>

      <label for="provider">Provider</label>
      <select id="provider" name="provider" required>
        <option value="" disabled selected>Select provider…</option>
        {_provider_options()}
      </select>

      <label for="api_key">API Key</label>
      <input id="api_key" name="api_key" type="password" placeholder="paste your provider key" autocomplete="off" required>

      <button type="submit">Spawn my instance</button>
    </form>
  </div>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
def registration_form():
    return HTML_FORM


@app.post("/spawn")
def spawn_container(team_name: str = Form(...), provider: str = Form(...), api_key: str = Form(...)):
    if team_name not in APPROVED_TEAMS:
        raise HTTPException(400, f"unknown team_name: {team_name!r}")
    if provider not in PROVIDERS:
        raise HTTPException(400, f"unknown provider: {provider!r} (expected one of {list(PROVIDERS)})")

    with REGISTRY_LOCK:
        existing = active_teams.get(team_name)
    if existing:
        return RedirectResponse(url=_team_url(existing["port"], existing["token"]), status_code=303)

    entry = _spawn_container(team_name, provider, api_key)
    return RedirectResponse(url=_team_url(entry["port"], entry["token"]), status_code=303)




@app.get("/api/status")
def status():
    with REGISTRY_LOCK:
        return [
            {
                "team_name": t,
                "url": _team_url(e["port"], e["token"]),
                "provider": e["provider"],
                "network": e["network"],
                "spawned_at": e["spawned_at"],
            }
            for t, e in active_teams.items()
        ]


@app.post("/api/teardown/{team_name}")
def teardown(request: Request, team_name: str, x_admin_key: Optional[str] = Header(None)):
    client_ip = request.client.host if request.client else "unknown"
    if client_ip not in ("127.0.0.1", "::1", "localhost"):
        raise HTTPException(404, "Not Found")
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(403, "bad admin key")
    if not _teardown_container(team_name):
        raise HTTPException(404, f"no active container for {team_name!r}")
    return {"status": "torn_down", "team_name": team_name}


@app.post("/api/reset-all")
def reset_all(request: Request, x_admin_key: Optional[str] = Header(None)):
    client_ip = request.client.host if request.client else "unknown"
    if client_ip not in ("127.0.0.1", "::1", "localhost"):
        raise HTTPException(404, "Not Found")
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(403, "bad admin key")
    with REGISTRY_LOCK:
        team_names = list(active_teams.keys())
    for team_name in team_names:
        _teardown_container(team_name)
    return {"status": "cleared", "count": len(team_names)}
