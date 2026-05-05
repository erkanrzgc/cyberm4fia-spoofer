from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional, TYPE_CHECKING

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
import uvicorn

if TYPE_CHECKING:
    from spoof.session import SpoofSession


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CyberM4fia — Dashboard</title>
<style>
:root { --bg: #0a0a0f; --card: #111118; --accent: #00e5ff; --red: #ff1744; --green: #00e676; --yellow: #ffd600; --text: #e0e0e0; --dim: #666; }
* { margin: 0; padding: 0; box-sizing: border-box; }
body { background: var(--bg); color: var(--text); font-family: 'Courier New', monospace; padding: 20px; }
h1 { color: var(--accent); text-align: center; margin-bottom: 20px; font-size: 1.5em; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; max-width: 1200px; margin: 0 auto; }
.card { background: var(--card); border: 1px solid #222; border-radius: 8px; padding: 16px; }
.card h3 { color: var(--accent); font-size: 0.8em; text-transform: uppercase; margin-bottom: 8px; }
.card .value { font-size: 2em; font-weight: bold; }
.card .value.green { color: var(--green); }
.card .value.red { color: var(--red); }
.card .value.yellow { color: var(--yellow); }
#log { max-width: 1200px; margin: 20px auto; background: var(--card); border: 1px solid #222; border-radius: 8px; padding: 16px; max-height: 300px; overflow-y: auto; font-size: 0.8em; }
#log .entry { padding: 4px 0; border-bottom: 1px solid #1a1a1a; color: var(--dim); }
#log .spoofed { color: var(--green); }
#log .blocked { color: var(--red); }
.cred { max-width: 1200px; margin: 20px auto; background: var(--card); border: 1px solid var(--red); border-radius: 8px; padding: 16px; }
.cred h3 { color: var(--red); }
.cred-item { padding: 8px; border-bottom: 1px solid #1a1a1a; font-size: 0.85em; }
.cred-type { color: var(--yellow); }
footer { text-align: center; color: var(--dim); margin-top: 40px; font-size: 0.75em; }
</style>
</head>
<body>
<h1>CYBERM4FIA — Live Dashboard</h1>
<div class="grid">
  <div class="card"><h3>DNS Queries</h3><div class="value" id="dns_total">0</div></div>
  <div class="card"><h3>DNS Spoofed</h3><div class="value green" id="dns_spoofed">0</div></div>
  <div class="card"><h3>DNS Blocked</h3><div class="value red" id="dns_blocked">0</div></div>
  <div class="card"><h3>ARP Packets</h3><div class="value yellow" id="arp_packets">0</div></div>
  <div class="card"><h3>Credentials</h3><div class="value red" id="cred_count">0</div></div>
  <div class="card"><h3>Uptime</h3><div class="value" id="uptime">0s</div></div>
</div>
<div id="log"><h3 style="color:var(--accent);margin-bottom:8px">Live Log</h3></div>
<div class="cred" id="cred_panel"><h3>Captured Credentials</h3></div>
<footer>CyberM4fia Spoofer v1.0.0</footer>
<script>
const ws = new WebSocket(`ws://${location.host}/ws`);
const log = document.getElementById('log');
const credPanel = document.getElementById('cred_panel');
let credEntries = [];

ws.onmessage = (e) => {
  const data = JSON.parse(e.data);
  if (data.type === 'stats') {
    document.getElementById('dns_total').textContent = data.dns_queries_total;
    document.getElementById('dns_spoofed').textContent = data.dns_spoofed;
    document.getElementById('dns_blocked').textContent = data.dns_blocked;
    document.getElementById('arp_packets').textContent = data.arp_packets_sent;
    document.getElementById('uptime').textContent = data.uptime?.toFixed(0) + 's';
  } else if (data.type === 'log') {
    const cls = data.action === 'block' ? 'blocked' : data.action === 'redirect' ? 'spoofed' : '';
    const div = document.createElement('div');
    div.className = 'entry ' + cls;
    div.textContent = data.message;
    log.appendChild(div);
    if (log.children.length > 50) log.removeChild(log.firstChild);
    log.scrollTop = log.scrollHeight;
  } else if (data.type === 'cred') {
    document.getElementById('cred_count').textContent = ++credEntries.length;
    const div = document.createElement('div');
    div.className = 'cred-item';
    div.innerHTML = `<span class="cred-type">${data.cred_type}</span> = <b>${data.value}</b> <span style="color:var(--dim)">@ ${data.url?.substring(0,40)}</span>`;
    credPanel.appendChild(div);
  }
};
ws.onclose = () => { document.body.innerHTML += '<div style="text-align:center;color:red;margin-top:20px">Connection lost — refresh page</div>'; };
</script>
</body>
</html>"""


class DashboardServer:
    def __init__(self, session: 'SpoofSession', host: str = "0.0.0.0", port: int = 8080):
        self._session = session
        self._host = host
        self._port = port
        self._app = FastAPI(title="CyberM4fia Dashboard")
        self._websockets: list[WebSocket] = []
        self._setup_routes()

    def _setup_routes(self):
        app = self._app

        @app.get("/", response_class=HTMLResponse)
        async def index():
            return DASHBOARD_HTML

        @app.get("/api/stats")
        async def api_stats():
            return JSONResponse(content=self._session.stats.model_dump())

        @app.get("/api/loot")
        async def api_loot():
            loot_dir = Path("loot")
            if not loot_dir.exists():
                return JSONResponse(content={"files": []})
            files = sorted(
                [{"name": f.name, "size": f.stat().st_size, "time": f.stat().st_mtime}
                 for f in loot_dir.iterdir() if f.is_file()],
                key=lambda x: x["time"], reverse=True,
            )[:50]
            return JSONResponse(content={"files": files})

        @app.get("/loot/{filename}")
        async def download_loot(filename: str):
            path = Path("loot") / filename
            if path.exists():
                return FileResponse(path)
            return JSONResponse(content={"error": "not found"}, status_code=404)

        @app.websocket("/ws")
        async def ws_endpoint(ws: WebSocket):
            await ws.accept()
            self._websockets.append(ws)
            try:
                while True:
                    await ws.receive_text()
            except WebSocketDisconnect:
                self._websockets.remove(ws)

    async def broadcast(self, data: dict):
        dead = []
        for ws in self._websockets:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            if ws in self._websockets:
                self._websockets.remove(ws)

    def broadcast_sync(self, data: dict):
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            loop.create_task(self.broadcast(data))
        except Exception:
            pass

    def start(self):
        cfg = uvicorn.Config(self._app, host=self._host, port=self._port, log_level="warning")
        server = uvicorn.Server(cfg)
        import asyncio
        import threading

        def run():
            asyncio.run(server.serve())

        t = threading.Thread(target=run, daemon=True)
        t.start()
        return server

    @property
    def app(self):
        return self._app
