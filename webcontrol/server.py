"""Web control panel (stdlib only).

A dependency-free HTTP control plane built on ``http.server`` that wraps an
``AgentRuntime``. Serves a small HTML dashboard plus a JSON API to:

  * view status (sources, scheduler, last run)
  * enable/disable sources at runtime
  * set techniques-per-run and AI strategy
  * trigger a single evaluation cycle
  * start/stop the paced background loop
  * view recent results

Mutating endpoints (everything except the dashboard and GET /api/status) are
protected by a bearer token (header ``Authorization: Bearer <token>`` or
``?token=<token>``). The token is generated at startup unless ``AGENT_TOKEN``
is set, and the full control URL (with token) is printed on launch.

Targets Python 3.12+.
"""

from __future__ import annotations

import json
import logging
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from core.runtime import AgentRuntime

logger = logging.getLogger(__name__)

_DASHBOARD = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MITRE AI Agent — Control</title>
<style>
 body{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:0;background:#0f1419;color:#e6e6e6}
 header{background:#1b2530;padding:16px 24px;border-bottom:1px solid #2a3a4a}
 h1{font-size:18px;margin:0}
 main{max-width:960px;margin:24px auto;padding:0 16px}
 .card{background:#1b2530;border:1px solid #2a3a4a;border-radius:8px;padding:16px;margin-bottom:16px}
 .row{display:flex;align-items:center;justify-content:space-between;padding:8px 0;border-bottom:1px solid #243240}
 .row:last-child{border-bottom:0}
 button{background:#2d7dd2;color:#fff;border:0;border-radius:6px;padding:8px 14px;cursor:pointer;font-size:14px}
 button.off{background:#c0392b}button.sec{background:#3a4a5a}
 input,select{background:#0f1419;color:#e6e6e6;border:1px solid #2a3a4a;border-radius:6px;padding:7px;font-size:14px}
 .tag{font-size:12px;padding:2px 8px;border-radius:10px;background:#243240}
 .on{color:#2ecc71}.dis{color:#e67e22}.err{color:#e74c3c}
 table{width:100%;border-collapse:collapse;font-size:13px}td,th{text-align:left;padding:6px;border-bottom:1px solid #243240}
 code{background:#0f1419;padding:2px 5px;border-radius:4px}
</style></head><body>
<header><h1>🛡️ Universal MITRE AI Agent — Control Panel</h1></header>
<main>
 <div class="card"><div class="row"><b>Scheduler loop</b>
   <span><button id="startBtn" onclick="api('/api/loop/start','POST')">Start loop</button>
   <button class="off" onclick="api('/api/loop/stop','POST')">Stop loop</button>
   <button class="sec" onclick="api('/api/run','POST')">Run once</button></span></div>
   <div class="row"><span>Techniques per run</span>
     <span><input id="tpr" type="number" min="1" style="width:70px">
     <button class="sec" onclick="setTpr()">Save</button></span></div>
   <div class="row"><span>AI strategy</span>
     <span><select id="strategy"><option>single</option><option>fallback</option><option>ensemble</option></select>
     <button class="sec" onclick="setStrategy()">Save</button></span></div>
 </div>
 <div class="card"><b>Sources</b><div id="sources"></div></div>
 <div class="card"><b>Status</b><pre id="status" style="white-space:pre-wrap"></pre></div>
 <div class="card"><b>Recent results</b><table id="results"><tbody></tbody></table></div>
</main>
<script>
const qs=new URLSearchParams(location.search);const TOKEN=qs.get('token')||'';
function hdr(){return TOKEN?{'Authorization':'Bearer '+TOKEN}:{}}
async function api(path,method='GET'){
  const r=await fetch(path,{method,headers:hdr()});
  if(!r.ok){alert('Error '+r.status+': '+await r.text());return}
  await refresh();}
async function setTpr(){await fetch('/api/scheduler',{method:'POST',headers:{...hdr(),'Content-Type':'application/json'},
  body:JSON.stringify({techniques_per_run:+document.getElementById('tpr').value})});refresh();}
async function setStrategy(){const s=document.getElementById('strategy').value;
  const provs=s==='single'?['mock-primary']:['mock-primary','mock-secondary','mock-tertiary'];
  await fetch('/api/ai',{method:'POST',headers:{...hdr(),'Content-Type':'application/json'},
  body:JSON.stringify({strategy:s,providers:provs})});refresh();}
async function toggle(name,enabled){await api('/api/sources/'+name+'/'+(enabled?'disable':'enable'),'POST');}
async function refresh(){
  const s=await (await fetch('/api/status',{headers:hdr()})).json();
  document.getElementById('tpr').value=s.scheduler.techniques_per_run;
  document.getElementById('strategy').value=s.ai.strategy;
  document.getElementById('startBtn').textContent=s.loop_running?'Loop running ✓':'Start loop';
  document.getElementById('status').textContent=JSON.stringify(s,null,2);
  document.getElementById('sources').innerHTML=s.sources.map(src=>{
    const cls=src.state==='active'?'on':(src.state==='error'?'err':'dis');
    return `<div class="row"><span>${src.name} <span class="tag ${cls}">${src.state}</span></span>
      <button class="${src.enabled?'off':''}" onclick="toggle('${src.name}',${src.enabled})">
      ${src.enabled?'Disable':'Enable'}</button></div>`}).join('');
  const res=await (await fetch('/api/results?limit=20',{headers:hdr()})).json();
  document.getElementById('results').innerHTML='<tbody><tr><th>Technique</th><th>Sources</th><th>Events</th></tr>'+
    res.map(r=>`<tr><td><code>${r.technique_id}</code></td><td>${(r.sources_queried||[]).join(', ')||'—'}</td>
    <td>${JSON.stringify(r.event_counts||{})}</td></tr>`).join('')+'</tbody>';
}
refresh();setInterval(refresh,5000);
</script></body></html>"""


class _Handler(BaseHTTPRequestHandler):
    runtime: AgentRuntime
    token: str
    server_version = "MitreAgentControl/0.1"

    # --- helpers ------------------------------------------------------------ #
    def _authorized(self) -> bool:
        if not self.token:
            return True
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer ") and secrets.compare_digest(
            auth[7:], self.token
        ):
            return True
        q = parse_qs(urlparse(self.path).query)
        supplied = (q.get("token") or [""])[0]
        return bool(supplied) and secrets.compare_digest(supplied, self.token)

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, payload: Any) -> None:
        self._send(code, json.dumps(payload).encode("utf-8"), "application/json")

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", 0) or 0)
        if not length:
            return {}
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw or b"{}")
            return data if isinstance(data, dict) else {}
        except json.JSONDecodeError:
            return {}

    def log_message(self, fmt: str, *args: Any) -> None:  # quieter logging
        logger.info("%s - %s", self.address_string(), fmt % args)

    # --- routing ------------------------------------------------------------ #
    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            self._send(200, _DASHBOARD.encode("utf-8"), "text/html; charset=utf-8")
            return
        if path == "/api/status":
            self._json(200, self.runtime.status())
            return
        if path == "/api/results":
            if not self._authorized():
                self._json(401, {"error": "unauthorized"})
                return
            q = parse_qs(urlparse(self.path).query)
            limit = int((q.get("limit") or ["50"])[0])
            self._json(200, self.runtime.recent_results(limit))
            return
        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if not self._authorized():
            self._json(401, {"error": "unauthorized"})
            return
        path = urlparse(self.path).path
        parts = [p for p in path.split("/") if p]
        try:
            if parts[:2] == ["api", "sources"] and len(parts) == 4:
                name, action = parts[2], parts[3]
                if action == "enable":
                    self._json(200, self.runtime.enable_source(name))
                elif action == "disable":
                    self._json(200, self.runtime.disable_source(name))
                else:
                    self._json(400, {"error": "bad action"})
                return
            if path == "/api/scheduler":
                body = self._read_json()
                val = self.runtime.set_techniques_per_run(
                    int(body.get("techniques_per_run", 5))
                )
                self._json(200, {"techniques_per_run": val})
                return
            if path == "/api/ai":
                body = self._read_json()
                self._json(
                    200,
                    self.runtime.set_ai_strategy(
                        str(body.get("strategy", "single")),
                        list(body.get("providers", [])),
                    ),
                )
                return
            if path == "/api/run":
                self._json(200, self.runtime.run_once())
                return
            if path == "/api/loop/start":
                self._json(200, {"started": self.runtime.start_loop()})
                return
            if path == "/api/loop/stop":
                self._json(200, {"stopped": self.runtime.stop_loop()})
                return
        except (KeyError, ValueError) as exc:
            self._json(400, {"error": str(exc)})
            return
        self._json(404, {"error": "not found"})


class ControlServer:
    """Owns the HTTP server + runtime."""

    def __init__(
        self,
        runtime: AgentRuntime,
        *,
        host: str = "0.0.0.0",
        port: int = 8080,
        token: str | None = None,
    ) -> None:
        self.runtime = runtime
        self.host = host
        self.port = port
        self.token = token or secrets.token_urlsafe(24)

        handler = type(
            "_BoundHandler",
            (_Handler,),
            {"runtime": runtime, "token": self.token},
        )
        self._httpd = ThreadingHTTPServer((host, port), handler)

    @property
    def bound_port(self) -> int:
        return self._httpd.server_address[1]

    def control_url(self, public_host: str | None = None) -> str:
        host = public_host or ("localhost" if self.host == "0.0.0.0" else self.host)
        return f"http://{host}:{self.bound_port}/?token={self.token}"

    def serve_forever(self) -> None:
        self._httpd.serve_forever()

    def shutdown(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()


def serve(
    config_path: str,
    *,
    host: str = "0.0.0.0",
    port: int = 8080,
    token: str | None = None,
    autostart_loop: bool = False,
    results_path: str | None = None,
) -> ControlServer:
    """Build a runtime + control server and return it (not yet serving)."""
    runtime = AgentRuntime(config_path, results_path=results_path)
    if autostart_loop:
        runtime.start_loop()
    return ControlServer(runtime, host=host, port=port, token=token)
