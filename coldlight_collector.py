#!/usr/bin/env python3
"""
Collection server for the ColdLight awareness test.

Receives hit records from the payload, stores them in SQLite (de-duplicated by
run_id), and serves a small dashboard. Run this ON YOUR OWN engagement infra.

    python coldlight_collector.py --token "$(python -c 'import secrets;print(secrets.token_urlsafe(24))')"
    # or via the CLI:
    python coldlight.py serve --token <token>

Security posture (this is the #2 upgrade over the old CSV stub):
  - Bearer-token auth on ingest AND on the stats API (constant-time compare).
  - Per-IP rate limiting and a hard request-body size cap.
  - Input validation + field length clipping before anything touches the DB.
  - Binds to 127.0.0.1 by default. If you expose it, put it behind HTTPS/a
    reverse proxy -- do not serve plain http:// on a hostile network.

Endpoints:
    POST /awareness/hit   (auth)  JSON hit record -> stored, deduped
    GET  /api/stats       (auth)  aggregate metrics as JSON
    GET  /                        dashboard (static shell; data needs the token)
    GET  /healthz                 liveness check, no auth
"""

from __future__ import annotations

import argparse
import hmac
import json
import threading
import time
import uuid
from collections import defaultdict, deque
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import coldlight_report as rr
import coldlight_safelist

MAX_BODY = 64 * 1024          # reject bodies larger than 64 KiB
RATE_MAX = 60                 # max requests ...
RATE_WINDOW = 60.0           # ... per IP per this many seconds


DASHBOARD_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ColdLight Awareness Dashboard</title>
<style>
 :root{color-scheme:light dark;--bg:#f5f6f8;--card:#fff;--fg:#1c1d21;--mut:#667;--accent:#d9480f;--bar:#4c6ef5}
 @media(prefers-color-scheme:dark){:root{--bg:#16171b;--card:#202127;--fg:#e9eaee;--mut:#99a;--bar:#5c7cfa}}
 *{box-sizing:border-box}body{font-family:system-ui,Segoe UI,Roboto,sans-serif;margin:0;background:var(--bg);color:var(--fg);padding:1.5rem}
 h1{font-size:1.3rem;margin:0 0 1rem}.row{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:1.25rem}
 .tile{background:var(--card);border-radius:12px;padding:1rem 1.25rem;min-width:140px;box-shadow:0 2px 10px rgba(0,0,0,.08);border-top:4px solid var(--accent)}
 .tile .n{font-size:2rem;font-weight:700}.tile .l{color:var(--mut);font-size:.8rem;text-transform:uppercase;letter-spacing:.04em}
 .card{background:var(--card);border-radius:12px;padding:1.25rem;box-shadow:0 2px 10px rgba(0,0,0,.08);margin-bottom:1.25rem}
 table{width:100%;border-collapse:collapse;font-size:.9rem}th,td{text-align:left;padding:.4rem .6rem;border-bottom:1px solid rgba(128,128,128,.2)}
 th{color:var(--mut);font-weight:600}input{padding:.5rem;border-radius:8px;border:1px solid #8884;background:var(--card);color:var(--fg)}
 button{padding:.5rem .9rem;border:0;border-radius:8px;background:var(--bar);color:#fff;cursor:pointer}
 .bar{fill:var(--bar)}.axis{fill:var(--mut);font-size:10px}.muted{color:var(--mut)}
</style></head><body>
<h1>ColdLight Awareness Dashboard</h1>
<div id="auth" class="card">
  <p class="muted">Enter the collector token to load data.</p>
  <input id="tok" type="password" placeholder="collector token" size="36">
  <button onclick="saveTok()">Load</button>
  <span id="err" style="color:var(--accent)"></span>
</div>
<div id="dash" style="display:none">
  <div class="row" id="tiles"></div>
  <p class="muted" id="vec"></p>
  <div class="card"><h3 style="margin:.2rem 0 1rem">Runs by day</h3><div id="chart"></div></div>
  <div class="card"><h3 style="margin:.2rem 0 1rem">Per engagement</h3><div id="eng"></div></div>
  <p class="muted" id="ts"></p>
</div>
<script>
 const $=id=>document.getElementById(id);
 function saveTok(){try{sessionStorage.setItem('coldlight_tok',$('tok').value.trim())}catch(e){}load()}
 function tok(){try{return sessionStorage.getItem('coldlight_tok')||''}catch(e){return ''}}
 async function load(){
   const t=tok(); if(!t)return;
   let r; try{r=await fetch('/api/stats',{headers:{Authorization:'Bearer '+t}})}catch(e){$('err').textContent='network error';return}
   if(r.status===401){$('err').textContent='bad token';return}
   if(!r.ok){$('err').textContent='error '+r.status;return}
   const s=await r.json(); render(s);
   $('auth').style.display='none'; $('dash').style.display='';
 }
 function tile(n,l){return `<div class="tile"><div class="n">${n}</div><div class="l">${l}</div></div>`}
 function render(s){
   $('tiles').innerHTML=tile(s.total_runs,'Total runs')+tile(s.unique_hosts,'Unique hosts')+tile(s.unique_users,'Unique users');
   $('vec').textContent='By vector: '+(Object.entries(s.by_vector||{}).map(([k,v])=>k+' '+v).join(', ')||'none')+(s.excluded_runs?('  |  excluded (safe-listed): '+s.excluded_runs):'');
   const days=Object.entries(s.by_day);
   if(days.length){
     const peak=Math.max(...days.map(d=>d[1])),W=Math.max(360,days.length*44),H=160,bw=28;
     let svg=`<svg width="100%" viewBox="0 0 ${W} ${H}" xmlns="http://www.w3.org/2000/svg">`;
     days.forEach((d,i)=>{const h=Math.round((H-30)*d[1]/peak),x=10+i*44,y=H-20-h;
       svg+=`<rect class="bar" x="${x}" y="${y}" width="${bw}" height="${h}" rx="3"/>`;
       svg+=`<text class="axis" x="${x+bw/2}" y="${y-4}" text-anchor="middle">${d[1]}</text>`;
       svg+=`<text class="axis" x="${x+bw/2}" y="${H-6}" text-anchor="middle">${d[0].slice(5)}</text>`;});
     $('chart').innerHTML=svg+'</svg>';
   }else $('chart').innerHTML='<p class="muted">No runs yet.</p>';
   const e=Object.entries(s.per_engagement);
   let html='<table><tr><th>Engagement</th><th>Runs</th><th>Hosts</th><th>First run</th><th>Last run</th></tr>';
   if(!e.length)html+='<tr><td colspan=5 class="muted">No data yet.</td></tr>';
   e.forEach(([k,v])=>{html+=`<tr><td>${k}</td><td>${v.count}</td><td>${v.unique_hosts}</td><td>${v.first_run||''}</td><td>${v.last_run||''}</td></tr>`});
   $('eng').innerHTML=html+'</table>';
   $('ts').textContent='Loaded '+new Date().toLocaleString();
 }
 load();
</script></body></html>"""


# Benign training page shown when someone clicks the awareness link / scans the QR.
# It records the click and teaches -- it NEVER asks for a password or any input.
LANDING_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Awareness Test</title>
<style>
 :root{color-scheme:light dark;--bg:#f5f6f8;--card:#fff;--fg:#1c1d21;--mut:#667;--accent:#d9480f}
 @media(prefers-color-scheme:dark){:root{--bg:#16171b;--card:#202127;--fg:#e9eaee;--mut:#99a}}
 body{font-family:system-ui,Segoe UI,Roboto,sans-serif;margin:0;background:var(--bg);color:var(--fg);
   display:flex;justify-content:center;padding:2rem 1rem}
 .card{max-width:620px;background:var(--card);border-radius:14px;padding:2rem 2.25rem;
   box-shadow:0 8px 30px rgba(0,0,0,.12);border-top:6px solid var(--accent)}
 h1{font-size:1.35rem;margin:.2rem 0 1rem}.flag{font-size:2.5rem}.ok{color:#2b8a3e;font-weight:600}
 ul{padding-left:1.2rem}li{margin:.35rem 0}.mut{color:var(--mut);font-size:.9rem;margin-top:1.25rem}
</style></head><body>
<div class="card">
 <div class="flag">&#9888;&#65039;</div>
 <h1>This was a security awareness test</h1>
 <p>You followed a link from a message or code you weren't expecting. In a real
    attack, that page could have tried to steal your password or install malware.</p>
 <p class="ok">Nothing happened here. We did <strong>not</strong> ask for your
    password, and nothing was installed.</p>
 <h2 style="font-size:1.05rem">Before you click next time</h2>
 <ul>
   <li>Check the sender and hover the link before clicking.</li>
   <li>Never enter your password on a page you reached from an unexpected link or QR code.</li>
   <li>Report suspicious messages to IT / Security.</li>
 </ul>
 <p class="mut">Authorized security-awareness exercise. You're not in trouble.</p>
</div></body></html>"""


class CollectorServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, token: str, db_path: str,
                 safelist: list[str] | None = None, retention_days: int | None = None):
        super().__init__(addr, CollectorHandler)
        self.token = token
        self.conn = rr.connect(db_path)
        self.lock = threading.Lock()
        self.rate: dict[str, deque] = defaultdict(deque)
        self.safelist = safelist or []
        self.stop = threading.Event()
        if retention_days:
            self._start_retention(retention_days)

    def _start_retention(self, days: int, interval: float = 3600.0) -> None:
        def loop():
            while not self.stop.wait(interval):
                try:
                    with self.lock:
                        n = rr.purge(self.conn, older_than_days=days)
                    if n:
                        print(f"[retention] purged {n} hits older than {days}d")
                except Exception:
                    pass
        threading.Thread(target=loop, daemon=True).start()

    def shutdown(self):
        self.stop.set()
        super().shutdown()


class CollectorHandler(BaseHTTPRequestHandler):
    server_version = "ColdLightCollector/2.0"

    # -- helpers ----------------------------------------------------------
    def _json(self, code: int, obj: dict, *, close: bool = False) -> None:
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if close:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        self.wfile.write(body)
        try:
            self.wfile.flush()
        except OSError:
            pass

    def _drain(self, limit: int) -> None:
        """Discard up to `limit` bytes of the request body.

        If we reply without reading a body the client is still sending,
        closing the socket makes the OS send an RST and the client sees a
        connection reset instead of our status code. Draining a BOUNDED
        amount avoids that. The bound matters: we must never let a client
        make us read unbounded data, so a genuinely enormous body still gets
        cut off.
        """
        remaining = max(0, int(limit))
        while remaining > 0:
            try:
                chunk = self.rfile.read(min(remaining, 8192))
            except OSError:
                return
            if not chunk:
                return
            remaining -= len(chunk)

    def _authorized(self) -> bool:
        presented = ""
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            presented = auth[7:]
        else:
            presented = self.headers.get("X-ColdLight-Token", "")
        return bool(presented) and hmac.compare_digest(presented, self.server.token)

    def _rate_limited(self) -> bool:
        ip = self.client_address[0]
        now = time.monotonic()
        with self.server.lock:
            q = self.server.rate[ip]
            while q and q[0] < now - RATE_WINDOW:
                q.popleft()
            if len(q) >= RATE_MAX:
                return True
            q.append(now)
        return False

    def _visitor(self) -> tuple[str, bool]:
        """Return (visitor_id, is_new). Reuses the `rv` cookie for click dedup."""
        try:
            jar = cookies.SimpleCookie(self.headers.get("Cookie", ""))
            if "rv" in jar and jar["rv"].value:
                return jar["rv"].value[:64], False
        except Exception:
            pass
        return uuid.uuid4().hex, True

    def log_message(self, fmt, *args):  # quieter default logging
        return

    # -- routes -----------------------------------------------------------
    def do_GET(self):
        if self.path == "/healthz":
            self._json(200, {"status": "ok"})
            return

        parsed = urlparse(self.path)
        if parsed.path == "/land":
            # Public click-tracking landing page (no auth; targets have no token).
            if self._rate_limited():
                self._json(429, {"error": "rate limited"})
                return
            qs = parse_qs(parsed.query)
            campaign = (qs.get("c", [""])[0])[:128]
            tag = (qs.get("t", [""])[0])[:128]
            visitor, is_new = self._visitor()
            record = {
                "engagement_id": campaign,
                "run_id": f"click:{visitor}:{campaign}",   # dedup repeat visits
                "timestamp_utc": _now_iso(), "received_utc": _now_iso(),
                "hostname": "", "username": "",
                "os": self.headers.get("User-Agent", "")[:200],
                "ran_from": tag,
            }
            with self.server.lock:
                rr.insert_hit(self.server.conn, record, vector="link")
            body = LANDING_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            if is_new:
                self.send_header("Set-Cookie", f"rv={visitor}; Path=/; HttpOnly; SameSite=Lax")
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.split("?")[0] == "/":
            body = DASHBOARD_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.split("?")[0] == "/api/stats":
            if not self._authorized():
                self._json(401, {"error": "unauthorized"})
                return
            with self.server.lock:
                stats = rr.compute_stats(self.server.conn)
            self._json(200, stats)
            return
        self._json(404, {"error": "not found"})

    def do_POST(self):
        if self.path.split("?")[0] != "/awareness/hit":
            self._json(404, {"error": "not found"})
            return
        if self._rate_limited():
            self._json(429, {"error": "rate limited"})
            return
        if not self._authorized():
            self._json(401, {"error": "unauthorized"})
            return

        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY:
            # Drain a bounded amount first so the client reads our 413 instead
            # of a connection reset, then close the connection.
            self._drain(min(length, MAX_BODY * 2))
            self._json(413, {"error": "bad or oversized body"}, close=True)
            return

        raw = self.rfile.read(length)
        try:
            record = json.loads(raw)
            if not isinstance(record, dict):
                raise ValueError
        except Exception:
            self._json(400, {"error": "invalid json"})
            return

        record["received_utc"] = _now_iso()
        excluded = coldlight_safelist.matches(
            self.server.safelist, record.get("hostname", ""), record.get("username", "")
        )
        with self.server.lock:
            is_new = rr.insert_hit(self.server.conn, record, excluded=excluded)
        self._json(200, {"status": "ok", "new": is_new, "excluded": excluded})


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def serve(host: str, port: int, token: str, db_path: str,
          safelist: list[str] | None = None, retention_days: int | None = None) -> None:
    if not token:
        raise SystemExit("A --token is required (the payload must authenticate).")
    srv = CollectorServer((host, port), token, db_path,
                          safelist=safelist, retention_days=retention_days)
    print(f"ColdLight collector on http://{host}:{port}  (db: {db_path})")
    print(f"  ingest : POST http://{host}:{port}/awareness/hit  (Bearer token)")
    print(f"  dash   : http://{host}:{port}/")
    if safelist:
        print(f"  safelist: {len(safelist)} pattern(s) -> matching hits flagged excluded")
    if retention_days:
        print(f"  retention: auto-purge hits older than {retention_days} day(s)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down.")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="ColdLight awareness-test collector.")
    ap.add_argument("--host", default="127.0.0.1",
                    help="bind address (default 127.0.0.1; only change on trusted infra)")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--token", required=True, help="shared ingest/stats token")
    ap.add_argument("--db", default="hits.db", help="SQLite path (default hits.db)")
    ap.add_argument("--safelist", help="file of opt-out patterns (one per line)")
    ap.add_argument("--retention-days", type=int, default=None,
                    help="auto-purge hits older than N days")
    args = ap.parse_args(argv)
    patterns = coldlight_safelist.load_patterns(args.safelist) if args.safelist else []
    serve(args.host, args.port, args.token, args.db,
          safelist=patterns, retention_days=args.retention_days)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
