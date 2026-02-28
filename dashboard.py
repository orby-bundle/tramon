#!/usr/bin/env python3
"""
Single script to run the agent + a minimal HTTP server so you can view
traffic in the browser without Docker. Opens the dashboard at http://127.0.0.1:8765

Usage: python run_dashboard.py
  (Run as Administrator on Windows, or sudo on Linux/macOS, so the agent can capture.)
"""
import json
import os
import queue
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

PORT = 8787
BASE_URL = "http://127.0.0.1:{}".format(PORT)

# In-memory: (ip, port, protocol) -> {bytes, count, process}
_stats = {}
_stats_lock = threading.Lock()

# Reverse DNS: ip -> hostname (background resolver)
_rdns_cache = {}  # ip -> hostname str
_rdns_cache_time = {}  # ip -> time when cached (for negative TTL)
_rdns_pending = set()  # ip -> True if queued (we allow re-queue after negative TTL)
_rdns_lock = threading.Lock()
_rdns_queue = queue.Queue()  # items: (ip, retry_count)
RDNS_TIMEOUT = 3.0
RDNS_MAX_RETRIES = 2
RDNS_NEGATIVE_TTL = 300.0  # seconds before re-trying a failed (empty) lookup
RDNS_WORKERS = 4

def _get_local_ips():
    ips = set(["127.0.0.1", "::1"])
    try:
        hostname = socket.gethostname()
        _, _, host_ips = socket.gethostbyname_ex(hostname)
        ips.update(host_ips)
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    return ips

_HOST_IPS = _get_local_ips()

# (protocol_upper, port) -> friendly label
_PROTOCOL_LABELS = {
    ("TCP", 443): "HTTPS",
    ("UDP", 137) : "NBNS",
    ("TCP", 137) : "NBNS",
    ("TCP", 80): "HTTP",
    ("TCP", 22): "SSH",
    ("TCP", 21): "FTP",
    ("TCP", 25): "SMTP",
    ("TCP", 587): "SMTP",
    ("TCP", 993): "IMAPS",
    ("TCP", 995): "POP3S",
    ("TCP", 143): "IMAP",
    ("TCP", 110): "POP3",
    ("TCP", 53): "DNS",
    ("TCP", 3389): "RDP",
    ("UDP", 443): "QUIC",
    ("UDP", 80): "HTTP/QUIC",
    ("UDP", 53): "DNS",
    ("UDP", 67): "DHCP",
    ("UDP", 68): "DHCP",
    ("UDP", 123): "NTP",
    ("ICMP", 0): "ICMP",
}

def _protocol_label(protocol, port):
    """Return a friendlier label for (protocol, port), e.g. TCP 443 -> HTTPS."""
    key = (str(protocol or "").upper(), int(port or 0))
    return _PROTOCOL_LABELS.get(key) or protocol or "-"

def _is_localhost(ip):
    return ip in ("127.0.0.1", "::1") or (ip and ip.startswith("127."))

def _ingest_events(events):
    with _stats_lock:
        for ev in events:
            b = int(ev.get("bytes", 0))
            process = ev.get("process") or ""
            pid = int(ev.get("pid") or 0)
            protocol = ev.get("protocol") or ""
            src_ip = ev.get("src_ip")
            dst_ip = ev.get("dst_ip")
            src_port = int(ev.get("src_port") or 0)
            dst_port = int(ev.get("dst_port") or 0)
            
            is_src_local = src_ip in _HOST_IPS
            is_dst_local = dst_ip in _HOST_IPS
            
            if is_src_local and not is_dst_local:
                local_ip = src_ip
                remote_ip = dst_ip
            elif is_dst_local and not is_src_local:
                local_ip = dst_ip
                remote_ip = src_ip
            else:
                local_ip = dst_ip
                remote_ip = src_ip

            # Usually the service port is the lower port, or 443 if present
            if src_port == 443 or dst_port == 443:
                port = 443
            elif src_port and dst_port:
                port = min(src_port, dst_port)
            else:
                port = max(src_port, dst_port)

            if not remote_ip or _is_localhost(remote_ip):
                continue
            key = (local_ip, remote_ip, port, protocol)
            if key not in _stats:
                _stats[key] = {"bytes": 0, "count": 0, "process": process, "pid": pid}
            _stats[key]["bytes"] += b
            _stats[key]["count"] += 1
            if process:
                _stats[key]["process"] = process
            if pid:
                _stats[key]["pid"] = pid

def _resolve_rdns(ip):
    """Reverse DNS with timeout. Returns hostname or ''."""
    result = {"hostname": ""}
    def do():
        try:
            result["hostname"] = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            pass
    t = threading.Thread(target=do, daemon=True)
    t.start()
    t.join(timeout=RDNS_TIMEOUT)
    return result["hostname"]

def _rdns_resolver_worker():
    while True:
        try:
            item = _rdns_queue.get()
            if item is None:
                break
            ip, retry = item if isinstance(item, tuple) else (item, 0)
            hostname = _resolve_rdns(ip)
            with _rdns_lock:
                _rdns_cache[ip] = hostname
                _rdns_cache_time[ip] = time.time()
                if not hostname and retry < RDNS_MAX_RETRIES:
                    _rdns_queue.put((ip, retry + 1))
                else:
                    _rdns_pending.discard(ip)
        except Exception:
            pass

def _get_top(n=500):
    with _stats_lock:
        rows = [
            {
                "local_ip": local_ip,
                "remote_ip": remote_ip,
                "port": port,
                "protocol": protocol,
                "service": _protocol_label(protocol, port),
                "bytes": d["bytes"],
                "count": d["count"],
                "pid": d.get("pid", 0),
                "process": d.get("process", ""),
            }
            for (local_ip, remote_ip, port, protocol), d in _stats.items()
        ]
    rows.sort(key=lambda r: r["bytes"], reverse=True)
    rows = rows[:n]
    # Queue missing IPs for reverse DNS; add hostname to each row (re-queue if negative expired)
    now = time.time()
    for r in rows:
        ip = r["remote_ip"]
        with _rdns_lock:
            cached = _rdns_cache.get(ip)
            cached_time = _rdns_cache_time.get(ip, 0)
            if cached:
                r["hostname"] = cached
            else:
                r["hostname"] = ""
            if ip not in _rdns_pending:
                if cached:
                    pass
                elif not cached and cached_time and (now - cached_time) > RDNS_NEGATIVE_TTL:
                    _rdns_cache.pop(ip, None)
                    _rdns_cache_time.pop(ip, None)
                    _rdns_pending.add(ip)
                    _rdns_queue.put((ip, 0))
                elif not cached and not cached_time:
                    _rdns_pending.add(ip)
                    _rdns_queue.put((ip, 0))
    return rows

START_TIME_STR = datetime.now().strftime("%H:%M %d.%m.%Y")

HTML_PAGE = """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Traffic Dashboard</title>
  <style>
    body { font-family: system-ui, sans-serif; margin: 1rem; background: #1a1a2e; color: #eee; }
    h1 { font-size: 1.25rem; }
    .tabs { margin-bottom: 1rem; display: flex; gap: 0.5rem; flex-wrap: wrap; }
    .tab { background: #16213e; border: 1px solid #333; padding: 0.5rem 1rem; cursor: pointer; border-radius: 4px; color: #a0a0ff; }
    .tab:hover { background: #1f2e5c; }
    .tab.active { background: #7eb8da; color: #1a1a2e; font-weight: bold; }
    table { border-collapse: collapse; width: 100%; max-width: 800px; }
    th, td { text-align: left; padding: 0.5rem 0.75rem; border-bottom: 1px solid #333; }
    th { background: #16213e; color: #a0a0ff; }
    tr:hover { background: #16213e; }
    .bytes { font-variant-numeric: tabular-nums; }
    a { color: #7eb8da; }
  </style>
</head>
<body>
  <h1>Traffic by Local IP <span style="font-size: 1rem; font-weight: normal; color: #a0a0ff; margin-left: 1rem;">Monitoring since """ + START_TIME_STR + """</span></h1>
  <div class="tabs" id="tabs"></div>
  <p>Updates every second. Plain <a href="/api/top">JSON</a></p>
  <table>
    <thead>
      <tr><th>#</th><th>Local IP</th><th>Remote IP</th><th>Reverse DNS</th><th>Port</th><th>Service</th><th>Protocol</th><th>Traffic</th><th>Packets</th><th>PID</th><th>Process</th></tr>
    </thead>
    <tbody id="tbody"></tbody>
  </table>
  <script>
    var selectedLocalIp = null;

    function fmtNum(n) { return n.toLocaleString(); }
    function formatBytes(n) {
      var sp = '\u00A0';
      if (n >= 1e9) return (n / 1e9).toFixed(2) + sp + 'GB';
      if (n >= 1e6) return (n / 1e6).toFixed(2) + sp + 'MB';
      if (n >= 1e3) return (n / 1e3).toFixed(2) + sp + 'KB';
      return n + sp + 'B';
    }
    function esc(s) { return (s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
    
    function renderTabs(localIps) {
      var tabsDiv = document.getElementById('tabs');
      var html = '<div class="tab ' + (selectedLocalIp === null ? 'active' : '') + '" onclick="selectIp(null)">All IPs</div>';
      localIps.forEach(function(ip) {
        var active = selectedLocalIp === ip ? 'active' : '';
        html += '<div class="tab ' + active + '" onclick="selectIp(\\'' + esc(ip) + '\\')">' + esc(ip) + '</div>';
      });
      tabsDiv.innerHTML = html;
    }

    function selectIp(ip) {
      selectedLocalIp = ip;
      poll(); // Force immediate update
    }

    function poll() {
      fetch('/api/top?n=500')
        .then(r => r.json())
        .then(data => {
          var uniqueIps = new Set();
          data.rows.forEach(r => {
            if (r.local_ip && !r.local_ip.startsWith("127.")) {
              uniqueIps.add(r.local_ip);
            }
          });
          var ipsArray = Array.from(uniqueIps).sort();
          renderTabs(ipsArray);

          var filteredRows = data.rows;
          if (selectedLocalIp) {
            filteredRows = filteredRows.filter(r => r.local_ip === selectedLocalIp);
          }

          var tbody = document.getElementById('tbody');
          tbody.innerHTML = filteredRows.map(function(r, i) {
            return '<tr><td>' + (i+1) + '</td><td>' + esc(r.local_ip) + '</td><td>' + esc(r.remote_ip) + '</td><td>' + esc(r.hostname || '-') + '</td><td class="bytes">' + (r.port || '-') + '</td><td>' + esc(r.service || '-') + '</td><td>' + esc(r.protocol || '-') + '</td><td class="bytes">' + formatBytes(r.bytes) + '</td><td class="bytes">' + fmtNum(r.count) + '</td><td class="bytes">' + (typeof r.pid === 'number' && r.pid > 0 ? r.pid : '-') + '</td><td>' + esc(r.process || '-') + '</td></tr>';
          }).join('');
        })
        .catch(function() {});
    }
    poll();
    setInterval(poll, 1000);
  </script>
</body>
</html>
"""

class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_POST(self):
        if self.path != "/ingest":
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            data = json.loads(body)
            events = data.get("events", [])
            _ingest_events(events)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok":true}')
        except Exception as e:
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode())

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)
        if path == "/api/top":
            n = 100
            if "n" in qs:
                try:
                    n = min(500, max(1, int(qs["n"][0])))
                except ValueError:
                    pass
            rows = _get_top(n)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"rows": rows}).encode())
            return
        if path == "/" or path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_PAGE.encode("utf-8"))
            return
        self.send_error(404)


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    agent_py = os.path.join(script_dir, "agent.py")
    if not os.path.isfile(agent_py):
        print("agent.py not found next to run_dashboard.py", file=sys.stderr)
        sys.exit(1)

    for _ in range(RDNS_WORKERS):
        t = threading.Thread(target=_rdns_resolver_worker, daemon=True)
        t.start()

    server = HTTPServer(("127.0.0.1", PORT), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    env = os.environ.copy()
    env["CONTAINER_URL"] = BASE_URL

    proc = subprocess.Popen(
        [sys.executable, agent_py],
        cwd=script_dir,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )

    print("Dashboard is available @ {}".format(BASE_URL))
    print("Agent running (PID {}). Press Ctrl+C to stop.".format(proc.pid))
    webbrowser.open(BASE_URL)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        server.shutdown()
    print("Stopped.")


if __name__ == "__main__":
    main()