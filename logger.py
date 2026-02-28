"""
CSV traffic logger: aggregates events by flow (local_ip, remote_ip, port, protocol)
and appends one row per distinct flow per 1s batch to hourly logs under logs/YYYY.MM/DD/HH.csv.s
"""

import os
import sys
import csv
import socket
from datetime import datetime

# -----------------------------------------------------------------------------
# Config dir
# -----------------------------------------------------------------------------

_LOG_DIR_BASE = os.path.dirname(os.path.abspath(__file__))
DISABLE_CSV_LOG = os.environ.get("DISABLE_CSV_LOG", "").strip().lower() in ("1", "true", "yes")
LOG_DIR = os.environ.get("LOG_DIR", "").strip() or os.path.join(_LOG_DIR_BASE, "logs")

# -----------------------------------------------------------------------------
# Local IPs for flow aggregation (same idea as in dashboard)
# -----------------------------------------------------------------------------


def _get_local_ips():
    """Set of local IPs for flow aggregation (same idea as dashboard)."""
    ips = {"127.0.0.1", "::1"}
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


_HOST_IPS = None


def _ensure_host_ips():
    global _HOST_IPS
    if _HOST_IPS is None:
        _HOST_IPS = _get_local_ips()
    return _HOST_IPS


def _aggregate_batch(events):
    """Aggregate events by (local_ip, remote_ip, port, protocol), same unit as dashboard totals.
    Returns list of dicts: local_ip, remote_ip, port, protocol, bytes, count, process, pid.
    """
    host_ips = _ensure_host_ips()
    agg = {}  # (local_ip, remote_ip, port, protocol) -> {bytes, count, process, pid}
    for ev in events:
        b = int(ev.get("bytes", 0))
        process = ev.get("process") or ""
        pid = int(ev.get("pid") or 0)
        protocol = ev.get("protocol") or ""
        src_ip = ev.get("src_ip")
        dst_ip = ev.get("dst_ip")
        src_port = int(ev.get("src_port") or 0)
        dst_port = int(ev.get("dst_port") or 0)

        is_src_local = src_ip in host_ips
        is_dst_local = dst_ip in host_ips
        if is_src_local and not is_dst_local:
            local_ip, remote_ip = src_ip, dst_ip
        elif is_dst_local and not is_src_local:
            local_ip, remote_ip = dst_ip, src_ip
        else:
            local_ip, remote_ip = dst_ip, src_ip

        if remote_ip in ("127.0.0.1", "::1") or (remote_ip and remote_ip.startswith("127.")):
            continue
        if src_port == 443 or dst_port == 443:
            port = 443
        elif src_port and dst_port:
            port = min(src_port, dst_port)
        else:
            port = max(src_port, dst_port)

        key = (local_ip, remote_ip, port, protocol)
        if key not in agg:
            agg[key] = {"bytes": 0, "count": 0, "process": process, "pid": pid}
        agg[key]["bytes"] += b
        agg[key]["count"] += 1
        if process:
            agg[key]["process"] = process
        if pid:
            agg[key]["pid"] = pid

    return [
        {
            "local_ip": local_ip,
            "remote_ip": remote_ip,
            "port": port,
            "protocol": protocol,
            "bytes": d["bytes"],
            "count": d["count"],
            "process": d["process"],
            "pid": d["pid"],
        }
        for (local_ip, remote_ip, port, protocol), d in agg.items()
    ]


def _log_path_for_hour(dt):
    """Path for hourly CSV: logs/YYYY.MM/DD/HH.csv"""
    y, m, d, h = dt.year, dt.month, dt.day, dt.hour
    return os.path.join(LOG_DIR, f"{y}.{m:02d}", f"{d:02d}", f"{h:02d}.csv")


CSV_HEADER = ("timestamp", "local_ip", "remote_ip", "port", "protocol", "bytes", "count", "process", "pid")


def _append_events_to_csv(events):
    """Append aggregated flow rows (one per distinct flow in the batch) to the current hour's CSV.
    Uses same aggregation as dashboard: (local_ip, remote_ip, port, protocol) with bytes and count.
    """
    if not events:
        return
    rows = _aggregate_batch(events)
    if not rows:
        return
    path = _log_path_for_hour(datetime.now())
    os.makedirs(os.path.dirname(path), exist_ok=True)
    batch_ts = datetime.now().isoformat()
    write_header = not os.path.isfile(path)
    try:
        with open(path, "a", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            if write_header:
                w.writerow(CSV_HEADER)
            for r in rows:
                w.writerow(
                    [
                        batch_ts,
                        r["local_ip"],
                        r["remote_ip"],
                        r["port"],
                        r["protocol"],
                        r["bytes"],
                        r["count"],
                        r["process"],
                        r["pid"],
                    ]
                )
            f.flush()
    except Exception as e:
        print(f"[agent] CSV log write failed: {e}", file=sys.stderr)


def append_events_to_csv(events):
    """Public API: append aggregated flow rows to the hourly CSV. No-op if DISABLE_CSV_LOG is set."""
    if DISABLE_CSV_LOG:
        return
    _append_events_to_csv(events)
