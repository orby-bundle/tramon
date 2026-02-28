"""
Host agent: captures live traffic on Windows (ETW) or Linux/macOS (Scapy),
normalizes to a single schema and batches.

  Windows: run scripts/run.ps1
  Linux/macOS: run scripts/run.sh
"""

import os
import platform
import sys
import json
import time
import threading
import subprocess
import logger

# -----------------------------------------------------------------------------
# Config (env)
# -----------------------------------------------------------------------------

CONTAINER_URL = os.environ.get("CONTAINER_URL", "").rstrip("/")
BATCH_INTERVAL = float(os.environ.get("BATCH_INTERVAL", "1"))
INTERFACE = os.environ.get("INTERFACE", "any")

# -----------------------------------------------------------------------------
# OS detection
# -----------------------------------------------------------------------------

def get_os_type():

    return os.environ.get("OS_OVERRIDE") or platform.system()

def select_capturer():
    os_type = get_os_type()
    if os_type == "Windows":
        return "windows"
    if os_type in ("Linux", "Darwin"):
        return "unix"
    sys.exit(f"Unsupported OS: {os_type!r}")

# -----------------------------------------------------------------------------
# Canonical event shape (same for Windows ETW and Unix Scapy)
# -----------------------------------------------------------------------------

def to_canonical(src_ip, dst_ip, protocol, bytes_, src_port=0, dst_port=0, pid=0, process_name=""):
    return {
        "src_ip": str(src_ip),
        "dst_ip": str(dst_ip),
        "protocol": str(protocol),
        "bytes": int(bytes_),
        "src_port": int(src_port),
        "dst_port": int(dst_port),
        "pid": int(pid),
        "process": str(process_name or "N/A"),
    }

# -----------------------------------------------------------------------------
# PID -> process name (cached, per-OS)
# -----------------------------------------------------------------------------

_pid_to_name_cache = {}
_pid_to_name_lock = threading.Lock()


def _process_name_for_pid(pid):

    if not pid:
        return ""

    with _pid_to_name_lock:
        if pid in _pid_to_name_cache:
            return _pid_to_name_cache[pid]

    name = ""
    os_type = get_os_type()
    if os_type == "Linux":
        comm = "/proc/{}/comm".format(pid)
        if os.path.isfile(comm):
            try:
                with open(comm) as f:
                    name = f.read().strip()
            except (OSError, IOError):
                pass

    elif os_type == "Darwin":
        try:
            # First, check if there's an actual app bundle name for this process
            try:
                import psutil
                proc = psutil.Process(pid)
                exe_path = proc.exe()
                if exe_path and ".app/" in exe_path:
                    # Extract the app name, e.g., /Applications/Opera.app/Contents/... -> Opera
                    app_part = exe_path.split(".app/")[0]
                    name = os.path.basename(app_part)
                else:
                    name = proc.name()

            except ImportError:
                # Fallback to ps if psutil is not installed
                out = subprocess.run(
                    ["ps", "-p", str(pid), "-c", "-o", "command="],
                    capture_output=True,
                    timeout=1,
                    text=True,
                )

                if out.returncode == 0 and out.stdout:
                    # Get just the executable name, not the full path
                    name = os.path.basename(out.stdout.strip())                 
                    # Heuristic to clean up helper processes if we don't have psutil
                    if " Helper" in name:
                        name = name.split(" Helper")[0]
        except (subprocess.TimeoutExpired, FileNotFoundError, ValueError, Exception):
            pass

    elif os_type == "Windows":
        try:
            out = subprocess.run(
                ["tasklist", "/FI", "PID eq {}".format(pid), "/FO", "CSV", "/NH"],
                capture_output=True,
                timeout=1,
                text=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0,
            )

            if out.returncode == 0 and out.stdout.strip():
                line = out.stdout.strip().splitlines()[-1]
                if line.startswith('"') and '"' in line[1:]:
                    end = line.index('"', 1)
                    name = line[1:end].strip()
        except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
            pass

    with _pid_to_name_lock:
        _pid_to_name_cache[pid] = name
    return name

# -----------------------------------------------------------------------------
# Shared state: capture thread -> batching thread
# -----------------------------------------------------------------------------

_batch_lock = threading.Lock()
_pending_events = []


def _add_event(ev):
    if ev is None:
        return

    with _batch_lock:
        _pending_events.append(ev)

def _take_batch():
    with _batch_lock:
        batch = _pending_events.copy()
        _pending_events.clear()

    return batch

# -----------------------------------------------------------------------------
# Output
# -----------------------------------------------------------------------------

def on_batch(batch):
    if not batch:
        return
    logger.append_events_to_csv(batch)
    if CONTAINER_URL:
        try:
            import urllib.request
            req = urllib.request.Request(
                f"{CONTAINER_URL}/ingest",
                data=json.dumps({"events": batch}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",

            )
            urllib.request.urlopen(req, timeout=5)

        except Exception as e:
            print(f"[agent] POST failed: {e}", file=sys.stderr)
    else:
        print(json.dumps(batch, indent=2))

# -----------------------------------------------------------------------------
# Batching thread
# -----------------------------------------------------------------------------

def _batching_loop():
    while True:
        time.sleep(BATCH_INTERVAL)
        batch = _take_batch()
        if batch:
            on_batch(batch)

# -----------------------------------------------------------------------------
# Unix: Scapy (Linux / macOS). Linux: PID from /proc/net + /proc/*/fd
# -----------------------------------------------------------------------------

PROTO_NAMES = {6: "TCP", 17: "UDP", 1: "ICMP"}

# Linux PID lookup cache: (local_ip, local_port, rem_ip, rem_port) -> inode, inode -> pid

_proc_conn_cache = {}
_inode_to_pid_cache = {}
_proc_cache_lock = threading.Lock()
_proc_cache_time = 0.0
PID_CACHE_TTL = 1.0

def _hex_addr_port_to_ip_port(addr_port_hex):
    """Parse 'AABBCCDD:PPPP' from /proc/net (IPv4 LE hex) to (ip_str, port_int)."""

    try:
        addr_hex, port_hex = addr_port_hex.strip().split(":")
        if len(addr_hex) != 8:
            return None, 0

        # 4 bytes LE: AABBCCDD -> DD CC BB AA -> 0xDD, 0xCC, 0xBB, 0xAA

        b = [int(addr_hex[i : i + 2], 16) for i in range(0, 8, 2)]
        ip_str = ".".join(str(x) for x in reversed(b))
        port = int(port_hex, 16)
        return ip_str, port

    except Exception:
        return None, 0

def _parse_proc_net(path):
    """Parse /proc/net/tcp or udp; yield (local_ip, local_port, rem_ip, rem_port, inode)."""
    if not os.path.isfile(path):
        return
    try:
        with open(path) as f:
            next(f)
            for line in f:
                parts = line.split()
                if len(parts) < 12:
                    continue

                local_addr, local_port = _hex_addr_port_to_ip_port(parts[1])
                rem_addr, rem_port = _hex_addr_port_to_ip_port(parts[2])
                if local_addr is None or rem_addr is None:
                    continue

                inode = parts[9]
                if inode == "0":
                    continue

                try:
                    inode_int = int(inode)
                except ValueError:

                    continue
                yield (local_addr, local_port, rem_addr, rem_port, inode_int)

    except (OSError, IOError):
        return

def _build_inode_to_pid():
    """Scan /proc/*/fd for socket:[inode] -> pid."""
    result = {}
    proc = "/proc"
    if not os.path.isdir(proc):
        return result

    try:
        for pid_str in os.listdir(proc):
            if not pid_str.isdigit():
                continue

            pid = int(pid_str)
            fd_dir = os.path.join(proc, pid_str, "fd")
            if not os.path.isdir(fd_dir):
                continue

            try:
                for fd in os.listdir(fd_dir):
                    link = os.path.join(fd_dir, fd)
                    try:
                        target = os.readlink(link)
                    except (OSError, IOError):
                        continue

                    if target.startswith("socket:[") and target.endswith("]"):
                        inode = target[8:-1]

                        try:
                            result[int(inode)] = pid

                        except ValueError:
                            pass

            except (OSError, IOError):
                continue

    except (OSError, IOError):
        pass

    return result

def _refresh_proc_caches():
    """Update connection->inode and inode->pid caches (Linux only, under lock)."""
    global _proc_conn_cache, _inode_to_pid_cache, _proc_cache_time
    now = time.time()
    if now - _proc_cache_time < PID_CACHE_TTL:
        return

    with _proc_cache_lock:
        if now - _proc_cache_time < PID_CACHE_TTL:
            return

        conn = {}
        for local_ip, local_port, rem_ip, rem_port, inode in _parse_proc_net("/proc/net/tcp"):
            key = (local_ip, local_port, rem_ip, rem_port)
            conn[key] = inode

        for local_ip, local_port, rem_ip, rem_port, inode in _parse_proc_net("/proc/net/udp"):
            key = (local_ip, local_port, rem_ip, rem_port)
            conn[key] = inode

        _proc_conn_cache = conn
        _inode_to_pid_cache = _build_inode_to_pid()
        _proc_cache_time = now


def _pid_for_connection_linux(src_ip, src_port, dst_ip, dst_port):
    """Resolve PID for (src_ip, src_port, dst_ip, dst_port) on Linux. Returns 0 if not found."""
    if get_os_type() != "Linux":
        return 0
    _refresh_proc_caches()

    with _proc_cache_lock:
        key1 = (str(src_ip), int(src_port), str(dst_ip), int(dst_port))
        key2 = (str(dst_ip), int(dst_port), str(src_ip), int(src_port))
        inode = _proc_conn_cache.get(key1) or _proc_conn_cache.get(key2)

        if inode is None:
            return 0

        return _inode_to_pid_cache.get(inode, 0)


# Global dictionary to hold local process mappings on macOS
# Used as a fallback fast-path

mac_process_map = {}
mac_process_map_time = 0
mac_process_map_lock = threading.Lock()
MAC_MAP_TTL = 1.0

def _refresh_mac_process_map():
    """Build a map of all local connections using a single lsof call."""
    global mac_process_map, mac_process_map_time
    now = time.time() 

    with mac_process_map_lock:
        if now - mac_process_map_time < MAC_MAP_TTL:
            return mac_process_map

            

        try:
            # Get all internet connections quickly
            # Format: Chrome 123 user 45u IPv4 0x... 0t0 TCP 192.168.1.10:12345->8.8.8.8:443 (ESTABLISHED)
            # or *:53
            cmd = ["lsof", "-i", "-n", "-P"]
            out = subprocess.run(cmd, capture_output=True, timeout=1, text=True)
       
            new_map = {}
            if out.returncode == 0 and out.stdout:
                lines = out.stdout.strip().split('\n')[1:] # Skip header
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 9:
                        proc_name = parts[0]
                        pid = parts[1]
                        conn = parts[8] # e.g. 192.168.1.10:54321->8.8.8.8:443                       

                        if pid.isdigit():
                            pid_int = int(pid)
                            # Parse out the ports
                            if "->" in conn:
                                local_part, remote_part = conn.split("->")
                                if ":" in local_part:
                                    local_port = local_part.split(":")[-1]
                                    if local_port.isdigit():
                                        new_map[int(local_port)] = pid_int
                                if ":" in remote_part:
                                    remote_port = remote_part.split(":")[-1]
                                    if remote_port.isdigit():
                                        new_map[int(remote_port)] = pid_int
                            elif ":" in conn:
                                port = conn.split(":")[-1]
                                if port.isdigit():
                                    new_map[int(port)] = pid_int

            mac_process_map = new_map
            mac_process_map_time = now
            return new_map

        except Exception:
            return mac_process_map


def _pid_for_connection_darwin(src_ip, src_port, dst_ip, dst_port, protocol_str):

    """Resolve PID for a specific connection on macOS."""
    if get_os_type() != "Darwin":
        return 0      

    proc_map = _refresh_mac_process_map()

    
    # Check if either the source or destination port is in our map

    if src_port in proc_map:
        return proc_map[src_port]
    if dst_port in proc_map:
        return proc_map[dst_port]      
    return 0


def _normalize_packet(pkt):
    try:
        if not pkt.haslayer("IP"):
            return None
        ip = pkt["IP"]
        proto_num = ip.proto
        proto = PROTO_NAMES.get(proto_num, f"PROTO_{proto_num}")
        src_port = dst_port = 0
        if pkt.haslayer("TCP"):
            src_port = pkt["TCP"].sport
            dst_port = pkt["TCP"].dport
        elif pkt.haslayer("UDP"):
            src_port = pkt["UDP"].sport
            dst_port = pkt["UDP"].dport
        pid = 0
        if src_port and dst_port:

            if get_os_type() == "Linux":
                pid = _pid_for_connection_linux(ip.src, src_port, ip.dst, dst_port)
            elif get_os_type() == "Darwin":
                # For macOS, try to get the PID using lsof helper. Only if it's a local IP

                if ip.src.startswith("192.168.") or ip.src.startswith("10.") or ip.src.startswith("172.") or ip.src == "127.0.0.1":
                    pid = _pid_for_connection_darwin(ip.src, src_port, ip.dst, dst_port, proto)
                elif ip.dst.startswith("192.168.") or ip.dst.startswith("10.") or ip.dst.startswith("172.") or ip.dst == "127.0.0.1":
                    pid = _pid_for_connection_darwin(ip.dst, dst_port, ip.src, src_port, proto)
      

        process_name = _process_name_for_pid(pid) if pid else ""
        return to_canonical(ip.src, ip.dst, proto, len(pkt), src_port, dst_port, pid=pid, process_name=process_name)

    except Exception:

        return None

def _run_capture_unix():
    if os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() != 0:
        print(
            "[agent] Packet capture requires root. Run with sudo:\n  sudo python3 agent.py\n  or: ./scripts/run_agent.sh",
            file=sys.stderr,
        )
        sys.exit(1)
    try:

        from scapy.all import sniff

    except ImportError as e:

        print("Unix capture requires scapy: pip install scapy", file=sys.stderr)
        print("Import error:", e, file=sys.stderr)

        sys.exit(1)

    iface = None if INTERFACE == "any" else INTERFACE
    threading.Thread(target=_batching_loop, daemon=True).start()
    sniff(iface=iface, prn=lambda p: _add_event(_normalize_packet(p)), store=False)

# -----------------------------------------------------------------------------
# Windows: ETW (Microsoft-Windows-TCPIP via NT Kernel Logger)
# Uses pywintrace; only imported on Windows
# -----------------------------------------------------------------------------

def _run_capture_windows():
    try:
        import etw
        from etw import evntrace as evnt

    except ImportError:
        try:
            from pywintrace import etw
            from pywintrace.etw import evntrace as evnt

        except ImportError as e:
            print("Windows capture requires pywintrace: pip install pywintrace", file=sys.stderr)
            print("Import error:", e, file=sys.stderr)
            sys.exit(1)

    SYSTEM_TRACE_CONTROL_GUID = etw.GUID("{9E814AAD-3204-11D2-9A82-006008A86939}")

    providers = [

        etw.ProviderInfo(
            evnt.KERNEL_LOGGER_NAME,
            SYSTEM_TRACE_CONTROL_GUID,
            any_keywords=evnt.EVENT_TRACE_FLAG_NETWORK_TCPIP,

        )

    ]

    def _get_port(obj, *keys):
        for k in keys:
            v = obj.get(k)
            if v is not None:
                try:
                    return int(v)

                except (TypeError, ValueError):
                    pass
        return 0



    _PROTO_BY_NUM = {6: "TCP", 17: "UDP", 1: "ICMP"}

    def _protocol_from_event(out, event_id):
        """Derive protocol (TCP/UDP) from ETW event. NT Kernel TCPIP may not expose UDP."""
        proto = out.get("protocol") or out.get("Protocol") or out.get("protocolId")
        if proto is not None:
            try:
                n = int(proto)
                return _PROTO_BY_NUM.get(n) or "TCP"
            except (TypeError, ValueError):
                if isinstance(proto, str) and proto.upper() in ("TCP", "UDP", "ICMP"):
                    return proto.upper()
        task = (out.get("Task Name") or out.get("Description") or "").upper()

        if "UDP" in task:
            return "UDP"

        if "TCP" in task:
            return "TCP"

        return "TCP"

    def _on_etw_event(args):
        event_id, out = args
        try:
            saddr = out.get("saddr") or out.get("Saddr")
            daddr = out.get("daddr") or out.get("Daddr")
            size = (
                out.get("size")
                or out.get("Size")
                or out.get("length")
                or out.get("DataLength")
                or out.get("datalen")
                or 0

            )

            sport = _get_port(out, "sport", "Sport")
            dport = _get_port(out, "dport", "Dport")
            protocol = _protocol_from_event(out, event_id)
            pid = out.get("PID") or out.get("ProcessId")

            if pid is None and "EventHeader" in out:

                pid = out["EventHeader"].get("ProcessId", 0)

            if pid is None:

                pid = 0

            else:

                try:

                    pid = int(pid)

                except (TypeError, ValueError):

                    pid = 0

            if saddr is not None and daddr is not None and size is not None:

                try:

                    n = int(size)

                except (TypeError, ValueError):

                    n = 0

                if n > 0:

                    process_name = _process_name_for_pid(pid) if pid else ""
                    ev = to_canonical(saddr, daddr, protocol, n, sport, dport, pid=pid, process_name=process_name)
                    _add_event(ev)

        except Exception:

            pass



    threading.Thread(target=_batching_loop, daemon=True).start()

    try:

        with etw.ETW(

            session_name=evnt.KERNEL_LOGGER_NAME,

            providers=providers,

            event_callback=_on_etw_event,

            ignore_exists_error=True,

        ):

            etw.run("agent_etw")

    except PermissionError:

        print(

            "[agent] ETW capture requires Administrator. Run as Administrator:\n"

            "  Right-click PowerShell -> Run as administrator, then: python agent.py\n"

            "  or: .\\scripts\\run_agent_admin.ps1",

            file=sys.stderr,

        )

        sys.exit(1)

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

def main():
    capturer = select_capturer()
    print(

        f"[agent] OS={get_os_type()}, capturer={capturer}, interval={BATCH_INTERVAL}s",

        file=sys.stderr,

    )

    if not CONTAINER_URL:
        print("[agent] No CONTAINER_URL set; only printing batches.", file=sys.stderr)
    if capturer == "unix":
        _run_capture_unix()
    else:
        _run_capture_windows()


if __name__ == "__main__":

    main()
