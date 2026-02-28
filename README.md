# tramon

This is a lightweight, cross-platform network traffic monitoring utility. 

`tramon` captures live host network traffic, maps it to specific processes and PIDs, and displays it on a minimalistic real-time dashboard in a browser. It runs locally, tracks traffic flows in memory and resolves (if possible) remote IPs to hostnames on the fly. 

## Features

- **Cross-Platform Capture:**
  - **Windows:** Uses ETW (Microsoft-Windows-TCPIP) via `pywintrace`.
  - **Linux / macOS:** Uses `scapy` for packet capture.
- **Process Mapping:** Automatically links connections and bandwidth to the specific application (e.g., Chrome, SSH, Opera).
- **Real-Time Web UI:** An embedded HTTP server displays in decreasing order top 500  traffic flows, auto-refreshing every second.
- **Local IP Filtering:** Easily filter traffic by your host's specific local interfaces.
- **Reverse DNS:** Background workers resolve when possible remote IP addresses to their hostnames to make traffic readable.

## Prerequisites

The utility will be Dockerized in the next update. For now follow the comman line hints.

## Usage

To start both the capture agent and the web dashboard, run:

```bash
# On Windows (Run as Administrator)
python dashboard.py

# On Linux/macOS (Requires root/sudo for packet capture)
sudo python3 dashboard.py
```
Once running, the script will automatically open your default browser to `http://127.0.0.1:8787` to display the traffic dashboard.

## Architecture

- `agent.py`: The host agent responsible for capturing traffic. It detects the operating system and then normalizes accordingly packets or ETW events into a canonical JSON format containing source/destination IPs, ports, bytes, protocol, and process info.
- `dashboard.py`: Spawns the agent as a subprocess and spins up a local HTTP server to receive the agent's batches. It aggregates the stats in-memory and serves the web UI. 

## License

MIT

## Special notice

created by a4 s7 for 104...171 opsmen
