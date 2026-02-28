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

The utility automatically sets up its own Python virtual environment and installs required dependencies (`scapy`, `psutil`, Windows only `pywintrace`).

## Usage
To start the utility, use the *.sh script for Linux/macOS and *.ps1 script for Windows. 

They will automatically request the necessary privileges (Admin/root for packet capture), create an isolated Python virtual environment, install dependencies, and launch the application.

**On Windows:**
Run the PowerShell script. It will prompt for Administrator privileges automatically if needed:
```powershell
.\run.ps1
```

**On Linux / macOS:**
Run the shell script. It will prompt for your `sudo` password:
```bash
./run.sh
```
Once running, the script will automatically open your default browser to `http://127.0.0.1:8787` to display the traffic dashboard.

## Architecture

- `agent.py`: The host agent responsible for capturing traffic. It detects the operating system and then normalizes accordingly packets or ETW events into a canonical JSON format containing source/destination IPs, ports, bytes, protocol, and process info.
- `dashboard.py`: Spawns the agent as a subprocess and spins up a local HTTP server to receive the agent's batches. It aggregates the stats in-memory and serves the web UI.
- `logger.py`: Writes aggregated traffic flows to hourly CSV logs under `logs/YYYY.MM/DD/HH.csv`; controlled by `DISABLE_CSV_LOG` and `LOG_DIR` environment variables.

## License

MIT

## Special notice

created by a4 s7 for 104...171 opsmen
