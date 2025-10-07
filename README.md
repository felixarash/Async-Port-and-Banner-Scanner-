# Async Port & Banner Scanner — Case Study & Guide

## Overview (Simple Words)
This app checks a target computer (IP or hostname) to see which network doors (ports) are open. For open ports, it tries to read a short message (banner) and guesses what service is running (like HTTP, SSH, Redis). It prints a clean table and saves results to files you can review later (JSON/CSV/TXT).

## Why This Is Useful
- Troubleshoot: Quickly see what services are exposed on a machine.
- Security hygiene: Verify only intended ports are open on servers or lab machines.
- Inventory: Keep lightweight records of open ports and hints for service types.
- Education/Labs: Learn how TCP/UDP ports and basic banners work using a safe tool.

Only scan hosts you own or have explicit permission to test.

## How It Works
- Uses Python `asyncio` to run many small network checks in parallel for speed.
- TCP: Tries to connect to each port; if it connects, it’s considered open. Reads the first bytes (banner) if available.
- UDP (optional): Sends a small probe and marks a port open only if a reply is received.
- Deep probes (optional): For common services (HTTP/HTTPS/Redis), sends minimal protocol messages to extract more info, like HTTP status, `Server` header, Redis `PONG`, or TLS certificate issuer/subject.
- Maps common port numbers to likely services (e.g., 22 → SSH) and also uses `socket.getservbyport` as a fallback.
- Saves outputs to `scan_results_<target>.json/.csv/.txt`.

## Features
- Fast concurrent TCP connect scanning with configurable range and workers.
- Opportunistic banner grabbing.
- Service hints from common ports and OS service mappings.
- Optional deep probes: HTTP HEAD, TLS peek, Redis PING.
- Optional UDP probes for DNS/NTP/generic ports.
- Pretty CLI table + JSON, CSV, and TXT export.

## Ethical Use & Limitations
- Only scan systems you control or have written permission to test.
- Some services don’t send banners until full protocol negotiation; TLS hides plaintext banners.
- UDP is ambiguous: no reply doesn’t prove closed.
- Firewalls/IDS may block or throttle scans.

## Case Study Example
Goal: Audit a lab web server and a cache service on `192.168.1.50`.

Commands:
```bash
python scanner.py 192.168.1.50 --start 1 --end 1024 --timeout 1 --workers 500 --deep
python scanner.py 192.168.1.50 --start 1 --end 1024 --udp --udp-timeout 1
```

What you might see:
```
[OPEN]    22 (SSH)  SSH-2.0-OpenSSH_8.4
[OPEN]    80 (HTTP)  Server: nginx/1.23.1
[OPEN]   443 (HTTPS)  (TLS certificate subject/issuer recorded)
[OPEN]  6379 (Redis)  redis_ping=PONG

Scan summary for 192.168.1.50
PROTO  PORT  SERVICE HINT  BANNER/INFO  DETAILS
tcp       22  SSH            SSH-2.0-OpenSSH_8.4  fingerprint=OpenSSH
tcp       80  HTTP           (headers)            http_status=HTTP/1.1 200 OK, server=nginx/1.23.1
tcp      443  HTTPS          (tls)                tls_subject=..., tls_issuer=...
tcp     6379  Redis                               redis_ping=PONG
```

JSON/CSV/TXT files will contain the same findings plus structured fields.

## How to Run
Prerequisites:
- Python 3.10+
- Windows/macOS/Linux (no extra dependencies required)

Basic usage:
```bash
python scanner.py TARGET --start 1 --end 1024 --timeout 1 --workers 500
```

Examples:
```bash
# Quick local check
python scanner.py 127.0.0.1 --start 1 --end 1024 --timeout 0.8 --workers 300

# Single port
python scanner.py 192.168.1.10 --start 22 --end 22

# Deep probes for common services
python scanner.py example.com --start 1 --end 1024 --deep

# Include UDP probes (same range)
python scanner.py example.com --start 1 --end 1024 --udp --udp-timeout 1 --udp-workers 300
```

Outputs:
- `scan_results_<target>.json` — structured results, including banners, details, fingerprint, rdns.
- `scan_results_<target>.csv` — row-per-port with proto, hint, details, fingerprint.
- `scan_results_<target>.txt` — human-readable summary table.

## Role of This App
This tool acts as a lightweight, permission-based recon utility for administrators, developers, and learners to quickly understand service exposure and basic metadata without heavyweight dependencies.

## How This App Was Made (by Fozan Ahmed)
- Built in Python using `asyncio` for high concurrency with low overhead.
- Uses only the standard library: `asyncio.open_connection`, `socket`, `ssl`, `argparse`, `json`, `csv`.
- Design focuses on clarity, safety, and portability—no external dependencies.
- Deep probes are intentionally minimal to avoid heavy or intrusive behavior.

## Design Notes
- Concurrency is controlled by semaphores; adjust `--workers` for system limits.
- Timeouts balance speed vs. reliability; increase `--timeout` for high latency.
- Fingerprinting is heuristic and works best when services expose banners or headers.

## Roadmap
- Optional web dashboard (Flask/FastAPI) with background scans and charts.
- More protocol probes and improved fingerprints.
- Configurable output destinations and formats.

## Safety Reminder
Scanning can trigger alerts. Use responsibly and only where permitted.