#!/usr/bin/env python3
"""
Simple async TCP port & banner scanner (for lab / authorized use only).
Usage:
    python scanner.py TARGET --start 1 --end 1024 --timeout 1 --workers 500
"""

import argparse
import asyncio
import json
import csv
import ssl
import socket
from datetime import datetime

COMMON_PORTS = {
    20: "FTP-data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-alt",
}


async def service_probe(host: str, port: int, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, timeout: float):
    info = {}
    try:
        if port in (80, 8080):
            host_header = host
            try:
                host_header = host.encode("idna").decode()
            except Exception:
                pass
            req = f"HEAD / HTTP/1.0\r\nHost: {host_header}\r\nConnection: close\r\n\r\n".encode()
            writer.write(req)
            await writer.drain()
            try:
                data = await asyncio.wait_for(reader.read(2048), timeout=0.8)
                if data:
                    text = data.decode(errors="ignore")
                    lines = text.splitlines()
                    if lines:
                        info["http_status"] = lines[0].strip()
                    for line in lines:
                        if line.lower().startswith("server:"):
                            info["server"] = line.split(":", 1)[1].strip()
                            break
            except asyncio.TimeoutError:
                pass
        elif port == 6379:
            writer.write(b"PING\r\n")
            await writer.drain()
            try:
                data = await asyncio.wait_for(reader.read(64), timeout=0.5)
                if data and data.startswith(b"+PONG"):
                    info["redis_ping"] = "PONG"
            except asyncio.TimeoutError:
                pass
    except Exception:
        # Probes are best-effort; ignore errors
        pass
    return info


async def tls_peek(host: str, port: int, timeout: float):
    try:
        ctx = ssl.create_default_context()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=host),
            timeout=timeout,
        )
        ssl_obj = writer.get_extra_info("ssl_object")
        details = {}
        if ssl_obj:
            try:
                cert = ssl_obj.getpeercert()
                if cert:
                    details["tls_subject"] = str(cert.get("subject"))
                    details["tls_issuer"] = str(cert.get("issuer"))
            except Exception:
                pass
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return details
    except Exception:
        return {}


async def probe_port(semaphore: asyncio.Semaphore, host: str, port: int, timeout: float, deep: bool = False):
    hint = COMMON_PORTS.get(port)
    if not hint:
        try:
            hint = socket.getservbyport(port, "tcp")
        except Exception:
            hint = None
    result = {"proto": "tcp", "port": port, "open": False, "banner": None, "hint": hint, "details": {}}
    try:
        async with semaphore:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
            result["open"] = True
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=0.8)
                if data:
                    try:
                        result["banner"] = data.decode(errors="ignore").strip()
                    except Exception:
                        result["banner"] = repr(data[:100])
            except asyncio.TimeoutError:
                result["banner"] = None
            if deep:
                # Best-effort protocol-specific probes
                details = await service_probe(host, port, reader, writer, timeout)
                if details:
                    result["details"].update(details)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            if deep and port in (443, 8443):
                tls_details = await tls_peek(host, port, timeout)
                if tls_details:
                    result["details"].update(tls_details)
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        pass
    except Exception as e:
        result["error"] = str(e)
    return result


async def run_scan(host: str, start: int, end: int, timeout: float, workers: int, deep: bool = False):
    semaphore = asyncio.Semaphore(workers)
    tasks = [probe_port(semaphore, host, p, timeout, deep) for p in range(start, end + 1)]
    results = []
    for future in asyncio.as_completed(tasks):
        res = await future
        results.append(res)
        if res["open"]:
            banner_preview = (
                (res["banner"][:80] + "...")
                if res["banner"] and len(res["banner"]) > 80
                else (res["banner"] or "")
            )
            hint = f" ({res['hint']})" if res.get("hint") else ""
            print(f"[OPEN] {res['port']:5} {hint}  {banner_preview}")
    results.sort(key=lambda x: x["port"])
    return results


def udp_payload_for_port(port: int) -> bytes:
    # Minimal best-effort probes
    if port == 53:  # DNS query for example.com A
        # ID=0x1234, flags=0x0100, QDCOUNT=1, QNAME=example.com, QTYPE=A, QCLASS=IN
        header = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        qname = b"\x07example\x03com\x00"
        qtail = b"\x00\x01\x00\x01"
        return header + qname + qtail
    if port == 123:  # NTP client request
        return bytes([0x1B]) + b"\x00" * 47
    # Generic small payload
    return b"\x00"


async def udp_probe_port(semaphore: asyncio.Semaphore, host: str, port: int, timeout: float):
    hint = COMMON_PORTS.get(port)
    if not hint:
        try:
            hint = socket.getservbyport(port, "udp")
        except Exception:
            hint = None
    result = {"proto": "udp", "port": port, "open": False, "banner": None, "hint": hint, "details": {}}
    loop = asyncio.get_running_loop()
    payload = udp_payload_for_port(port)
    try:
        async with semaphore:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)
            try:
                sock.connect((host, port))
            except Exception:
                sock.close()
                raise
            try:
                await loop.sock_sendall(sock, payload)
                try:
                    data = await asyncio.wait_for(loop.sock_recv(sock, 2048), timeout=timeout)
                    if data:
                        # If we got any response, mark as open/responsive
                        result["open"] = True
                        try:
                            result["banner"] = data.decode(errors="ignore").strip()
                        except Exception:
                            result["banner"] = repr(data[:100])
                except asyncio.TimeoutError:
                    # No response; UDP is ambiguous—leave as closed/non-responsive
                    pass
            finally:
                sock.close()
    except Exception as e:
        result["error"] = str(e)
    return result


async def run_udp_scan(host: str, start: int, end: int, timeout: float, workers: int):
    semaphore = asyncio.Semaphore(workers)
    tasks = [udp_probe_port(semaphore, host, p, timeout) for p in range(start, end + 1)]
    results = []
    for future in asyncio.as_completed(tasks):
        res = await future
        results.append(res)
        if res["open"]:
            banner_preview = (
                (res["banner"][:80] + "...")
                if res["banner"] and len(res["banner"]) > 80
                else (res["banner"] or "")
            )
            hint = f" ({res['hint']})" if res.get("hint") else ""
            print(f"[OPEN] {res['proto']}/{res['port']:5} {hint}  {banner_preview}")
    results.sort(key=lambda x: x["port"])
    return results


def pretty_print(results, host: str, started_at: datetime):
    open_ports = [r for r in results if r["open"]]
    print(f"\nScan summary for {host}")
    print("Started:", started_at.isoformat())
    try:
        rdns = socket.gethostbyaddr(host)[0]
        print("RDNS:", rdns)
    except Exception:
        pass
    print(f"Open ports: {len(open_ports)}")
    print("-" * 60)
    print(f"{'PROTO':<5} {'PORT':>5}  {'SERVICE HINT':<12}  {'BANNER/INFO'}  DETAILS")
    print("-" * 60)
    for r in open_ports:
        hint = r.get("hint") or "-"
        banner = (r.get("banner") or "").replace("\n", " ")[:120]
        details = r.get("details") or {}
        details_text = ", ".join(f"{k}={str(v)[:40]}" for k, v in details.items())
        print(f"{r['proto']:<5} {r['port']:5}  {hint:<12}  {banner}  {details_text}")
    print("-" * 60)


def save_json(results, host: str):
    fname = f"scan_results_{host.replace(':', '_')}.json"
    with open(fname, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print("Saved results to", fname)
    return fname


def save_csv(results, host: str):
    fname = f"scan_results_{host.replace(':', '_')}.csv"
    fieldnames = ["proto", "port", "open", "hint", "banner", "details", "error", "tls_subject", "tls_issuer", "rdns", "fingerprint"]
    with open(fname, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            details = r.get("details") or {}
            writer.writerow({
                "proto": r.get("proto"),
                "port": r.get("port"),
                "open": r.get("open"),
                "hint": r.get("hint"),
                "banner": (r.get("banner") or "").replace("\n", " "),
                "details": json.dumps(details, ensure_ascii=False),
                "error": r.get("error"),
                "tls_subject": details.get("tls_subject"),
                "tls_issuer": details.get("tls_issuer"),
                "rdns": r.get("rdns"),
                "fingerprint": r.get("fingerprint"),
            })
    print("Saved results to", fname)
    return fname


def save_txt(results, host: str, started_at: datetime):
    fname = f"scan_results_{host.replace(':', '_')}.txt"
    open_ports = [r for r in results if r.get("open")]
    lines = []
    lines.append(f"Scan summary for {host}")
    lines.append(f"Started: {started_at.isoformat()}")
    lines.append(f"Open ports: {len(open_ports)}")
    lines.append("-" * 60)
    lines.append(f"{'PROTO':<5} {'PORT':>5}  {'SERVICE HINT':<12}  {'BANNER/INFO'}  DETAILS")
    lines.append("-" * 60)
    for r in open_ports:
        hint = r.get("hint") or "-"
        banner = (r.get("banner") or "").replace("\n", " ")[:120]
        details = r.get("details") or {}
        details_text = ", ".join(f"{k}={str(v)[:40]}" for k, v in details.items())
        lines.append(f"{r['proto']:<5} {r['port']:5}  {hint:<12}  {banner}  {details_text}")
    lines.append("-" * 60)
    with open(fname, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print("Saved results to", fname)
    return fname


def main():
    parser = argparse.ArgumentParser(description="Async Port & Banner Scanner (lab use only)")
    parser.add_argument("target", help="Target hostname or IP")
    parser.add_argument("--start", type=int, default=1)
    parser.add_argument("--end", type=int, default=1024)
    parser.add_argument("--timeout", type=float, default=1.0, help="connect timeout (seconds)")
    parser.add_argument("--workers", type=int, default=500, help="concurrent TCP tasks")
    parser.add_argument("--udp", action="store_true", help="scan UDP ports in the same range")
    parser.add_argument("--udp-timeout", type=float, default=1.0, help="UDP response wait (seconds)")
    parser.add_argument("--udp-workers", type=int, default=300, help="concurrent UDP tasks")
    parser.add_argument("--deep", action="store_true", help="enable protocol-specific probes for richer info")
    args = parser.parse_args()

    started_at = datetime.utcnow()
    print(
        f"Scanning {args.target} ports {args.start}-{args.end} (UTC start {started_at.isoformat()})"
    )
    results = asyncio.run(run_scan(args.target, args.start, args.end, args.timeout, args.workers, args.deep))
    if args.udp:
        # Merge UDP results
        udp_results = asyncio.run(run_udp_scan(args.target, args.start, args.end, args.udp_timeout, args.udp_workers))
        results.extend(udp_results)
        results.sort(key=lambda x: (x.get("proto"), x.get("port")))
    # Add rdns to each result for completeness
    try:
        rdns = socket.gethostbyaddr(args.target)[0]
    except Exception:
        rdns = None
    if rdns:
        for r in results:
            r["rdns"] = rdns
    # Simple fingerprinting
    for r in results:
        fp = None
        banner = (r.get("banner") or "").lower()
        hint = (r.get("hint") or "").lower()
        details = r.get("details") or {}
        if r.get("proto") == "tcp" and r.get("open"):
            if "ssh-" in banner or hint == "ssh":
                fp = "OpenSSH" if "openssh" in banner else "SSH"
            if (hint == "http" or hint == "https" or r.get("port") in (80, 8080, 443)):
                server = (details.get("server") or "").lower()
                if server:
                    fp = server
                elif banner:
                    fp = "http"
            if r.get("port") == 6379 and details.get("redis_ping") == "PONG":
                fp = "Redis"
        if fp:
            r["fingerprint"] = fp
    pretty_print(results, args.target, started_at)
    save_json(results, args.target)
    save_csv(results, args.target)
    save_txt(results, args.target, started_at)


if __name__ == "__main__":
    main()