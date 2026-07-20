"""
Port Scanner
------------
A multithreaded TCP port scanner. Scans a target host across a port range
or a list of common ports and reports which are open.

For safety and legality, only scan hosts you own or have explicit
permission to scan (localhost, your own lab VMs, or systems you've been
authorized to test). Scanning systems without permission is illegal in
most jurisdictions.

Usage:
    python port_scanner.py <host> --ports 1-1024
    python port_scanner.py 127.0.0.1 --common
"""

import argparse
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Alt",
}


def scan_port(host, port, timeout=0.5):
    """Attempt a TCP connection to a single port. Returns (port, is_open)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        return port, result == 0


def scan(host, ports, max_workers=100):
    open_ports = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, host, p): p for p in ports}
        for future in as_completed(futures):
            port, is_open = future.result()
            if is_open:
                service = COMMON_PORTS.get(port, "unknown")
                open_ports.append((port, service))
    return sorted(open_ports)


def parse_port_range(range_str):
    start, end = range_str.split("-")
    return range(int(start), int(end) + 1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple TCP port scanner")
    parser.add_argument("host", help="Target host (e.g. 127.0.0.1)")
    parser.add_argument("--ports", help="Port range, e.g. 1-1024")
    parser.add_argument("--common", action="store_true", help="Scan common ports only")
    args = parser.parse_args()

    if args.common:
        ports = list(COMMON_PORTS.keys())
    elif args.ports:
        ports = list(parse_port_range(args.ports))
    else:
        ports = list(parse_port_range("1-1024"))

    print(f"Scanning {args.host} ({len(ports)} ports)...")
    results = scan(args.host, ports)

    print("=" * 50)
    print(f"PORT SCAN RESULTS: {args.host}")
    print("=" * 50)
    if results:
        for port, service in results:
            print(f"Port {port:<6} OPEN   ({service})")
    else:
        print("No open ports found in scanned range.")
    print("=" * 50)
    print(f"Total open: {len(results)} / {len(ports)} scanned")
