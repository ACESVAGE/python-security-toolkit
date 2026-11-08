#!/usr/bin/env python3
"""
=============================================================================
host_discovery.py — Script #06 in Python Security Toolkit
Phase 2: Network Scanning
=============================================================================
High-performance network host discovery and alive-host detection tool.
Performs concurrent ICMP ping sweeps, ARP table inspection, and TCP connect
fallback probes against individual targets, IP ranges, or CIDR subnets.

Concepts Covered:
    • Network address range parsing (CIDR subnets, hyphenated ranges, single IPs)
    • ICMP Echo Request sweeps with platform-aware parameterization
    • Local ARP cache inspection for MAC address resolution
    • TCP ping probes (bypassing ICMP-blocking firewalls)
    • High-speed multithreaded scanning via ThreadPoolExecutor
    • Reverse DNS PTR resolution for identified live hosts

Usage:
    python scanning/host_discovery.py 192.168.1.0/24
    python scanning/host_discovery.py 192.168.1.1-192.168.1.50 --threads 60
    python scanning/host_discovery.py 10.0.0.1 --method tcp --ports 80,443,22
    python scanning/host_discovery.py 192.168.1.0/24 --json
=============================================================================
"""

import argparse
import ipaddress
import json
import os
import platform
import re
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

# Ensure UTF-8 output encoding across Windows terminals
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


# ── ANSI Colors ──────────────────────────────────────────────────────────────
class Colors:
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    MAGENTA = "\033[95m"
    RESET = "\033[0m"


# Common ports used for TCP ping fallback probes
DEFAULT_TCP_PORTS = [80, 443, 22, 445, 8080]


def parse_targets(target_str: str) -> List[str]:
    """
    Parse a target string into a list of individual IP address strings.
    Supports:
        • CIDR notation: 192.168.1.0/24
        • Hyphenated range: 192.168.1.1-192.168.1.50 or 192.168.1.1-50
        • Single IP: 192.168.1.1
        • Hostname: example.com
    """
    target_str = target_str.strip()
    ips: List[str] = []

    # 1. CIDR notation (e.g., 192.168.1.0/24)
    if "/" in target_str:
        try:
            network = ipaddress.ip_network(target_str, strict=False)
            # For /31 or /32, include all addresses; otherwise exclude network/broadcast
            if network.num_addresses <= 2:
                ips = [str(ip) for ip in network]
            else:
                ips = [str(ip) for ip in network.hosts()]
            return ips
        except ValueError as err:
            raise ValueError(f"Invalid CIDR network '{target_str}': {err}")

    # 2. Range notation (e.g. 192.168.1.1-192.168.1.50 or 192.168.1.1-50)
    if "-" in target_str:
        parts = target_str.split("-", 1)
        start_str = parts[0].strip()
        end_str = parts[1].strip()

        try:
            start_ip = ipaddress.ip_address(start_str)
            if "." in end_str:
                end_ip = ipaddress.ip_address(end_str)
            else:
                # Shorthand notation like 192.168.1.1-50
                base_parts = start_str.split(".")
                base_parts[-1] = end_str
                end_ip = ipaddress.ip_address(".".join(base_parts))

            if int(start_ip) > int(end_ip):
                raise ValueError("Start IP must be less than or equal to End IP")

            curr = int(start_ip)
            last = int(end_ip)
            while curr <= last:
                ips.append(str(ipaddress.ip_address(curr)))
                curr += 1
            return ips
        except ValueError as err:
            raise ValueError(f"Invalid IP range '{target_str}': {err}")

    # 3. Single IP address
    try:
        ip = ipaddress.ip_address(target_str)
        return [str(ip)]
    except ValueError:
        pass

    # 4. Hostname resolution
    try:
        resolved_ip = socket.gethostbyname(target_str)
        return [resolved_ip]
    except socket.gaierror as err:
        raise ValueError(f"Could not resolve hostname '{target_str}': {err}")


def get_local_arp_table() -> Dict[str, str]:
    """
    Parse the system ARP table to map IP addresses to MAC addresses.
    Returns a dictionary of {ip_address: mac_address}.
    """
    arp_table: Dict[str, str] = {}
    is_win = platform.system().lower() == "windows"
    cmd = ["arp", "-a"]

    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=3)
        output = proc.stdout or ""

        if is_win:
            # Windows format: 192.168.1.1          00-14-22-01-23-45     dynamic
            regex = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})")
            for match in regex.finditer(output):
                ip, mac = match.groups()
                arp_table[ip] = mac.replace("-", ":").lower()
        else:
            # Linux/Unix format: ? (192.168.1.1) at 00:14:22:01:23:45 [ether] on eth0
            regex = re.compile(r"\(?(\d{1,3}(?:\.\d{1,3}){3})\)?\s+at\s+([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})")
            for match in regex.finditer(output):
                ip, mac = match.groups()
                arp_table[ip] = mac.lower()
    except Exception:
        pass

    return arp_table


def ping_host(ip: str, timeout_sec: float) -> Tuple[bool, Optional[float]]:
    """
    Ping a single host using platform-specific ping command.
    Returns (is_alive, latency_ms).
    """
    is_win = platform.system().lower() == "windows"
    timeout_ms = max(1, int(timeout_sec * 1000))

    if is_win:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout_sec))), ip]

    try:
        start_time = time.time()
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=timeout_sec + 1.0,
        )
        elapsed_ms = (time.time() - start_time) * 1000.0

        if proc.returncode == 0:
            output = proc.stdout or ""
            # Extract latency from ping output if possible
            match = re.search(r"time[<=](\d+(?:\.\d+)?)ms", output, re.IGNORECASE)
            if match:
                return True, float(match.group(1))
            return True, round(elapsed_ms, 2)
        return False, None
    except Exception:
        return False, None


def tcp_ping_host(ip: str, ports: List[int], timeout_sec: float) -> Tuple[bool, Optional[int], Optional[float]]:
    """
    Attempt TCP connect probe against common ports.
    Useful when firewalls block ICMP echo requests.
    Returns (is_alive, open_port, latency_ms).
    """
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout_sec)
        start_time = time.time()
        try:
            res = sock.connect_ex((ip, port))
            elapsed_ms = (time.time() - start_time) * 1000.0
            sock.close()
            # 0 indicates open; in some networks 111/10061 (refused) also proves host is alive!
            if res == 0:
                return True, port, round(elapsed_ms, 2)
            # RST packet (connection refused) means host is alive and responded!
            # On Windows WSAECONNREFUSED is 10061, on Linux ECONNREFUSED is 111
            if res in (111, 10061):
                return True, port, round(elapsed_ms, 2)
        except Exception:
            sock.close()
            continue
    return False, None, None


def resolve_hostname(ip: str) -> Optional[str]:
    """Attempt reverse DNS lookup for an IP address."""
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return None


def probe_single_host(
    ip: str,
    method: str,
    timeout_sec: float,
    tcp_ports: List[int],
    arp_table: Dict[str, str],
) -> Optional[Dict[str, Any]]:
    """
    Execute discovery probes on a single target IP based on chosen method.
    Returns host metadata dictionary if alive, otherwise None.
    """
    is_alive = False
    discovery_method = None
    latency: Optional[float] = None
    open_port: Optional[int] = None

    # Check ARP cache first
    mac_addr = arp_table.get(ip)

    # 1. ICMP Ping probe
    if method in ("all", "icmp"):
        alive_icmp, lat_icmp = ping_host(ip, timeout_sec)
        if alive_icmp:
            is_alive = True
            discovery_method = "ICMP"
            latency = lat_icmp

    # 2. TCP Ping fallback
    if not is_alive and method in ("all", "tcp"):
        alive_tcp, port_found, lat_tcp = tcp_ping_host(ip, tcp_ports, timeout_sec)
        if alive_tcp:
            is_alive = True
            discovery_method = f"TCP ({port_found})"
            latency = lat_tcp
            open_port = port_found

    # 3. ARP Match (if host is in local ARP table and method allows)
    if not is_alive and method in ("all", "arp") and mac_addr:
        is_alive = True
        discovery_method = "ARP"
        latency = 0.0

    if not is_alive:
        return None

    hostname = resolve_hostname(ip)

    return {
        "ip": ip,
        "status": "UP",
        "method": discovery_method,
        "latency_ms": latency,
        "mac_address": mac_addr,
        "hostname": hostname,
    }


def scan_network(
    targets: List[str],
    method: str = "all",
    threads: int = 50,
    timeout_sec: float = 1.0,
    tcp_ports: Optional[List[int]] = None,
    verbose: bool = True,
) -> Dict[str, Any]:
    """
    Scan a list of IP targets concurrently using ThreadPoolExecutor.
    """
    if tcp_ports is None:
        tcp_ports = DEFAULT_TCP_PORTS

    arp_table = get_local_arp_table()
    alive_hosts: List[Dict[str, Any]] = []

    start_scan_time = time.time()
    total_targets = len(targets)

    if verbose:
        print(f"  {Colors.DIM}[*] Scanning {total_targets} target host(s) across {threads} thread(s)...{Colors.RESET}")

    with ThreadPoolExecutor(max_workers=min(threads, total_targets or 1)) as executor:
        future_to_ip = {
            executor.submit(probe_single_host, ip, method, timeout_sec, tcp_ports, arp_table): ip
            for ip in targets
        }

        completed_count = 0
        for future in as_completed(future_to_ip):
            completed_count += 1
            res = future.result()
            if res:
                alive_hosts.append(res)
                if verbose:
                    host_info = f" ({res['hostname']})" if res.get("hostname") else ""
                    lat_info = f" — {res['latency_ms']}ms" if res.get("latency_ms") is not None else ""
                    print(f"      {Colors.GREEN}✔ Host UP:{Colors.RESET} {Colors.BOLD}{res['ip']}{Colors.RESET}{host_info} via {res['method']}{lat_info}")

    total_time = round(time.time() - start_scan_time, 2)

    # Sort discovered hosts by IP integer value
    try:
        alive_hosts.sort(key=lambda x: int(ipaddress.ip_address(x["ip"])))
    except Exception:
        alive_hosts.sort(key=lambda x: x["ip"])

    return {
        "targets_total": total_targets,
        "hosts_up": len(alive_hosts),
        "hosts_down": total_targets - len(alive_hosts),
        "scan_duration_seconds": total_time,
        "method": method,
        "hosts": alive_hosts,
    }


def print_banner() -> None:
    banner = f"""{Colors.CYAN}{Colors.BOLD}
╔════════════════════════════════════════════════════════════════════╗
║             🌐  NETWORK HOST DISCOVERY — SCRIPT #06               ║
║               Python Security Toolkit • Phase 2: Scanning          ║
╚════════════════════════════════════════════════════════════════════╝{Colors.RESET}
"""
    print(banner)


def display_results(results: Dict[str, Any]) -> None:
    """Print beautifully formatted alive hosts table."""
    print(f"\n{Colors.BOLD}Total Scanned :{Colors.RESET} {results['targets_total']} hosts")
    print(f"{Colors.BOLD}Hosts Alive   :{Colors.RESET} {Colors.GREEN}{Colors.BOLD}{results['hosts_up']}{Colors.RESET}")
    print(f"{Colors.BOLD}Scan Duration :{Colors.RESET} {results['scan_duration_seconds']}s")
    print(f"{Colors.BOLD}Method Used   :{Colors.RESET} {results['method'].upper()}\n")

    print(f"{Colors.CYAN}{Colors.BOLD}━━━ ACTIVE HOSTS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}")
    if results["hosts"]:
        # Table Header
        print(f"  {Colors.BOLD}{'IP Address':<18} {'Status':<8} {'Latency':<12} {'Method':<12} {'MAC Address':<20} {'Hostname'}{Colors.RESET}")
        print(f"  {Colors.DIM}{'─'*18} {'─'*8} {'─'*12} {'─'*12} {'─'*20} {'─'*20}{Colors.RESET}")

        for h in results["hosts"]:
            lat = f"{h['latency_ms']} ms" if h.get("latency_ms") is not None else "N/A"
            mac = h.get("mac_address") or "N/A"
            name = h.get("hostname") or ""
            print(f"  {Colors.GREEN}{h['ip']:<18}{Colors.RESET} {Colors.GREEN}{h['status']:<8}{Colors.RESET} {lat:<12} {h['method']:<12} {mac:<20} {name}")
    else:
        print(f"  {Colors.YELLOW}[!] No alive hosts detected. Check your network or try '--method tcp'.{Colors.RESET}")

    print(f"\n{Colors.DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Network Host Discovery & Alive Host Detection (Script #06 in Python Security Toolkit)",
        epilog="Examples:\n"
               "  python scanning/host_discovery.py 192.168.1.0/24\n"
               "  python scanning/host_discovery.py 192.168.1.1-192.168.1.50 --threads 50\n"
               "  python scanning/host_discovery.py 10.0.0.1 --method tcp --ports 80,443,22\n"
               "  python scanning/host_discovery.py 127.0.0.1 --json",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", help="Target CIDR (e.g. 192.168.1.0/24), range (192.168.1.1-50), or IP")
    parser.add_argument("-m", "--method", choices=["all", "icmp", "tcp", "arp"], default="all",
                        help="Discovery technique (default: all - ICMP, TCP, ARP)")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of concurrent worker threads (default: 50)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Probe timeout in seconds (default: 1.0)")
    parser.add_argument("-p", "--ports", default="80,443,22,445,8080",
                        help="Comma-separated TCP ports for TCP ping probe (default: 80,443,22,445,8080)")
    parser.add_argument("-j", "--json", action="store_true", help="Output results in structured JSON format")

    args = parser.parse_args()

    # Parse TCP ports
    try:
        tcp_ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
    except ValueError:
        print(f"{Colors.RED}[!] Error: Invalid port specification in '{args.ports}'. Must be comma-separated integers.{Colors.RESET}", file=sys.stderr)
        sys.exit(1)

    # Parse targets
    try:
        targets = parse_targets(args.target)
    except ValueError as err:
        print(f"{Colors.RED}[!] Error: {err}{Colors.RESET}", file=sys.stderr)
        sys.exit(1)

    if not args.json:
        print_banner()
        print(f"{Colors.DIM}[*] Target Input : {args.target}{Colors.RESET}")
        print(f"{Colors.DIM}[*] Total Hosts  : {len(targets)}{Colors.RESET}")
        print(f"{Colors.DIM}[*] Method       : {args.method.upper()}{Colors.RESET}")
        print(f"{Colors.DIM}[*] Threads      : {args.threads}{Colors.RESET}")
        print(f"{Colors.DIM}[*] Timeout      : {args.timeout}s{Colors.RESET}")
        print(f"{Colors.DIM}[*] Initiating host discovery scan...{Colors.RESET}\n")

    results = scan_network(
        targets=targets,
        method=args.method,
        threads=args.threads,
        timeout_sec=args.timeout,
        tcp_ports=tcp_ports,
        verbose=not args.json,
    )

    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
    else:
        display_results(results)


if __name__ == "__main__":
    main()
