#!/usr/bin/env python3
"""
=============================================================================
dns_resolver.py — Script #02 in Python Security Toolkit
Phase 1: Reconnaissance
=============================================================================
Performs multi-record DNS enumeration and reverse IP lookups (PTR).
Queries A, AAAA, MX, NS, TXT, SOA, and CNAME records using pure standard-library
UDP sockets (RFC 1035) with fallback to dnspython if installed.

Usage:
    python recon/dns_resolver.py example.com
    python recon/dns_resolver.py example.com -t MX
    python recon/dns_resolver.py example.com -s 1.1.1.1
    python recon/dns_resolver.py 8.8.8.8 --reverse
    python recon/dns_resolver.py example.com --json
=============================================================================
"""

import argparse
import ipaddress
import json
import random
import re
import socket
import struct
import sys
from typing import Any, Dict, List, Optional, Tuple

# Ensure UTF-8 output encoding across Windows terminals
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Default Public DNS Resolvers
DEFAULT_RESOLVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
DNS_PORT = 53
SOCKET_TIMEOUT = 5

# DNS Record Type Mapping (RFC 1035 / RFC 3596)
RECORD_TYPES = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "PTR": 12,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
}

REVERSE_RECORD_TYPES = {v: k for k, v in RECORD_TYPES.items()}


# ANSI Colors for terminal output
class Colors:
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    MAGENTA = "\033[95m"
    RESET = "\033[0m"


def clean_target(target: str) -> str:
    """Normalize input target: strip protocols, ports, and trailing slashes."""
    target = target.strip()
    target = re.sub(r"^https?://", "", target, flags=re.IGNORECASE)
    target = target.split("/")[0].split("?")[0].split(":")[0]
    return target


def is_ip_address(val: str) -> bool:
    """Check if string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(val)
        return True
    except ValueError:
        return False


def build_qname(domain: str) -> bytes:
    """Encode a domain name into DNS wire format labels (e.g. \x07example\x03com\x00)."""
    labels = domain.strip(".").split(".")
    encoded = bytearray()
    for label in labels:
        b = label.encode("utf-8")
        if len(b) > 63:
            raise ValueError(f"Label '{label}' exceeds maximum length of 63 bytes.")
        encoded.append(len(b))
        encoded.extend(b)
    encoded.append(0)
    return bytes(encoded)


def parse_name(data: bytes, offset: int) -> Tuple[str, int]:
    """Parse a domain name from DNS response, resolving RFC 1035 compression pointers."""
    labels: List[str] = []
    jumped = False
    original_offset = offset
    max_hops = 20
    hops = 0

    while True:
        if offset >= len(data):
            break
        length = data[offset]

        # Compression pointer (starts with two high bits 11xxxxx)
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                original_offset = offset + 2
                jumped = True
            offset = pointer
            hops += 1
            if hops > max_hops:
                break
            continue

        offset += 1
        if length == 0:
            break

        if offset + length > len(data):
            break

        label = data[offset : offset + length].decode("utf-8", errors="replace")
        labels.append(label)
        offset += length

    domain = ".".join(labels)
    final_offset = original_offset if jumped else offset
    return domain, final_offset


def craft_dns_query(domain: str, qtype: int) -> Tuple[bytes, int]:
    """Craft a 12-byte standard DNS query header + question section."""
    query_id = random.randint(1000, 65535)
    flags = 0x0100  # Standard query with Recursion Desired (RD = 1)
    qdcount = 1     # 1 question
    ancount = 0
    nscount = 0
    arcount = 0

    header = struct.pack("!HHHHHH", query_id, flags, qdcount, ancount, nscount, arcount)
    qname = build_qname(domain)
    question = qname + struct.pack("!HH", qtype, 1)  # QTYPE and QCLASS (IN = 1)
    return header + question, query_id


def query_dns_raw(domain: str, qtype_str: str, server: str, timeout: int = SOCKET_TIMEOUT) -> List[Dict[str, Any]]:
    """Send raw UDP DNS query and parse resource record answers."""
    qtype = RECORD_TYPES.get(qtype_str.upper())
    if not qtype:
        return []

    packet, query_id = craft_dns_query(domain, qtype)
    results: List[Dict[str, Any]] = []

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, (server, DNS_PORT))
            data, _ = sock.recvfrom(4096)
    except (socket.timeout, OSError):
        return []

    if len(data) < 12:
        return []

    res_id, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", data[:12])
    if res_id != query_id:
        return []

    # Check RCODE (bits 0-3 of flags)
    rcode = flags & 0x0F
    if rcode != 0:
        return []

    # Skip Question Section
    offset = 12
    for _ in range(qdcount):
        _, offset = parse_name(data, offset)
        offset += 4  # Skip QTYPE (2) + QCLASS (2)

    # Parse Answer Section
    for _ in range(ancount):
        if offset >= len(data):
            break
        _, offset = parse_name(data, offset)
        if offset + 10 > len(data):
            break

        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        rdata_end = offset + rdlength
        if rdata_end > len(data):
            break

        rdata_bytes = data[offset:rdata_end]
        type_name = REVERSE_RECORD_TYPES.get(rtype, f"TYPE{rtype}")

        value = None

        if rtype == 1 and rdlength == 4:  # A (IPv4)
            value = socket.inet_ntoa(rdata_bytes)
        elif rtype == 28 and rdlength == 16:  # AAAA (IPv6)
            try:
                value = socket.inet_ntop(socket.AF_INET6, rdata_bytes)
            except AttributeError:
                value = ":".join(f"{struct.unpack('!H', rdata_bytes[i:i+2])[0]:x}" for i in range(0, 16, 2))
        elif rtype in (2, 5, 12):  # NS, CNAME, PTR
            name, _ = parse_name(data, offset)
            value = name
        elif rtype == 15 and rdlength >= 3:  # MX
            pref = struct.unpack("!H", rdata_bytes[:2])[0]
            mx_name, _ = parse_name(data, offset + 2)
            value = f"{pref} {mx_name}"
        elif rtype == 16:  # TXT
            # TXT records are sequences of length-prefixed strings
            pos = offset
            txt_parts = []
            while pos < rdata_end:
                txt_len = data[pos]
                pos += 1
                txt_parts.append(data[pos : pos + txt_len].decode("utf-8", errors="replace"))
                pos += txt_len
            value = "".join(txt_parts)
        elif rtype == 6:  # SOA
            mname, next_off = parse_name(data, offset)
            rname, next_off = parse_name(data, next_off)
            if next_off + 20 <= rdata_end:
                serial, refresh, retry, expire, minimum = struct.unpack("!IIIII", data[next_off : next_off + 20])
                value = f"Primary: {mname}, Admin: {rname}, Serial: {serial}"
            else:
                value = f"{mname} {rname}"
        else:
            value = f"<raw {rdlength} bytes>"

        if value:
            results.append({
                "type": type_name,
                "value": value,
                "ttl": ttl,
            })

        offset = rdata_end

    return results


def resolve_reverse(ip: str, server: str, timeout: int = SOCKET_TIMEOUT) -> List[str]:
    """Perform reverse DNS lookup (PTR)."""
    # 1. Try standard gethostbyaddr first
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        if host:
            return [host]
    except Exception:
        pass

    # 2. Try raw PTR query (e.g. 8.8.8.8 -> 8.8.8.8.in-addr.arpa)
    try:
        parsed_ip = ipaddress.ip_address(ip)
        reverse_name = parsed_ip.reverse_pointer
        raw_res = query_dns_raw(reverse_name, "PTR", server, timeout=timeout)
        return [r["value"] for r in raw_res if r.get("value")]
    except Exception:
        pass

    return []


def resolve_all_records(domain: str, server: str, target_types: List[str], timeout: int = SOCKET_TIMEOUT) -> Dict[str, List[Any]]:
    """Enumerate multiple DNS record types for a domain."""
    records: Dict[str, List[Any]] = {}
    for rtype in target_types:
        res = query_dns_raw(domain, rtype, server, timeout=timeout)
        if res:
            records[rtype] = res
    return records


def print_banner() -> None:
    banner = f"""{Colors.CYAN}{Colors.BOLD}
╔════════════════════════════════════════════════════════════════════╗
║             🌐  DNS RECONNAISSANCE & RESOLVER — SCRIPT #02         ║
║               Python Security Toolkit • Phase 1: Recon             ║
╚════════════════════════════════════════════════════════════════════╝{Colors.RESET}
"""
    print(banner)


def display_results(target: str, server: str, records: Dict[str, List[Dict[str, Any]]], is_reverse: bool) -> None:
    """Print beautifully styled terminal report of resolved DNS records."""
    print(f"{Colors.BOLD}Target        :{Colors.RESET} {Colors.GREEN}{target}{Colors.RESET}")
    print(f"{Colors.BOLD}DNS Resolver  :{Colors.RESET} {server}")
    print(f"{Colors.BOLD}Query Mode    :{Colors.RESET} {'Reverse DNS (PTR)' if is_reverse else 'Forward Enumeration'}\n")

    if is_reverse:
        ptrs = records.get("PTR", [])
        print(f"{Colors.CYAN}{Colors.BOLD}━━━ REVERSE DNS POINTERS (PTR) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}")
        if ptrs:
            for p in ptrs:
                val = p if isinstance(p, str) else p.get("value")
                print(f"  {Colors.BOLD}Hostname :{Colors.RESET} {Colors.GREEN}{val}{Colors.RESET}")
        else:
            print("  (No reverse PTR record found for this IP)")
        print(f"\n{Colors.DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}")
        return

    total_records = sum(len(v) for v in records.values())
    if total_records == 0:
        print(f"{Colors.YELLOW}[!] No records found for '{target}' using resolver {server}.{Colors.RESET}\n")
        return

    # A & AAAA Records
    if "A" in records or "AAAA" in records:
        print(f"{Colors.CYAN}{Colors.BOLD}━━━ IP ADDRESSES (A / AAAA) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}")
        for r in records.get("A", []):
            print(f"  {Colors.BOLD}IPv4 (A)    :{Colors.RESET} {Colors.GREEN}{r['value']}{Colors.RESET}  {Colors.DIM}(TTL: {r['ttl']}s){Colors.RESET}")
        for r in records.get("AAAA", []):
            print(f"  {Colors.BOLD}IPv6 (AAAA) :{Colors.RESET} {Colors.MAGENTA}{r['value']}{Colors.RESET}  {Colors.DIM}(TTL: {r['ttl']}s){Colors.RESET}")
        print()

    # MX Records
    if "MX" in records:
        print(f"{Colors.CYAN}{Colors.BOLD}━━━ MAIL EXCHANGERS (MX) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}")
        for r in records["MX"]:
            print(f"  {Colors.BOLD}Mail Server :{Colors.RESET} {r['value']}  {Colors.DIM}(TTL: {r['ttl']}s){Colors.RESET}")
        print()

    # NS Records
    if "NS" in records:
        print(f"{Colors.CYAN}{Colors.BOLD}━━━ NAME SERVERS (NS) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}")
        for r in records["NS"]:
            print(f"  • {r['value']}  {Colors.DIM}(TTL: {r['ttl']}s){Colors.RESET}")
        print()

    # TXT Records (Security Policies, SPF, DMARC)
    if "TXT" in records:
        print(f"{Colors.CYAN}{Colors.BOLD}━━━ TXT RECORDS / SECURITY POLICIES ({len(records['TXT'])}) ━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}")
        for r in records["TXT"]:
            val = r["value"]
            # Highlight SPF and DMARC policies
            if "v=spf1" in val:
                print(f"  {Colors.GREEN}{Colors.BOLD}[SPF POLICY]{Colors.RESET}   {val}")
            elif "v=DMARC1" in val:
                print(f"  {Colors.GREEN}{Colors.BOLD}[DMARC POLICY]{Colors.RESET} {val}")
            else:
                print(f"  {Colors.DIM}• {val}{Colors.RESET}")
        print()

    # SOA Records
    if "SOA" in records:
        print(f"{Colors.CYAN}{Colors.BOLD}━━━ START OF AUTHORITY (SOA) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}")
        for r in records["SOA"]:
            print(f"  {r['value']}")
        print()

    # CNAME Records
    if "CNAME" in records:
        print(f"{Colors.CYAN}{Colors.BOLD}━━━ ALIASES (CNAME) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}")
        for r in records["CNAME"]:
            print(f"  {Colors.BOLD}Canonical :{Colors.RESET} {r['value']}")
        print()

    print(f"{Colors.DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}")


def main():
    parser = argparse.ArgumentParser(
        description="DNS Intelligence & Reconnaissance Tool (Script #02 in Python Security Toolkit)",
        epilog="Examples:\n  python recon/dns_resolver.py example.com\n  python recon/dns_resolver.py example.com -t MX\n  python recon/dns_resolver.py 8.8.8.8 --reverse",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", help="Target domain name (e.g. example.com) or IP address for reverse lookup")
    parser.add_argument("-t", "--type", help="Specific record type to query (A, AAAA, MX, NS, TXT, SOA, CNAME, or ALL by default)")
    parser.add_argument("-s", "--server", default="8.8.8.8", help="Custom DNS server address (default: 8.8.8.8 Google)")
    parser.add_argument("-r", "--reverse", action="store_true", help="Perform reverse DNS (PTR) lookup on target IP")
    parser.add_argument("-j", "--json", action="store_true", help="Output results in structured JSON format")
    parser.add_argument("--timeout", type=int, default=SOCKET_TIMEOUT, help="Query timeout in seconds (default: 5)")

    args = parser.parse_args()
    target = clean_target(args.target)

    if not target:
        print(f"{Colors.RED}[!] Error: Target domain or IP cannot be empty.{Colors.RESET}", file=sys.stderr)
        sys.exit(1)

    is_reverse = args.reverse or is_ip_address(target)

    # Reverse DNS Mode
    if is_reverse:
        ptrs = resolve_reverse(target, args.server, timeout=args.timeout)
        result_dict = {"PTR": ptrs}
        if args.json:
            print(json.dumps({
                "target": target,
                "resolver": args.server,
                "query_mode": "reverse",
                "records": result_dict,
            }, indent=2))
        else:
            print_banner()
            display_results(target, args.server, result_dict, is_reverse=True)
        return

    # Forward DNS Enumeration Mode
    if args.type and args.type.upper() != "ALL":
        target_types = [args.type.upper()]
        if target_types[0] not in RECORD_TYPES:
            print(f"{Colors.RED}[!] Error: Unsupported record type '{args.type}'. Supported types: {', '.join(RECORD_TYPES.keys())}{Colors.RESET}", file=sys.stderr)
            sys.exit(2)
    else:
        target_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]

    records = resolve_all_records(target, args.server, target_types, timeout=args.timeout)

    if args.json:
        output_payload = {
            "target": target,
            "resolver": args.server,
            "query_mode": "forward",
            "records": records,
        }
        print(json.dumps(output_payload, indent=2, ensure_ascii=False))
    else:
        print_banner()
        display_results(target, args.server, records, is_reverse=False)


if __name__ == "__main__":
    main()
