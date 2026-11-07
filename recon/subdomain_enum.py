#!/usr/bin/env python3
"""
=============================================================================
subdomain_enum.py — Script #03 in Python Security Toolkit
Phase 1: Reconnaissance
=============================================================================
Subdomain brute-force enumerator that discovers valid subdomains by resolving
candidate hostnames against a DNS server. Ships with a built-in wordlist of
~120 common subdomains and supports custom wordlists for deeper enumeration.

Concepts Covered:
    • DNS-based subdomain brute-forcing
    • Concurrent resolution with ThreadPoolExecutor
    • Wildcard detection to reduce false positives
    • Progress reporting during long scans

Usage:
    python recon/subdomain_enum.py example.com
    python recon/subdomain_enum.py example.com --wordlist custom.txt
    python recon/subdomain_enum.py example.com --threads 50 --timeout 3
    python recon/subdomain_enum.py example.com --json
=============================================================================
"""

import argparse
import json
import random
import socket
import string
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


# ── Built-in default wordlist (~120 common subdomains) ───────────────────────
# These are the most frequently encountered subdomains across the internet.
# For production reconnaissance, use larger lists like SecLists/Discovery.
DEFAULT_WORDLIST: List[str] = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "mx",
    "admin", "administrator", "portal", "panel", "dashboard", "cpanel",
    "api", "api2", "api3", "rest", "graphql", "gateway",
    "dev", "develop", "development", "staging", "stage", "test", "testing",
    "qa", "uat", "sandbox", "demo", "beta", "alpha", "preview",
    "app", "apps", "mobile", "m", "web", "www2", "www3",
    "ns", "ns1", "ns2", "ns3", "ns4", "dns", "dns1", "dns2",
    "vpn", "remote", "ssh", "rdp", "proxy", "socks",
    "db", "database", "mysql", "postgres", "postgresql", "mongo", "redis",
    "sql", "mssql", "oracle", "elastic", "elasticsearch",
    "cdn", "static", "assets", "media", "images", "img", "files",
    "git", "gitlab", "github", "svn", "repo", "ci", "jenkins", "build",
    "blog", "news", "forum", "wiki", "docs", "doc", "help", "support",
    "shop", "store", "cart", "pay", "payment", "billing", "checkout",
    "auth", "login", "sso", "oauth", "id", "identity", "accounts",
    "status", "monitor", "monitoring", "grafana", "prometheus", "nagios",
    "logs", "log", "syslog", "kibana",
    "backup", "bak", "old", "legacy", "archive",
    "internal", "intranet", "corp", "office", "exchange",
    "cloud", "aws", "azure", "gcp", "s3",
    "video", "stream", "live", "chat", "meet",
    "analytics", "track", "metrics",
    "search", "solr",
    "mail2", "smtp2", "relay",
    "crm", "erp", "jira", "confluence",
    "secure", "ssl", "wss",
]


def clean_domain(domain: str) -> str:
    """Normalize input by stripping protocols, paths, and whitespace."""
    domain = domain.strip().lower()
    domain = domain.replace("https://", "").replace("http://", "")
    domain = domain.split("/")[0].split("?")[0].split(":")[0]
    if domain.startswith("www.") and domain.count(".") > 1:
        domain = domain[4:]
    return domain


def load_wordlist(path: str) -> List[str]:
    """Load subdomain candidates from a file (one per line)."""
    words: List[str] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                word = line.strip().lower()
                # Skip comments and empty lines
                if word and not word.startswith("#"):
                    words.append(word)
    except FileNotFoundError:
        print(f"{Colors.RED}[!] Wordlist file not found: {path}{Colors.RESET}", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print(f"{Colors.RED}[!] Permission denied reading: {path}{Colors.RESET}", file=sys.stderr)
        sys.exit(1)
    return words


def detect_wildcard(domain: str, timeout: float) -> Optional[str]:
    """
    Detect wildcard DNS by resolving a random, highly unlikely subdomain.
    If it resolves, the domain uses wildcard records and every subdomain
    will appear "found" — we need to filter those IPs out.
    """
    random_sub = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
    fqdn = f"{random_sub}.{domain}"
    try:
        socket.setdefaulttimeout(timeout)
        result = socket.gethostbyname(fqdn)
        return result  # Wildcard IP
    except (socket.gaierror, socket.timeout, OSError):
        return None


def resolve_subdomain(
    subdomain: str, domain: str, timeout: float, wildcard_ip: Optional[str]
) -> Optional[Dict[str, Any]]:
    """
    Attempt to resolve a single subdomain candidate.
    Returns a dict with results if found, or None.
    """
    fqdn = f"{subdomain}.{domain}"
    try:
        socket.setdefaulttimeout(timeout)
        # gethostbyname_ex returns (hostname, aliases, ip_list)
        hostname, aliases, ip_list = socket.gethostbyname_ex(fqdn)

        if not ip_list:
            return None

        # Filter out wildcard matches — if the IP matches the wildcard,
        # this subdomain is almost certainly not real
        if wildcard_ip and all(ip == wildcard_ip for ip in ip_list):
            return None

        return {
            "subdomain": subdomain,
            "fqdn": fqdn,
            "ips": ip_list,
            "hostname": hostname,
            "aliases": aliases if aliases else [],
        }
    except (socket.gaierror, socket.herror, socket.timeout, OSError):
        return None


def print_banner() -> None:
    banner = f"""{Colors.CYAN}{Colors.BOLD}
╔════════════════════════════════════════════════════════════════════╗
║          🔍  SUBDOMAIN ENUMERATOR — SCRIPT #03                     ║
║               Python Security Toolkit • Phase 1: Recon             ║
╚════════════════════════════════════════════════════════════════════╝{Colors.RESET}
"""
    print(banner)


def display_results(
    domain: str,
    found: List[Dict[str, Any]],
    total_checked: int,
    elapsed: float,
    wildcard_ip: Optional[str],
) -> None:
    """Print beautifully formatted subdomain enumeration report."""
    print(f"{Colors.BOLD}Target Domain  :{Colors.RESET} {Colors.GREEN}{domain}{Colors.RESET}")
    print(f"{Colors.BOLD}Subdomains Tested :{Colors.RESET} {total_checked}")
    print(f"{Colors.BOLD}Scan Duration  :{Colors.RESET} {elapsed:.2f}s")

    if wildcard_ip:
        print(f"{Colors.YELLOW}{Colors.BOLD}⚠  Wildcard DNS Detected :{Colors.RESET} {Colors.YELLOW}{wildcard_ip} — results filtered{Colors.RESET}")
    print()

    if not found:
        print(f"{Colors.YELLOW}[!] No subdomains discovered. Try a larger wordlist.{Colors.RESET}\n")
        return

    print(f"{Colors.CYAN}{Colors.BOLD}━━━ DISCOVERED SUBDOMAINS ({len(found)}) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}")
    for entry in found:
        ip_str = ", ".join(entry["ips"])
        print(f"  {Colors.GREEN}{Colors.BOLD}{entry['fqdn']}{Colors.RESET}")
        print(f"      └─ IP: {ip_str}")
        if entry["aliases"]:
            print(f"      └─ Aliases: {', '.join(entry['aliases'])}")

    print(f"\n{Colors.DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}")
    print(f"\n{Colors.BOLD}Summary:{Colors.RESET} Found {Colors.GREEN}{len(found)}{Colors.RESET} subdomains out of {total_checked} tested ({elapsed:.1f}s)")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Subdomain Brute-Force Enumerator (Script #03 in Python Security Toolkit)",
        epilog="Examples:\n"
               "  python recon/subdomain_enum.py example.com\n"
               "  python recon/subdomain_enum.py example.com --wordlist subs.txt --threads 50\n"
               "  python recon/subdomain_enum.py example.com --json",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("domain", help="Target domain to enumerate subdomains for (e.g. example.com)")
    parser.add_argument("-w", "--wordlist", help="Path to custom wordlist file (one subdomain per line)")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Number of concurrent threads (default: 20)")
    parser.add_argument("--timeout", type=float, default=3.0, help="DNS resolution timeout in seconds (default: 3)")
    parser.add_argument("-j", "--json", action="store_true", help="Output results in structured JSON format")
    parser.add_argument("--no-wildcard-check", action="store_true", help="Skip wildcard DNS detection")

    args = parser.parse_args()
    domain = clean_domain(args.domain)

    if not domain or "." not in domain:
        print(f"{Colors.RED}[!] Error: Invalid domain '{args.domain}'. Provide a valid domain (e.g. example.com).{Colors.RESET}", file=sys.stderr)
        sys.exit(1)

    # Load wordlist — custom file or built-in default
    if args.wordlist:
        wordlist = load_wordlist(args.wordlist)
        if not wordlist:
            print(f"{Colors.RED}[!] Error: Wordlist is empty.{Colors.RESET}", file=sys.stderr)
            sys.exit(1)
    else:
        wordlist = DEFAULT_WORDLIST[:]

    # Deduplicate while preserving order
    seen = set()
    unique_wordlist: List[str] = []
    for w in wordlist:
        if w not in seen:
            seen.add(w)
            unique_wordlist.append(w)
    wordlist = unique_wordlist

    if not args.json:
        print_banner()
        print(f"{Colors.DIM}[*] Loaded {len(wordlist)} subdomain candidates{Colors.RESET}")

    # ── Wildcard detection ───────────────────────────────────────────────
    wildcard_ip: Optional[str] = None
    if not args.no_wildcard_check:
        if not args.json:
            print(f"{Colors.DIM}[*] Checking for wildcard DNS...{Colors.RESET}")
        wildcard_ip = detect_wildcard(domain, args.timeout)
        if wildcard_ip and not args.json:
            print(f"{Colors.YELLOW}[!] Wildcard detected → {wildcard_ip} — filtering false positives{Colors.RESET}")
        elif not args.json:
            print(f"{Colors.DIM}[*] No wildcard DNS detected{Colors.RESET}")

    # ── Concurrent subdomain resolution ──────────────────────────────────
    if not args.json:
        print(f"{Colors.DIM}[*] Scanning with {args.threads} threads...{Colors.RESET}\n")

    found: List[Dict[str, Any]] = []
    completed = 0
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_sub = {
            executor.submit(resolve_subdomain, sub, domain, args.timeout, wildcard_ip): sub
            for sub in wordlist
        }

        for future in as_completed(future_to_sub):
            completed += 1
            result = future.result()
            if result:
                found.append(result)
                if not args.json:
                    ip_str = ", ".join(result["ips"])
                    print(f"  {Colors.GREEN}[+]{Colors.RESET} {result['fqdn']} → {ip_str}")

            # Progress indicator every 25 completions (non-JSON mode)
            if not args.json and completed % 25 == 0:
                pct = (completed / len(wordlist)) * 100
                print(f"{Colors.DIM}    ... {completed}/{len(wordlist)} checked ({pct:.0f}%){Colors.RESET}")

    elapsed = time.time() - start_time

    # Sort results alphabetically by FQDN
    found.sort(key=lambda x: x["fqdn"])

    # ── Output ───────────────────────────────────────────────────────────
    if args.json:
        output = {
            "target": domain,
            "total_checked": len(wordlist),
            "found_count": len(found),
            "elapsed_seconds": round(elapsed, 2),
            "wildcard_ip": wildcard_ip,
            "subdomains": found,
        }
        print(json.dumps(output, indent=2, ensure_ascii=False))
    else:
        print()
        display_results(domain, found, len(wordlist), elapsed, wildcard_ip)


if __name__ == "__main__":
    main()
