#!/usr/bin/env python3
"""
=============================================================================
whois_lookup.py — Script #01 in Python Security Toolkit
Phase 1: Reconnaissance
=============================================================================
Performs RFC 3912 WHOIS queries against root and registrar servers to gather
domain intelligence: registration dates, registrar, name servers, and OSINT
details without requiring any external dependencies.

Usage:
    python recon/whois_lookup.py example.com
    python recon/whois_lookup.py example.com --json
    python recon/whois_lookup.py example.com --raw
    python recon/whois_lookup.py example.com --server whois.verisign-grs.com
=============================================================================
"""

import argparse
import json
import re
import socket
import sys
from typing import Dict, List, Optional, Tuple

# Ensure UTF-8 output encoding across Windows terminals
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


# Default TLD-to-WHOIS server mappings for fast direct lookups
TLD_WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "info": "whois.afilias.net",
    "io": "whois.nic.io",
    "co": "whois.nic.co",
    "me": "whois.nic.me",
    "dev": "whois.nic.google",
    "app": "whois.nic.google",
    "ai": "whois.nic.ai",
    "uk": "whois.nic.uk",
    "ca": "whois.cira.ca",
    "de": "whois.denic.de",
    "fr": "whois.nic.fr",
    "eu": "whois.eu",
    "gov": "whois.nic.gov",
    "edu": "whois.educause.edu",
}

DEFAULT_IANA_SERVER = "whois.iana.org"
WHOIS_PORT = 43
DEFAULT_TIMEOUT = 10


# ANSI Colors for terminal output
class Colors:
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


def clean_domain(domain: str) -> str:
    """Normalize input by stripping protocols, paths, and whitespace."""
    domain = domain.strip().lower()
    # Strip URL schemes if present
    domain = re.sub(r"^https?://", "", domain)
    # Strip paths or query parameters
    domain = domain.split("/")[0].split("?")[0].split(":")[0]
    # Strip leading 'www.' if present
    if domain.startswith("www.") and domain.count(".") > 1:
        domain = domain[4:]
    return domain


def query_whois_server(domain: str, server: str, timeout: int = DEFAULT_TIMEOUT) -> str:
    """
    Connect to a WHOIS server via TCP port 43 (RFC 3912) and return raw text.
    """
    response_chunks: List[bytes] = []

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((server, WHOIS_PORT))

            # Queries in RFC 3912 are terminated by CRLF
            query = f"{domain}\r\n".encode("utf-8")
            sock.sendall(query)

            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response_chunks.append(data)

    except socket.timeout:
        raise TimeoutError(f"Connection to WHOIS server '{server}' timed out after {timeout}s.")
    except socket.gaierror:
        raise ConnectionError(f"Could not resolve WHOIS server address: '{server}'.")
    except OSError as err:
        raise ConnectionError(f"Socket error communicating with '{server}': {err}")

    raw_bytes = b"".join(response_chunks)
    # Decode with fallback encoding handling
    for encoding in ("utf-8", "latin-1", "iso-8859-1"):
        try:
            return raw_bytes.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw_bytes.decode("utf-8", errors="replace")


def get_referral_server(whois_text: str) -> Optional[str]:
    """
    Inspect WHOIS response for a referral to a registrar-specific WHOIS server.
    """
    patterns = [
        r"Registrar WHOIS Server:\s*([^\s\r\n]+)",
        r"refer:\s*([^\s\r\n]+)",
        r"whois:\s*([^\s\r\n]+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, whois_text, re.IGNORECASE)
        if match:
            candidate = match.group(1).strip()
            # Filter out non-server strings
            if candidate and not candidate.startswith("http") and "." in candidate:
                return candidate
    return None


def get_tld_server(domain: str, timeout: int = DEFAULT_TIMEOUT) -> str:
    """
    Determine the initial WHOIS server for a domain's TLD.
    Checks static table first, falls back to querying IANA.
    """
    parts = domain.split(".")
    tld = parts[-1]

    if tld in TLD_WHOIS_SERVERS:
        return TLD_WHOIS_SERVERS[tld]

    # Query IANA for unknown TLDs
    try:
        iana_response = query_whois_server(tld, DEFAULT_IANA_SERVER, timeout=timeout)
        referral = get_referral_server(iana_response)
        if referral:
            return referral
    except Exception:
        pass

    # Generic fallback
    return f"{tld}.whois-servers.net"


def fetch_whois(domain: str, custom_server: Optional[str] = None, timeout: int = DEFAULT_TIMEOUT) -> Tuple[str, str]:
    """
    Retrieve full WHOIS data, automatically following registrar referrals if present.
    Returns: (raw_whois_text, final_server_queried)
    """
    start_server = custom_server if custom_server else get_tld_server(domain, timeout=timeout)
    first_response = query_whois_server(domain, start_server, timeout=timeout)

    # If the user specified a custom server, don't auto-hop unless they want to
    if custom_server:
        return first_response, custom_server

    # Check if this response points to a more detailed registrar WHOIS server
    referral_server = get_referral_server(first_response)
    if referral_server and referral_server.lower() != start_server.lower():
        try:
            second_response = query_whois_server(domain, referral_server, timeout=timeout)
            if len(second_response.strip()) > 100:
                # Append both for complete provenance
                combined = f"{second_response}\n\n# --- TLD Server ({start_server}) Response ---\n{first_response}"
                return combined, referral_server
        except Exception:
            # If referral fails, fall back gracefully to the first response
            pass

    return first_response, start_server


def parse_whois_fields(whois_text: str) -> Dict[str, Optional[str | List[str]]]:
    """
    Parse standard WHOIS key-value fields using flexible regular expressions.
    """
    data: Dict[str, Optional[str | List[str]]] = {
        "domain_name": None,
        "registrar": None,
        "registrar_whois_server": None,
        "registrar_url": None,
        "creation_date": None,
        "expiration_date": None,
        "updated_date": None,
        "name_servers": [],
        "status": [],
        "registrant_name": None,
        "registrant_organization": None,
        "registrant_country": None,
        "dnssec": None,
    }

    # Match single-value fields
    single_field_patterns = {
        "domain_name": [
            r"Domain Name:\s*([^\r\n]+)",
            r"domain:\s*([^\r\n]+)",
        ],
        "registrar": [
            r"Registrar:\s*([^\r\n]+)",
            r"registrar-name:\s*([^\r\n]+)",
            r"Sponsoring Registrar:\s*([^\r\n]+)",
        ],
        "registrar_whois_server": [
            r"Registrar WHOIS Server:\s*([^\r\n]+)",
        ],
        "registrar_url": [
            r"Registrar URL:\s*([^\r\n]+)",
        ],
        "creation_date": [
            r"Creation Date:\s*([^\r\n]+)",
            r"Created:\s*([^\r\n]+)",
            r"Registration Time:\s*([^\r\n]+)",
            r"created:\s*([^\r\n]+)",
        ],
        "expiration_date": [
            r"Registry Expiry Date:\s*([^\r\n]+)",
            r"Registrar Registration Expiration Date:\s*([^\r\n]+)",
            r"Expir\S+ Date:\s*([^\r\n]+)",
            r"paid-till:\s*([^\r\n]+)",
        ],
        "updated_date": [
            r"Updated Date:\s*([^\r\n]+)",
            r"Last Updated Date:\s*([^\r\n]+)",
            r"changed:\s*([^\r\n]+)",
        ],
        "registrant_name": [
            r"Registrant Name:\s*([^\r\n]+)",
            r"registrant:\s*([^\r\n]+)",
        ],
        "registrant_organization": [
            r"Registrant Organization:\s*([^\r\n]+)",
            r"org:\s*([^\r\n]+)",
        ],
        "registrant_country": [
            r"Registrant Country:\s*([^\r\n]+)",
            r"country:\s*([^\r\n]+)",
        ],
        "dnssec": [
            r"DNSSEC:\s*([^\r\n]+)",
            r"dnssec:\s*([^\r\n]+)",
        ],
    }

    for key, patterns in single_field_patterns.items():
        for pat in patterns:
            match = re.search(pat, whois_text, re.IGNORECASE)
            if match:
                val = match.group(1).strip()
                if val:
                    data[key] = val
                    break

    # Multi-value: Name Servers
    ns_matches = re.findall(r"Name Server:\s*([^\r\n]+)", whois_text, re.IGNORECASE)
    if not ns_matches:
        ns_matches = re.findall(r"nserver:\s*([^\s\r\n]+)", whois_text, re.IGNORECASE)
    name_servers = sorted(list({ns.strip().lower() for ns in ns_matches if ns.strip()}))
    data["name_servers"] = name_servers

    # Multi-value: Domain Status
    status_matches = re.findall(r"Domain Status:\s*([^\s\r\n]+)", whois_text, re.IGNORECASE)
    statuses = sorted(list({st.strip() for st in status_matches if st.strip()}))
    data["status"] = statuses

    return data


def print_banner():
    banner = f"""{Colors.CYAN}{Colors.BOLD}
╔════════════════════════════════════════════════════════════════════╗
║             🛡️  WHOIS RECONNAISSANCE TOOL — SCRIPT #01             ║
║               Python Security Toolkit • Phase 1: Recon             ║
╚════════════════════════════════════════════════════════════════════╝{Colors.RESET}
"""
    print(banner)


def display_results(domain: str, server: str, data: Dict[str, Optional[str | List[str]]]):
    """Print beautifully formatted human-readable WHOIS report."""
    print(f"{Colors.BOLD}Target Domain :{Colors.RESET} {Colors.GREEN}{domain}{Colors.RESET}")
    print(f"{Colors.BOLD}WHOIS Server  :{Colors.RESET} {server}\n")

    print(f"{Colors.CYAN}{Colors.BOLD}━━━ REGISTRATION DETAILS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}")
    print(f"  {Colors.BOLD}Registrar       :{Colors.RESET} {data.get('registrar') or 'N/A'}")
    print(f"  {Colors.BOLD}WHOIS Server    :{Colors.RESET} {data.get('registrar_whois_server') or 'N/A'}")
    print(f"  {Colors.BOLD}Registrar URL   :{Colors.RESET} {data.get('registrar_url') or 'N/A'}")
    print(f"  {Colors.BOLD}Created On      :{Colors.RESET} {Colors.YELLOW}{data.get('creation_date') or 'N/A'}{Colors.RESET}")
    print(f"  {Colors.BOLD}Expires On      :{Colors.RESET} {Colors.YELLOW}{data.get('expiration_date') or 'N/A'}{Colors.RESET}")
    print(f"  {Colors.BOLD}Last Updated    :{Colors.RESET} {data.get('updated_date') or 'N/A'}")
    print(f"  {Colors.BOLD}DNSSEC          :{Colors.RESET} {data.get('dnssec') or 'unsigned/N/A'}")

    print(f"\n{Colors.CYAN}{Colors.BOLD}━━━ REGISTRANT OSINT ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}")
    print(f"  {Colors.BOLD}Name            :{Colors.RESET} {data.get('registrant_name') or 'Redacted / Private'}")
    print(f"  {Colors.BOLD}Organization    :{Colors.RESET} {data.get('registrant_organization') or 'Redacted / Private'}")
    print(f"  {Colors.BOLD}Country         :{Colors.RESET} {data.get('registrant_country') or 'N/A'}")

    name_servers = data.get("name_servers", [])
    print(f"\n{Colors.CYAN}{Colors.BOLD}━━━ NAME SERVERS ({len(name_servers)}) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}")
    if name_servers:
        for ns in name_servers:
            print(f"  • {ns}")
    else:
        print("  (None detected in parsed response)")

    statuses = data.get("status", [])
    if statuses:
        print(f"\n{Colors.CYAN}{Colors.BOLD}━━━ DOMAIN STATUS FLAGS ({len(statuses)}) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}")
        for st in statuses:
            print(f"  • {st}")

    print(f"\n{Colors.DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}")


def main():
    parser = argparse.ArgumentParser(
        description="WHOIS Intelligence Reconnaissance Tool (Script #01 in Python Security Toolkit)",
        epilog="Example: python recon/whois_lookup.py example.com --json",
    )
    parser.add_argument("domain", help="Target domain name (e.g. github.com, python.org)")
    parser.add_argument("-j", "--json", action="store_true", help="Output parsed data as JSON")
    parser.add_argument("-r", "--raw", action="store_true", help="Print raw unparsed WHOIS response")
    parser.add_argument("-s", "--server", help="Custom WHOIS server to query directly")
    parser.add_argument("-t", "--timeout", type=int, default=DEFAULT_TIMEOUT, help="Socket timeout in seconds (default: 10)")

    args = parser.parse_args()
    domain = clean_domain(args.domain)

    if not domain or "." not in domain:
        print(f"{Colors.RED}[!] Error: Invalid domain name '{args.domain}'. Please provide a valid domain (e.g. example.com).{Colors.RESET}", file=sys.stderr)
        sys.exit(1)

    try:
        raw_text, final_server = fetch_whois(domain, custom_server=args.server, timeout=args.timeout)
    except (TimeoutError, ConnectionError) as err:
        print(f"{Colors.RED}[!] Connection Failure: {err}{Colors.RESET}", file=sys.stderr)
        sys.exit(2)
    except Exception as err:
        print(f"{Colors.RED}[!] Unexpected Error: {err}{Colors.RESET}", file=sys.stderr)
        sys.exit(3)

    if args.raw:
        print(raw_text)
        return

    parsed = parse_whois_fields(raw_text)
    # Ensure domain is populated if not explicitly in output
    if not parsed["domain_name"]:
        parsed["domain_name"] = domain

    if args.json:
        output_payload = {
            "target": domain,
            "whois_server": final_server,
            "data": parsed,
        }
        print(json.dumps(output_payload, indent=2, ensure_ascii=False))
    else:
        print_banner()
        display_results(domain, final_server, parsed)


if __name__ == "__main__":
    main()
