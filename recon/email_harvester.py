#!/usr/bin/env python3
"""
=============================================================================
email_harvester.py — Script #05 in Python Security Toolkit
Phase 1: Reconnaissance
=============================================================================
Targeted OSINT email harvesting and validation tool. Crawls a target domain,
extracts email addresses using regular expressions, mailto: tags, and
de-obfuscation heuristics, and optionally verifies recipient domain MX records.

Concepts Covered:
    • Web crawling and link boundary scoping (BFS traversal)
    • Multi-vector email pattern matching and de-obfuscation
    • False-positive filtering (asset extensions, placeholder addresses)
    • OSINT intelligence classification (internal vs. external addresses)
    • DNS Mail Exchanger (MX) record validation for discovered domains

Usage:
    python recon/email_harvester.py https://example.com
    python recon/email_harvester.py example.com --depth 2 --max-pages 20
    python recon/email_harvester.py example.com --verify-mx
    python recon/email_harvester.py example.com --json
=============================================================================
"""

import argparse
import html
import json
import re
import sys
from collections import deque
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urldefrag, urljoin, urlparse

# Ensure UTF-8 output encoding across Windows terminals
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    print("[!] 'requests' library is required. Install with: pip install requests", file=sys.stderr)
    sys.exit(1)

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

# Fallback: leverage Script #02 (dns_resolver.py) if dnspython is not installed
try:
    from recon.dns_resolver import resolve_all_records
    HAS_LOCAL_RESOLVER = True
except ImportError:
    try:
        from dns_resolver import resolve_all_records
        HAS_LOCAL_RESOLVER = True
    except ImportError:
        HAS_LOCAL_RESOLVER = False


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


# ── Constants & Patterns ─────────────────────────────────────────────────────
# Standard email address regex
EMAIL_REGEX = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    re.IGNORECASE,
)

# File extensions to ignore during crawling or false-positive email filtering
IGNORED_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
    ".css", ".js", ".map", ".woff", ".woff2", ".ttf", ".eot",
    ".pdf", ".zip", ".tar", ".gz", ".exe", ".bin", ".mp3", ".mp4",
)

# Common placeholder / dummy addresses
COMMON_PLACEHOLDERS = {
    "example@example.com",
    "user@example.com",
    "name@example.com",
    "email@example.com",
    "user@domain.com",
    "yourname@email.com",
    "test@test.com",
}


def normalize_target(target: str) -> Tuple[str, str]:
    """
    Ensure target has a valid scheme and return both the full URL
    and the clean apex/subdomain hostname.
    """
    target = target.strip()
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    parsed = urlparse(target)
    hostname = parsed.hostname or ""
    # Strip port if present
    if ":" in hostname:
        hostname = hostname.split(":")[0]

    base_url = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
    return base_url, hostname.lower()


def is_internal_link(url: str, base_domain: str) -> bool:
    """Check if a URL belongs to the target domain or subdomains."""
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc.lower().split(":")[0]
        return netloc == base_domain or netloc.endswith(f".{base_domain}")
    except Exception:
        return False


def is_valid_crawl_target(url: str) -> bool:
    """Filter out non-HTML assets (images, stylesheets, documents)."""
    parsed = urlparse(url)
    path = parsed.path.lower()
    return not any(path.endswith(ext) for ext in IGNORED_EXTENSIONS)


def deobfuscate_text(raw_text: str) -> str:
    """Decode HTML entities and unmask common email obfuscation patterns."""
    text = html.unescape(raw_text)
    # Replace [at], (at), [AT], (AT), [@], (@) with @
    text = re.sub(r"\s*(\[|\()\s*(?:at|@)\s*(\]|\))\s*", "@", text, flags=re.IGNORECASE)
    # Replace [dot], (dot), [DOT], (DOT), [.], (.) with .
    text = re.sub(r"\s*(\[|\()\s*(?:dot|\.)\s*(\]|\))\s*", ".", text, flags=re.IGNORECASE)
    # Collapse whitespace around @ and . in email patterns (e.g. user @ domain . com)
    text = re.sub(r"([A-Za-z0-9._%+-]+)\s*@\s*([A-Za-z0-9.-]+)\s*\.\s*([A-Za-z]{2,})", r"\1@\2.\3", text)
    return text


def extract_emails_from_content(content: str, current_url: str) -> Set[str]:
    """
    Extract email addresses from page HTML and text content using multiple vectors:
    1. Direct regex on raw and de-obfuscated content.
    2. mailto: URI parsing from anchor tags.
    """
    found_emails: Set[str] = set()

    # 1. De-obfuscation and regex search
    cleaned_content = deobfuscate_text(content)
    for match in EMAIL_REGEX.findall(cleaned_content):
        match_clean = match.strip().lower().rstrip(".")
        found_emails.add(match_clean)

    # 2. Parse mailto: links
    if HAS_BS4:
        try:
            soup = BeautifulSoup(content, "html.parser")
            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"].strip()
                if href.lower().startswith("mailto:"):
                    raw_email = href.split(":", 1)[1].split("?")[0].strip()
                    raw_email = deobfuscate_text(raw_email).lower()
                    if EMAIL_REGEX.match(raw_email):
                        found_emails.add(raw_email)
        except Exception:
            pass
    else:
        # Fallback regex search for mailto links
        for mailto_match in re.findall(r"mailto:([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})", content, re.IGNORECASE):
            found_emails.add(mailto_match.strip().lower())

    # 3. Filter false positives
    filtered: Set[str] = set()
    for email_addr in found_emails:
        # Discard if ending with an asset extension (e.g. image@2x.png)
        if any(email_addr.endswith(ext) for ext in IGNORED_EXTENSIONS):
            continue
        # Discard standard non-target placeholders
        if email_addr in COMMON_PLACEHOLDERS and "example.com" not in current_url:
            continue
        filtered.add(email_addr)

    return filtered


def extract_links(base_url: str, base_domain: str, html_content: str) -> Set[str]:
    """Extract in-scope internal links to follow during crawl."""
    links: Set[str] = set()

    if HAS_BS4:
        try:
            soup = BeautifulSoup(html_content, "html.parser")
            for a_tag in soup.find_all("a", href=True):
                raw_href = a_tag["href"].strip()
                if not raw_href or raw_href.startswith(("javascript:", "mailto:", "tel:", "#")):
                    continue
                full_url = urljoin(base_url, raw_href)
                # Strip fragment
                clean_url, _ = urldefrag(full_url)
                if is_internal_link(clean_url, base_domain) and is_valid_crawl_target(clean_url):
                    links.add(clean_url)
        except Exception:
            pass
    else:
        # Fallback regex link extraction
        for href in re.findall(r'href=["\'](.*?)["\']', html_content, re.IGNORECASE):
            href = href.strip()
            if not href or href.startswith(("javascript:", "mailto:", "tel:", "#")):
                continue
            full_url = urljoin(base_url, href)
            clean_url, _ = urldefrag(full_url)
            if is_internal_link(clean_url, base_domain) and is_valid_crawl_target(clean_url):
                links.add(clean_url)

    return links


def check_mx_record(domain: str, timeout: int = 3) -> Optional[bool]:
    """Check if the email domain has valid DNS MX records."""
    if HAS_DNS:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        resolver.timeout = timeout
        try:
            answers = resolver.resolve(domain, "MX")
            return len(answers) > 0
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
            return False
        except Exception:
            pass

    if HAS_LOCAL_RESOLVER:
        try:
            records = resolve_all_records(domain, "8.8.8.8", ["MX"], timeout=timeout)
            mx_list = records.get("MX", [])
            return len(mx_list) > 0
        except Exception:
            return False

    return None


def crawl_and_harvest(
    start_url: str,
    base_domain: str,
    max_depth: int = 2,
    max_pages: int = 15,
    timeout: int = 10,
    verify_mx: bool = False,
    verbose: bool = True,
) -> Dict[str, Any]:
    """
    Perform BFS web crawling across internal links within max_depth and max_pages,
    harvesting and organizing discovered email addresses.
    """
    visited_urls: Set[str] = set()
    queue: deque = deque([(start_url, 0)])
    discovered_emails: Dict[str, List[str]] = {}  # email -> list of source URLs
    mx_cache: Dict[str, Optional[bool]] = {}

    session = requests.Session()
    session.headers.update({"User-Agent": "PythonSecurityToolkit/1.0 (educational email harvester)"})

    pages_crawled = 0

    while queue and pages_crawled < max_pages:
        current_url, depth = queue.popleft()

        if current_url in visited_urls:
            continue

        visited_urls.add(current_url)
        pages_crawled += 1

        if verbose:
            print(f"  {Colors.DIM}[*] [{pages_crawled}/{max_pages}] Crawling (depth {depth}): {current_url}{Colors.RESET}")

        try:
            resp = session.get(current_url, timeout=timeout, allow_redirects=True, verify=True)
            if resp.status_code != 200 or not resp.text:
                continue

            content_type = resp.headers.get("Content-Type", "").lower()
            if "text/html" not in content_type and "text/plain" not in content_type:
                continue

            # Extract emails
            page_emails = extract_emails_from_content(resp.text, current_url)
            for email_addr in page_emails:
                if email_addr not in discovered_emails:
                    discovered_emails[email_addr] = []
                    if verbose:
                        print(f"      {Colors.GREEN}✔ Found:{Colors.RESET} {email_addr}")
                discovered_emails[email_addr].append(current_url)

            # Discover further internal links if depth permits
            if depth < max_depth:
                new_links = extract_links(resp.url, base_domain, resp.text)
                for link in new_links:
                    if link not in visited_urls:
                        queue.append((link, depth + 1))

        except RequestException:
            if verbose:
                print(f"      {Colors.YELLOW}⚠ Request failed for {current_url}{Colors.RESET}")
            continue

    # Classify emails into Internal vs External
    internal_emails: List[Dict[str, Any]] = []
    external_emails: List[Dict[str, Any]] = []

    for email_addr, sources in discovered_emails.items():
        email_domain = email_addr.split("@", 1)[1].lower()
        is_internal = email_domain == base_domain or email_domain.endswith(f".{base_domain}")

        mx_valid = None
        if verify_mx:
            if email_domain not in mx_cache:
                mx_cache[email_domain] = check_mx_record(email_domain)
            mx_valid = mx_cache[email_domain]

        entry = {
            "email": email_addr,
            "domain": email_domain,
            "sources": sources,
            "source_count": len(sources),
            "mx_valid": mx_valid,
        }

        if is_internal:
            internal_emails.append(entry)
        else:
            external_emails.append(entry)

    # Sort alphabetically by email
    internal_emails.sort(key=lambda x: x["email"])
    external_emails.sort(key=lambda x: x["email"])

    return {
        "target_url": start_url,
        "base_domain": base_domain,
        "pages_crawled": pages_crawled,
        "total_emails_found": len(discovered_emails),
        "internal_count": len(internal_emails),
        "external_count": len(external_emails),
        "internal_emails": internal_emails,
        "external_emails": external_emails,
    }


def print_banner() -> None:
    banner = f"""{Colors.CYAN}{Colors.BOLD}
╔════════════════════════════════════════════════════════════════════╗
║             📧  OSINT EMAIL HARVESTER — SCRIPT #05                 ║
║               Python Security Toolkit • Phase 1: Recon             ║
╚════════════════════════════════════════════════════════════════════╝{Colors.RESET}
"""
    print(banner)


def display_results(results: Dict[str, Any], verify_mx: bool) -> None:
    """Print structured terminal report for harvested email intelligence."""
    print(f"\n{Colors.BOLD}Target URL    :{Colors.RESET} {Colors.GREEN}{results['target_url']}{Colors.RESET}")
    print(f"{Colors.BOLD}Base Domain   :{Colors.RESET} {results['base_domain']}")
    print(f"{Colors.BOLD}Pages Crawled :{Colors.RESET} {results['pages_crawled']}")
    print(f"{Colors.BOLD}Total Harvested:{Colors.RESET} {Colors.BOLD}{results['total_emails_found']}{Colors.RESET} emails ("
          f"{Colors.GREEN}{results['internal_count']} internal{Colors.RESET}, "
          f"{Colors.YELLOW}{results['external_count']} external{Colors.RESET})\n")

    # ── Internal Domain Emails ───────────────────────────────────────────
    print(f"{Colors.CYAN}{Colors.BOLD}━━━ TARGET DOMAIN EMAILS ({results['internal_count']}) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}")
    if results["internal_emails"]:
        for item in results["internal_emails"]:
            mx_badge = ""
            if verify_mx:
                if item["mx_valid"] is True:
                    mx_badge = f" {Colors.GREEN}[MX: Valid]{Colors.RESET}"
                elif item["mx_valid"] is False:
                    mx_badge = f" {Colors.RED}[MX: Invalid]{Colors.RESET}"
                else:
                    mx_badge = f" {Colors.DIM}[MX: Unknown]{Colors.RESET}"

            first_source = item["sources"][0] if item["sources"] else ""
            print(f"  {Colors.GREEN}✔{Colors.RESET} {Colors.BOLD}{item['email']}{Colors.RESET}{mx_badge}")
            print(f"    {Colors.DIM}Source: {first_source} ({item['source_count']} page(s)){Colors.RESET}")
    else:
        print(f"  {Colors.DIM}(No target domain email addresses discovered){Colors.RESET}")
    print()

    # ── External Discovered Emails ───────────────────────────────────────
    print(f"{Colors.CYAN}{Colors.BOLD}━━━ EXTERNAL / THIRD-PARTY EMAILS ({results['external_count']}) ━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}")
    if results["external_emails"]:
        for item in results["external_emails"]:
            mx_badge = ""
            if verify_mx:
                if item["mx_valid"] is True:
                    mx_badge = f" {Colors.GREEN}[MX: Valid]{Colors.RESET}"
                elif item["mx_valid"] is False:
                    mx_badge = f" {Colors.RED}[MX: Invalid]{Colors.RESET}"
                else:
                    mx_badge = f" {Colors.DIM}[MX: Unknown]{Colors.RESET}"

            first_source = item["sources"][0] if item["sources"] else ""
            print(f"  {Colors.YELLOW}•{Colors.RESET} {item['email']}{mx_badge}  {Colors.DIM}(domain: {item['domain']}){Colors.RESET}")
            print(f"    {Colors.DIM}Source: {first_source}{Colors.RESET}")
    else:
        print(f"  {Colors.DIM}(No external email addresses discovered){Colors.RESET}")

    print(f"\n{Colors.DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="OSINT Email Harvester & Validator (Script #05 in Python Security Toolkit)",
        epilog="Examples:\n"
               "  python recon/email_harvester.py https://example.com\n"
               "  python recon/email_harvester.py example.com --depth 2 --max-pages 25\n"
               "  python recon/email_harvester.py example.com --verify-mx\n"
               "  python recon/email_harvester.py example.com --json",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", help="Target URL or domain (e.g. example.com or https://example.com)")
    parser.add_argument("-d", "--depth", type=int, default=2, help="Crawl depth limit (default: 2)")
    parser.add_argument("-m", "--max-pages", type=int, default=15, help="Maximum number of pages to crawl (default: 15)")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="HTTP request timeout in seconds (default: 10)")
    parser.add_argument("--verify-mx", action="store_true", help="Perform DNS MX record verification on email domains")
    parser.add_argument("-j", "--json", action="store_true", help="Output results in structured JSON format")

    args = parser.parse_args()

    start_url, base_domain = normalize_target(args.target)

    if not base_domain:
        print(f"{Colors.RED}[!] Invalid target hostname provided.{Colors.RESET}", file=sys.stderr)
        sys.exit(1)

    if not args.json:
        print_banner()
        print(f"{Colors.DIM}[*] Target Host  : {base_domain}{Colors.RESET}")
        print(f"{Colors.DIM}[*] Start URL    : {start_url}{Colors.RESET}")
        print(f"{Colors.DIM}[*] Crawl Limit  : Depth {args.depth}, Max {args.max_pages} pages{Colors.RESET}")
        if args.verify_mx:
            print(f"{Colors.DIM}[*] MX Check     : Enabled{Colors.RESET}")
        print(f"{Colors.DIM}[*] Initiating crawl...{Colors.RESET}\n")

    results = crawl_and_harvest(
        start_url=start_url,
        base_domain=base_domain,
        max_depth=args.depth,
        max_pages=args.max_pages,
        timeout=args.timeout,
        verify_mx=args.verify_mx,
        verbose=not args.json,
    )

    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
    else:
        display_results(results, verify_mx=args.verify_mx)


if __name__ == "__main__":
    main()
