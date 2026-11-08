#!/usr/bin/env python3
"""
=============================================================================
web_recon.py — Script #04 in Python Security Toolkit
Phase 1: Reconnaissance
=============================================================================
Web reconnaissance and security header analysis tool.  Fingerprints server
technology, audits HTTP security headers (CSP, HSTS, X-Frame-Options, etc.),
parses robots.txt disallowed paths, probes sitemap.xml, and inspects cookie
security attributes — all from a single target URL.

Concepts Covered:
    • HTTP response header analysis & server fingerprinting
    • Security header best-practice auditing (OWASP recommendations)
    • robots.txt & sitemap.xml parsing for hidden-path discovery
    • Cookie attribute inspection (Secure, HttpOnly, SameSite)
    • HTML meta-tag technology detection

Usage:
    python recon/web_recon.py https://example.com
    python recon/web_recon.py example.com --timeout 15
    python recon/web_recon.py example.com --json
=============================================================================
"""

import argparse
import json
import re
import sys
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

# Ensure UTF-8 output encoding across Windows terminals
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

try:
    import requests
    from requests.exceptions import ConnectionError, Timeout, RequestException
except ImportError:
    print("[!] 'requests' library is required. Install with: pip install requests", file=sys.stderr)
    sys.exit(1)

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False


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


# ── Security Header Definitions ─────────────────────────────────────────────
# Each entry: (header_name, description, severity_if_missing)
SECURITY_HEADERS = [
    ("Strict-Transport-Security", "HSTS — forces HTTPS connections, prevents downgrade attacks", "HIGH"),
    ("Content-Security-Policy", "CSP — mitigates XSS and injection attacks via content source whitelisting", "HIGH"),
    ("X-Frame-Options", "Clickjacking protection — prevents page embedding in iframes", "MEDIUM"),
    ("X-Content-Type-Options", "MIME-sniffing protection — must be 'nosniff'", "MEDIUM"),
    ("X-XSS-Protection", "Legacy XSS filter (deprecated in modern browsers, but still checked)", "LOW"),
    ("Referrer-Policy", "Controls referrer information leakage to third parties", "LOW"),
    ("Permissions-Policy", "Controls browser feature access (camera, geolocation, etc.)", "LOW"),
    ("Cross-Origin-Opener-Policy", "COOP — isolates browsing context from cross-origin documents", "LOW"),
    ("Cross-Origin-Resource-Policy", "CORP — restricts cross-origin resource loading", "LOW"),
    ("Cross-Origin-Embedder-Policy", "COEP — requires cross-origin resources to grant permission", "LOW"),
]

# Common server technology signatures found in headers
SERVER_SIGNATURES = {
    "apache": "Apache HTTP Server",
    "nginx": "Nginx",
    "iis": "Microsoft IIS",
    "lighttpd": "Lighttpd",
    "cloudflare": "Cloudflare CDN",
    "gunicorn": "Gunicorn (Python WSGI)",
    "uvicorn": "Uvicorn (Python ASGI)",
    "express": "Express.js (Node.js)",
    "kestrel": "Kestrel (.NET)",
    "openresty": "OpenResty (Nginx+Lua)",
    "litespeed": "LiteSpeed",
    "caddy": "Caddy Server",
    "tomcat": "Apache Tomcat (Java)",
    "jetty": "Eclipse Jetty (Java)",
    "werkzeug": "Werkzeug (Python/Flask)",
    "cowboy": "Cowboy (Erlang)",
    "envoy": "Envoy Proxy",
}


def normalize_url(target: str) -> str:
    """Ensure target has a scheme, defaulting to https://."""
    target = target.strip()
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    # Strip trailing slashes for consistency
    return target.rstrip("/")


def fetch_page(url: str, timeout: int) -> Optional[requests.Response]:
    """Fetch a URL with error handling. Returns Response or None."""
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers={"User-Agent": "PythonSecurityToolkit/1.0 (educational recon)"},
            verify=True,
        )
        return resp
    except Timeout:
        return None
    except ConnectionError:
        return None
    except RequestException:
        return None


def identify_server(headers: Dict[str, str]) -> List[str]:
    """Extract server technology information from response headers."""
    techs: List[str] = []

    server = headers.get("Server", "")
    if server:
        techs.append(f"Server: {server}")
        for sig, name in SERVER_SIGNATURES.items():
            if sig.lower() in server.lower():
                techs.append(f"Identified: {name}")
                break

    powered_by = headers.get("X-Powered-By", "")
    if powered_by:
        techs.append(f"X-Powered-By: {powered_by}")

    asp_version = headers.get("X-AspNet-Version", "")
    if asp_version:
        techs.append(f"ASP.NET Version: {asp_version}")

    asp_mvc = headers.get("X-AspNetMvc-Version", "")
    if asp_mvc:
        techs.append(f"ASP.NET MVC: {asp_mvc}")

    generator = headers.get("X-Generator", "")
    if generator:
        techs.append(f"Generator: {generator}")

    via = headers.get("Via", "")
    if via:
        techs.append(f"Via (proxy): {via}")

    return techs


def audit_security_headers(headers: Dict[str, str]) -> List[Dict[str, str]]:
    """Audit response headers against security best practices."""
    findings: List[Dict[str, str]] = []

    for header_name, description, severity in SECURITY_HEADERS:
        value = headers.get(header_name)
        if value:
            status = "PRESENT"
            finding = {
                "header": header_name,
                "status": status,
                "value": value,
                "severity": "INFO",
                "description": description,
            }

            # Extra validation for specific headers
            if header_name == "X-Content-Type-Options" and value.lower() != "nosniff":
                finding["status"] = "MISCONFIGURED"
                finding["severity"] = "MEDIUM"
                finding["note"] = f"Expected 'nosniff', got '{value}'"

            if header_name == "X-Frame-Options":
                valid = ["deny", "sameorigin"]
                if value.lower() not in valid:
                    finding["status"] = "MISCONFIGURED"
                    finding["severity"] = "MEDIUM"
                    finding["note"] = f"Expected DENY or SAMEORIGIN, got '{value}'"
        else:
            finding = {
                "header": header_name,
                "status": "MISSING",
                "value": None,
                "severity": severity,
                "description": description,
            }

        findings.append(finding)

    return findings


def analyze_cookies(response: requests.Response) -> List[Dict[str, Any]]:
    """Inspect Set-Cookie headers and response cookies for security attributes."""
    cookie_findings: List[Dict[str, Any]] = []

    # Gather cookies from both redirect history and final response
    cookies_to_inspect = []
    seen_names = set()
    for hist in getattr(response, "history", []):
        for cookie in hist.cookies:
            if cookie.name not in seen_names:
                cookies_to_inspect.append(cookie)
                seen_names.add(cookie.name)
    for cookie in response.cookies:
        if cookie.name not in seen_names:
            cookies_to_inspect.append(cookie)
            seen_names.add(cookie.name)

    if not cookies_to_inspect:
        return cookie_findings

    for cookie in cookies_to_inspect:
        httponly = bool(
            cookie.has_nonstandard_attr("httponly")
            or cookie.has_nonstandard_attr("HttpOnly")
            or "httponly" in [k.lower() for k in getattr(cookie, "_rest", {}).keys()]
        )

        samesite = None
        for key, val in getattr(cookie, "_rest", {}).items():
            if key.lower() == "samesite":
                samesite = val if val else "Present"
                break

        entry: Dict[str, Any] = {
            "name": cookie.name,
            "domain": cookie.domain,
            "path": cookie.path,
            "secure": bool(cookie.secure),
            "httponly": httponly,
            "samesite": samesite,
            "issues": [],
        }

        is_https = response.url.startswith("https")
        if not cookie.secure and is_https:
            entry["issues"].append("Missing 'Secure' flag — cookie sent over HTTP")
        if not httponly:
            entry["issues"].append("Missing 'HttpOnly' flag — accessible to JavaScript (XSS risk)")
        if not samesite:
            entry["issues"].append("Missing 'SameSite' attribute — susceptible to CSRF")

        cookie_findings.append(entry)

    return cookie_findings



def fetch_robots_txt(base_url: str, timeout: int) -> Optional[Dict[str, Any]]:
    """Fetch and parse robots.txt for disallowed paths (hidden content discovery)."""
    url = urljoin(base_url + "/", "robots.txt")
    resp = fetch_page(url, timeout)
    if not resp or resp.status_code != 200:
        return None

    lines = resp.text.splitlines()
    disallowed: List[str] = []
    allowed: List[str] = []
    sitemaps: List[str] = []

    for line in lines:
        line = line.strip()
        if line.lower().startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path:
                disallowed.append(path)
        elif line.lower().startswith("allow:"):
            path = line.split(":", 1)[1].strip()
            if path:
                allowed.append(path)
        elif line.lower().startswith("sitemap:"):
            sm = line.split(":", 1)[1].strip()
            # Reassemble if the split broke the URL scheme
            if sm and not sm.startswith("http"):
                sm = ":" + sm  # fixup "https" split
                sm = line[len("sitemap:"):].strip()
            else:
                sm = line.split(" ", 1)[-1].strip() if " " in line else line.split(":", 1)[1].strip()
            # Better: just grab everything after "Sitemap:"
            sm = line[line.lower().index("sitemap:") + 8:].strip()
            if sm:
                sitemaps.append(sm)

    return {
        "url": url,
        "disallowed": disallowed,
        "allowed": allowed,
        "sitemaps": sitemaps,
        "total_rules": len(disallowed) + len(allowed),
    }


def fetch_sitemap(base_url: str, timeout: int) -> Optional[Dict[str, Any]]:
    """Probe sitemap.xml for indexed URL count."""
    url = urljoin(base_url + "/", "sitemap.xml")
    resp = fetch_page(url, timeout)
    if not resp or resp.status_code != 200:
        return None

    # Count <url> or <loc> tags in the sitemap XML
    content = resp.text
    loc_count = len(re.findall(r"<loc>", content, re.IGNORECASE))
    sitemap_count = len(re.findall(r"<sitemap>", content, re.IGNORECASE))

    return {
        "url": url,
        "url_count": loc_count,
        "sitemap_index_count": sitemap_count,
        "is_index": sitemap_count > 0,
    }


def detect_technologies_html(html: str) -> List[str]:
    """Detect technologies from HTML meta tags and script references."""
    techs: List[str] = []

    if not HAS_BS4:
        # Fallback regex detection without BeautifulSoup
        gen_match = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)', html, re.IGNORECASE)
        if gen_match:
            techs.append(f"Generator: {gen_match.group(1)}")
        return techs

    soup = BeautifulSoup(html, "html.parser")

    # Meta generator tag (WordPress, Drupal, Joomla, etc.)
    gen = soup.find("meta", attrs={"name": re.compile(r"generator", re.I)})
    if gen and gen.get("content"):
        techs.append(f"Generator: {gen['content']}")

    # Common framework indicators
    framework_indicators = {
        "wp-content": "WordPress",
        "wp-includes": "WordPress",
        "drupal": "Drupal",
        "joomla": "Joomla",
        "react": "React.js",
        "vue": "Vue.js",
        "angular": "Angular",
        "next.js": "Next.js",
        "nuxt": "Nuxt.js",
        "bootstrap": "Bootstrap CSS",
        "tailwind": "Tailwind CSS",
        "jquery": "jQuery",
        "shopify": "Shopify",
        "squarespace": "Squarespace",
        "wix": "Wix",
    }

    html_lower = html.lower()
    detected = set()
    for indicator, name in framework_indicators.items():
        if indicator in html_lower and name not in detected:
            techs.append(f"Detected: {name}")
            detected.add(name)

    return techs


def calculate_security_score(findings: List[Dict[str, str]]) -> Dict[str, Any]:
    """Calculate a security score based on header audit results."""
    total = len(findings)
    present = sum(1 for f in findings if f["status"] == "PRESENT")
    missing_high = sum(1 for f in findings if f["status"] == "MISSING" and f["severity"] == "HIGH")
    missing_medium = sum(1 for f in findings if f["status"] == "MISSING" and f["severity"] == "MEDIUM")
    misconfigured = sum(1 for f in findings if f["status"] == "MISCONFIGURED")

    # Scoring: start at 100, deduct for issues
    score = 100
    score -= missing_high * 20
    score -= missing_medium * 10
    score -= misconfigured * 15
    score -= (total - present - missing_high - missing_medium - misconfigured) * 5
    score = max(0, min(100, score))

    if score >= 80:
        grade = "A"
    elif score >= 60:
        grade = "B"
    elif score >= 40:
        grade = "C"
    elif score >= 20:
        grade = "D"
    else:
        grade = "F"

    return {"score": score, "grade": grade, "present": present, "total": total}


def print_banner() -> None:
    banner = f"""{Colors.CYAN}{Colors.BOLD}
╔════════════════════════════════════════════════════════════════════╗
║          🌐  WEB RECONNAISSANCE & HEADER AUDIT — SCRIPT #04       ║
║               Python Security Toolkit • Phase 1: Recon             ║
╚════════════════════════════════════════════════════════════════════╝{Colors.RESET}
"""
    print(banner)


def display_results(target_url: str, report: Dict[str, Any]) -> None:
    """Print beautifully formatted web reconnaissance report."""
    print(f"{Colors.BOLD}Target URL    :{Colors.RESET} {Colors.GREEN}{target_url}{Colors.RESET}")
    print(f"{Colors.BOLD}Final URL     :{Colors.RESET} {report.get('final_url', 'N/A')}")
    print(f"{Colors.BOLD}Status Code   :{Colors.RESET} {report.get('status_code', 'N/A')}")
    print()

    # ── Server Technology ────────────────────────────────────────────────
    techs = report.get("technologies", [])
    print(f"{Colors.CYAN}{Colors.BOLD}━━━ SERVER TECHNOLOGY ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}")
    if techs:
        for t in techs:
            print(f"  • {t}")
    else:
        print(f"  {Colors.DIM}(No server technology identified — headers may be stripped){Colors.RESET}")
    print()

    # ── Security Headers Audit ───────────────────────────────────────────
    findings = report.get("security_headers", [])
    score_info = report.get("security_score", {})
    grade = score_info.get("grade", "?")
    score = score_info.get("score", 0)

    grade_color = Colors.GREEN if grade in ("A", "B") else Colors.YELLOW if grade == "C" else Colors.RED

    print(f"{Colors.CYAN}{Colors.BOLD}━━━ SECURITY HEADERS AUDIT ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}")
    print(f"  {Colors.BOLD}Security Grade :{Colors.RESET} {grade_color}{Colors.BOLD}{grade} ({score}/100){Colors.RESET}")
    print(f"  {Colors.BOLD}Headers Present:{Colors.RESET} {score_info.get('present', 0)}/{score_info.get('total', 0)}\n")

    for f in findings:
        if f["status"] == "PRESENT":
            icon = f"{Colors.GREEN}✔{Colors.RESET}"
            val_display = f" → {Colors.DIM}{f['value'][:80]}{Colors.RESET}" if f.get("value") else ""
        elif f["status"] == "MISCONFIGURED":
            icon = f"{Colors.YELLOW}⚠{Colors.RESET}"
            val_display = f" → {Colors.YELLOW}{f.get('note', f['value'])}{Colors.RESET}"
        else:
            sev_color = Colors.RED if f["severity"] == "HIGH" else Colors.YELLOW if f["severity"] == "MEDIUM" else Colors.DIM
            icon = f"{sev_color}✘{Colors.RESET}"
            val_display = f"  {sev_color}[{f['severity']}]{Colors.RESET}"
        print(f"  {icon} {Colors.BOLD}{f['header']}{Colors.RESET}{val_display}")
    print()

    # ── Cookies ──────────────────────────────────────────────────────────
    cookies = report.get("cookies", [])
    if cookies:
        print(f"{Colors.CYAN}{Colors.BOLD}━━━ COOKIE SECURITY ({len(cookies)}) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}")
        for c in cookies:
            secure_flag = f"{Colors.GREEN}✔ Secure{Colors.RESET}" if c.get("secure") else f"{Colors.RED}✘ No Secure{Colors.RESET}"
            http_flag = f"{Colors.GREEN}✔ HttpOnly{Colors.RESET}" if c.get("httponly") else f"{Colors.YELLOW}✘ No HttpOnly{Colors.RESET}"
            samesite_val = c.get("samesite")
            samesite_flag = f"{Colors.GREEN}✔ SameSite={samesite_val}{Colors.RESET}" if samesite_val else f"{Colors.YELLOW}✘ No SameSite{Colors.RESET}"
            print(f"  {Colors.BOLD}{c['name']}{Colors.RESET}  {secure_flag}  {http_flag}  {samesite_flag}")
            for issue in c.get("issues", []):
                print(f"    {Colors.YELLOW}⚠ {issue}{Colors.RESET}")
        print()

    # ── robots.txt ───────────────────────────────────────────────────────
    robots = report.get("robots_txt")
    if robots:
        print(f"{Colors.CYAN}{Colors.BOLD}━━━ ROBOTS.TXT ({robots['total_rules']} rules) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}")
        disallowed = robots.get("disallowed", [])
        if disallowed:
            print(f"  {Colors.BOLD}Disallowed paths (interesting for recon):{Colors.RESET}")
            for path in disallowed[:20]:  # Cap display at 20
                print(f"    {Colors.YELLOW}• {path}{Colors.RESET}")
            if len(disallowed) > 20:
                print(f"    {Colors.DIM}... and {len(disallowed) - 20} more{Colors.RESET}")
        sitemaps = robots.get("sitemaps", [])
        if sitemaps:
            print(f"  {Colors.BOLD}Sitemaps referenced:{Colors.RESET}")
            for sm in sitemaps:
                print(f"    • {sm}")
        print()
    else:
        print(f"{Colors.DIM}  [robots.txt] Not found or not accessible{Colors.RESET}\n")

    # ── Sitemap ──────────────────────────────────────────────────────────
    sitemap = report.get("sitemap")
    if sitemap:
        kind = "Sitemap Index" if sitemap.get("is_index") else "URL Sitemap"
        count = sitemap.get("sitemap_index_count") if sitemap.get("is_index") else sitemap.get("url_count")
        print(f"{Colors.CYAN}{Colors.BOLD}━━━ SITEMAP.XML ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}")
        print(f"  Type: {kind}  |  Entries: {count}")
        print()

    print(f"{Colors.DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Web Reconnaissance & Security Header Audit (Script #04 in Python Security Toolkit)",
        epilog="Examples:\n"
               "  python recon/web_recon.py https://example.com\n"
               "  python recon/web_recon.py example.com --json\n"
               "  python recon/web_recon.py example.com --timeout 15",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", help="Target URL or domain (e.g. https://example.com or example.com)")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="HTTP request timeout in seconds (default: 10)")
    parser.add_argument("-j", "--json", action="store_true", help="Output results in structured JSON format")

    args = parser.parse_args()
    target_url = normalize_url(args.target)

    if not args.json:
        print_banner()
        print(f"{Colors.DIM}[*] Target: {target_url}{Colors.RESET}")
        print(f"{Colors.DIM}[*] Fetching main page...{Colors.RESET}")

    # ── Fetch the main page ──────────────────────────────────────────────
    resp = fetch_page(target_url, args.timeout)
    if not resp:
        # Try HTTP fallback if HTTPS failed
        if target_url.startswith("https://"):
            fallback = target_url.replace("https://", "http://", 1)
            if not args.json:
                print(f"{Colors.YELLOW}[!] HTTPS failed, trying HTTP...{Colors.RESET}")
            resp = fetch_page(fallback, args.timeout)
            if resp:
                target_url = fallback

    if not resp:
        msg = f"Could not connect to '{target_url}'. Check the URL and your network connection."
        if args.json:
            print(json.dumps({"error": msg}))
        else:
            print(f"{Colors.RED}[!] {msg}{Colors.RESET}", file=sys.stderr)
        sys.exit(1)

    headers = dict(resp.headers)

    # ── Build report ─────────────────────────────────────────────────────
    report: Dict[str, Any] = {
        "target": target_url,
        "final_url": resp.url,
        "status_code": resp.status_code,
    }

    # Server technology fingerprinting
    if not args.json:
        print(f"{Colors.DIM}[*] Analyzing server headers...{Colors.RESET}")
    server_techs = identify_server(headers)
    html_techs = detect_technologies_html(resp.text) if resp.text else []
    report["technologies"] = server_techs + html_techs

    # Security header audit
    if not args.json:
        print(f"{Colors.DIM}[*] Auditing security headers...{Colors.RESET}")
    findings = audit_security_headers(headers)
    report["security_headers"] = findings
    report["security_score"] = calculate_security_score(findings)

    # Cookie analysis
    cookies = analyze_cookies(resp)
    report["cookies"] = cookies

    # robots.txt
    if not args.json:
        print(f"{Colors.DIM}[*] Checking robots.txt...{Colors.RESET}")
    robots = fetch_robots_txt(target_url, args.timeout)
    report["robots_txt"] = robots

    # sitemap.xml
    if not args.json:
        print(f"{Colors.DIM}[*] Probing sitemap.xml...{Colors.RESET}")
    sitemap = fetch_sitemap(target_url, args.timeout)
    report["sitemap"] = sitemap

    # ── Output ───────────────────────────────────────────────────────────
    if args.json:
        # Clean None values from security_headers for cleaner JSON
        for f in report["security_headers"]:
            if f["value"] is None:
                del f["value"]
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print()
        display_results(target_url, report)


if __name__ == "__main__":
    main()
