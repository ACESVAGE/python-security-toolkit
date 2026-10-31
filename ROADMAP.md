# 🛡️ Python Security Toolkit — Learning Roadmap

> Scripts are written and pushed daily. Each one builds on the last.
> Repository: [ACESVAGE/python-security-toolkit](https://github.com/ACESVAGE/python-security-toolkit)

---

## 🔍 Phase 1 — Reconnaissance
*Gather intelligence before you attack. Learn passive and active recon techniques.*

| # | Script | Folder | Concepts Covered | Status |
|---|--------|--------|-----------------|--------|
| 1 | `whois_lookup.py` | `recon/` | WHOIS queries, domain registration info, registrar data | ✅ Done |
| 2 | `dns_resolver.py` | `recon/` | A/AAAA/MX/NS/TXT records, reverse DNS, zone info | ✅ Done |
| 3 | `subdomain_enum.py` | `recon/` | Wordlist brute-force, DNS resolution, concurrent scanning | ⏳ Next |
| 4 | `web_recon.py` | `recon/` | HTTP headers, robots.txt, sitemap, tech fingerprinting | ⬜ |
| 5 | `email_harvester.py` | `recon/` | Scrape emails from pages, OSINT gathering, validation | ⬜ |

---

## 🌐 Phase 2 — Network Scanning
*Map the network. Discover hosts, ports, and services.*

| # | Script | Folder | Concepts Covered | Status |
|---|--------|--------|-----------------|--------|
| 6 | `host_discovery.py` | `scanning/` | ICMP ping sweep, ARP scanning, alive host detection | ⬜ |
| 7 | `port_scanner.py` | `scanning/` | TCP connect/SYN scan, common ports, service detection | ⬜ |
| 8 | `banner_grabber.py` | `scanning/` | Socket connections, service version fingerprinting | ⬜ |
| 9 | `network_mapper.py` | `scanning/` | Subnet enumeration, OS detection, topology mapping | ⬜ |
| 10 | `vuln_scanner.py` | `scanning/` | CVE lookup, NSE script integration, risk scoring | ⬜ |

---

## 🔐 Phase 3 — System Hardening & Auditing
*Lock it down. Audit configurations and enforce security policies.*

| # | Script | Folder | Concepts Covered | Status |
|---|--------|--------|-----------------|--------|
| 11 | `password_auditor.py` | `hardening/` | Strength checking, dictionary attacks, policy enforcement | ⬜ |
| 12 | `ssh_config_checker.py` | `hardening/` | SSH config parsing, best practices audit, key management | ⬜ |
| 13 | `open_ports_audit.py` | `hardening/` | Listening services, unexpected ports, firewall rule check | ⬜ |
| 14 | `file_permissions_audit.py` | `hardening/` | SUID/SGID scan, world-writable files, permission report | ⬜ |
| 15 | `ssl_cert_checker.py` | `hardening/` | Certificate expiry, chain validation, cipher strength | ⬜ |

---

## 📊 Phase 4 — Threat Detection & Log Analysis
*Detect attacks. Parse logs and hunt for anomalies.*

| # | Script | Folder | Concepts Covered | Status |
|---|--------|--------|-----------------|--------|
| 16 | `failed_login_detector.py` | `log-analysis/` | auth.log parsing, brute-force pattern detection | ⬜ |
| 17 | `log_parser.py` | `log-analysis/` | Multi-format parsing (syslog, JSON, CSV), filtering | ⬜ |
| 18 | `intrusion_detector.py` | `log-analysis/` | Anomaly detection, suspicious pattern matching, alerts | ⬜ |
| 19 | `file_integrity_checker.py` | `log-analysis/` | SHA-256 baselines, change detection, tamper alerts | ⬜ |
| 20 | `network_traffic_analyzer.py` | `log-analysis/` | Packet capture parsing, traffic stats, connection tracking | ⬜ |

---

## 🔓 Phase 5 — Cryptography & CTF Tools
*Master the crypto. Build tools for encoding, hashing, and CTF challenges.*

| # | Script | Folder | Concepts Covered | Status |
|---|--------|--------|-----------------|--------|
| 21 | `hash_identifier.py` | `crypto/` | Hash type detection, length analysis, algorithm matching | ⬜ |
| 22 | `hash_cracker.py` | `crypto/` | Dictionary & brute-force attacks, rainbow table concepts | ⬜ |
| 23 | `cipher_tools.py` | `crypto/` | Caesar, Vigenère, ROT13, XOR — encode & decode | ⬜ |
| 24 | `encoding_converter.py` | `crypto/` | Base64, hex, URL, binary — multi-format converter | ⬜ |
| 25 | `steganography_tool.py` | `crypto/` | Hide/extract data in images, LSB technique | ⬜ |

---

## ⚙️ Phase 6 — Automation & Reporting
*Tie it all together. Automate scans and generate professional reports.*

| # | Script | Folder | Concepts Covered | Status |
|---|--------|--------|-----------------|--------|
| 26 | `security_report.py` | `automation/` | Full system audit report, HTML/PDF output | ⬜ |
| 27 | `vuln_alert.py` | `automation/` | CVE feed monitoring, email/Slack notifications | ⬜ |
| 28 | `scheduled_scanner.py` | `automation/` | Cron-based scanning, diff reports, change alerts | ⬜ |
| 29 | `incident_responder.py` | `automation/` | Automated triage, evidence collection, timeline builder | ⬜ |
| 30 | `toolkit_cli.py` | `automation/` | Unified CLI for all tools, argparse, interactive menu | ⬜ |

---

## 🗓️ Daily Session Format

Each session we will:
1. **Review** the previous script briefly
2. **Write** the next script with full explanations
3. **Commit** it to the correct folder in GitHub
4. **Update** this roadmap (mark ✅)

---

## 🔑 Legend
| Symbol | Meaning |
|--------|---------|
| ✅ Done | Script written, committed, and reviewed |
| ⏳ Next | This is the next script to be written |
| ⬜ Queued | Scheduled for a future session |

---

*Last updated: 2026-10-31 • Roadmap version 1.0*
