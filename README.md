# 🛡️ Python Security Toolkit

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Scripts](https://img.shields.io/badge/Scripts-0%2F30-orange)](ROADMAP.md)

> A growing Python toolkit for cybersecurity & security analysis — built on my journey to becoming a Security Analyst.

---

## 📋 What Is This?

A collection of **30 Python scripts** covering the full security lifecycle — from reconnaissance and scanning to threat detection and automated reporting. Each script is written, studied, and committed daily as part of a structured learning path.

**🗺️ [View the Full Roadmap →](ROADMAP.md)**

---

## 📂 Project Structure

```
python-security-toolkit/
│
├── recon/                # 🔍 Phase 1 — Reconnaissance
│   ├── whois_lookup.py         # WHOIS domain intelligence
│   ├── dns_resolver.py         # DNS record enumeration
│   ├── subdomain_enum.py       # Subdomain brute-forcing
│   ├── web_recon.py            # Web technology fingerprinting
│   └── email_harvester.py      # OSINT email gathering
│
├── scanning/             # 🌐 Phase 2 — Network Scanning
│   ├── host_discovery.py       # Ping sweep & ARP scanning
│   ├── port_scanner.py         # TCP/UDP port scanning
│   ├── banner_grabber.py       # Service version detection
│   ├── network_mapper.py       # Network topology mapping
│   └── vuln_scanner.py         # Vulnerability assessment
│
├── hardening/            # 🔐 Phase 3 — System Hardening
│   ├── password_auditor.py     # Password strength analysis
│   ├── ssh_config_checker.py   # SSH security audit
│   ├── open_ports_audit.py     # Unexpected port detection
│   ├── file_permissions_audit.py # SUID/SGID permission scan
│   └── ssl_cert_checker.py     # SSL/TLS certificate validation
│
├── log-analysis/         # 📊 Phase 4 — Threat Detection
│   ├── failed_login_detector.py # Brute-force detection
│   ├── log_parser.py           # Multi-format log analysis
│   ├── intrusion_detector.py   # Anomaly pattern matching
│   ├── file_integrity_checker.py # File tamper detection
│   └── network_traffic_analyzer.py # Packet analysis
│
├── crypto/               # 🔓 Phase 5 — Cryptography & CTF
│   ├── hash_identifier.py      # Hash type detection
│   ├── hash_cracker.py         # Dictionary/brute-force cracking
│   ├── cipher_tools.py         # Classical cipher toolkit
│   ├── encoding_converter.py   # Multi-format encoder/decoder
│   └── steganography_tool.py   # Image steganography
│
├── automation/           # ⚙️ Phase 6 — Automation & Reporting
│   ├── security_report.py      # Full audit report generator
│   ├── vuln_alert.py           # CVE monitoring & alerts
│   ├── scheduled_scanner.py    # Automated scan scheduling
│   ├── incident_responder.py   # Incident triage automation
│   └── toolkit_cli.py          # Unified CLI interface
│
├── requirements.txt      # Python dependencies
├── ROADMAP.md            # 📍 Learning roadmap & progress
└── LICENSE               # MIT License
```

---

## 🚀 Getting Started

### Prerequisites
- Python 3.10 or higher
- pip (Python package manager)

### Installation

```bash
# Clone the repo
git clone https://github.com/ACESVAGE/python-security-toolkit.git
cd python-security-toolkit

# Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate   # Linux/Mac
venv\Scripts\activate      # Windows

# Install dependencies
pip install -r requirements.txt
```

### Usage

Each script is standalone and can be run directly:

```bash
python recon/whois_lookup.py example.com
python scanning/port_scanner.py 192.168.1.1
python crypto/hash_identifier.py 5f4dcc3b5aa765d61d8327deb882cf99
```

---

## ⚠️ Disclaimer

These tools are built for **educational purposes** and **authorized security testing only**. Never use these tools against systems you don't own or have explicit written permission to test. Unauthorized access to computer systems is illegal.

---

## 📈 Progress

| Phase | Category | Scripts | Status |
|-------|----------|---------|--------|
| 1 | Reconnaissance | 0/5 | 🔲 |
| 2 | Network Scanning | 0/5 | 🔲 |
| 3 | System Hardening | 0/5 | 🔲 |
| 4 | Threat Detection | 0/5 | 🔲 |
| 5 | Cryptography & CTF | 0/5 | 🔲 |
| 6 | Automation & Reporting | 0/5 | 🔲 |
| **Total** | | **0/30** | |

---

## 🤝 About

Built by **[ACESVAGE](https://github.com/ACESVAGE)** — aspiring Security Analyst with a developer's mindset.

Part of a daily coding discipline alongside [linux-admin-scripts](https://github.com/ACESVAGE/linux-admin-scripts).

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
