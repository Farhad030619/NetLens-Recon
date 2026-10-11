# NetLens-Recon

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Playwright](https://img.shields.io/badge/playwright-async-green.svg)](https://playwright.dev/)
[![Tests](https://img.shields.io/badge/tests-10%20passed-brightgreen.svg)](tests/)
[![License](https://img.shields.io/badge/license-MIT-purple.svg)](LICENSE)

Asynchronous attack surface discovery and visual inspection engine for enterprise networks. Built for penetration testing, red teaming, and network security audits across large domain, IP, and CIDR ranges.

Developed by **Farhad Jelve** (B.Sc. Electrical Engineering, KTH Royal Institute of Technology | Cisco CCNP Enterprise Core certified).

---

## Technical Overview

When auditing large enterprise networks with hundreds of endpoints and subdomains, inspecting web interfaces manually is inefficient and prone to missed targets. NetLens-Recon automates discovery through five coordinated stages:

1. **Network Probing:** Rapid asynchronous port pre-filtering across standard and non-standard web ports using aiohttp and aiodns.
2. **Headless Browser Capture:** Asynchronous Chromium rendering via Playwright to capture pixel-level viewports and extract DOM metadata.
3. **Visual Deduplication:** Computes perceptual image hashes (dHash) to group identical parking, default, or error pages, removing duplicate manual reviews.
4. **Target Classification:** Heuristically detects login forms, password inputs, and administrative portals (Grafana, Jenkins, phpMyAdmin, Cisco WebUI, Swagger).
5. **Triage Interface:** Generates a standalone HTML5/Tailwind dashboard with instant search, category filtering, and modal lightbox inspection.

---

## Architecture

```text
[Target Domains / IPs / CIDR]
             │
             ▼
  ┌──────────────────────┐
  │  Async Network Probe │  (aiohttp / aiodns port pre-filtering)
  └──────────┬───────────┘
             │ Active Endpoints
             ▼
  ┌──────────────────────┐
  │ Playwright Headless  │  (Async browser context pool)
  └──────────┬───────────┘
             │ Viewports + DOM + Headers
             ▼
  ┌──────────────────────┐
  │ Intelligence Engine  │  (Login detection, tech fingerprinting, dHash)
  └──────────┬───────────┘
             │ Structured Recon Data
             ▼
  ┌──────────────────────┐
  │ Interactive Gallery  │  (Standalone HTML5/Tailwind Dark Dashboard)
  └──────────────────────┘
```

---

## Setup and Usage

### 1. Installation
```bash
git clone https://github.com/Farhad030619/NetLens-Recon.git
cd NetLens-Recon

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
playwright install chromium
```

### 2. Run Test Suite
```bash
pytest tests/ -v
```

### 3. Usage Examples
```bash
# Scan a single domain or URL
python3 -m src.cli scan https://example.com

# Scan multiple targets from file with 10 concurrent browser workers
python3 -m src.cli scan -f targets.txt --concurrency 10 --output ./output
```

---

## Author
**Farhad Jelve**
- **Education:** B.Sc. Electrical Engineering, KTH Royal Institute of Technology
- **Certifications:** Cisco Certified Network Professional (CCNP Enterprise) and CCNA
- **Specialization:** Network Security, Network Automation, Async Systems
- **LinkedIn:** [Farhad Jelve](https://www.linkedin.com/in/farhad-jelve-9771a1270/)
