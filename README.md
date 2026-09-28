# 🛡️ NetLens-Recon

> **Next-Generation Visual Reconnaissance & Attack Surface Mapping Engine**  
> *Fast, asynchronous web asset probing, headless viewport capture, visual clustering, and automated vulnerability triage.*

---

## ⚡ Overview
**NetLens-Recon** is a high-throughput reconnaissance tool designed for penetration testers, red teamers, and network security engineers. When assessing large enterprise networks with hundreds of domains and subdomains, manually reviewing web interfaces is slow and prone to oversight. 

NetLens-Recon automates the entire discovery-to-triage workflow:
1. **Network-Aware Probing:** Rapid async pre-flight checks across standard and non-standard web ports.
2. **Headless Browser Capture:** Asynchronous Chromium rendering via Playwright to capture pixel-perfect viewports and extract deep DOM metadata.
3. **Visual Deduplication:** Computes perceptual image hashes (dHash) to group identical parking, default, or error pages, preventing analyst fatigue.
4. **Heuristic High-Value Target (HVT) Flagging:** Automatically detects login forms, password inputs, sensitive administrative portals (Grafana, Jenkins, phpMyAdmin, Cisco WebUI, Swagger).
5. **Interactive Dark-Mode Dashboard:** Generates a lightweight, zero-dependency HTML5/Tailwind triage interface with instant search, category filtering, and modal lightbox inspection.

---

## 🏗️ Architecture

```
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

## 🚀 Quick Start

### 1. Installation
```bash
# Clone the repository
git clone https://github.com/Farhad030619/NetLens-Recon.git
cd NetLens-Recon

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies & Playwright browser
pip install -r requirements.txt
playwright install chromium
```

### 2. Usage
```bash
# Scan a single domain or URL
python3 -m src.cli scan https://example.com

# Scan multiple targets from file with 10 concurrent browser workers
python3 -m src.cli scan -f targets.txt --concurrency 10 --output ./output
```

---

## 👤 Author
- **Farhad Jelve**  
  B.Sc. Electrical Engineering, KTH Royal Institute of Technology  
  Cisco Certified Network Professional (CCNP Enterprise) & CCNA  
  [LinkedIn](https://www.linkedin.com/in/farhad-jelve-9771a1270/) • [GitHub](https://github.com/Farhad030619)
