# 🛡️ NetLens-Recon: Technical Architecture & Development Spec

## 1. Project Overview & Inspiration
- **Inspired by:** "Recon Screenshot Platform" featured in *10 Cybersecurity Projects That'll Make You DANGEROUSLY Smart* (YouTube ID: `XvHi5aJmGpc` at 03:34).
- **Core Purpose:** An automated, high-throughput reconnaissance engine and visual attack-surface mapper. It ingests lists of targets (domains, URLs, CIDR IP blocks, or Nmap XML), asynchronously probes open web ports, captures high-resolution viewport screenshots with Playwright, fingerprints technologies, clusters visual duplicates via perceptual hashing, and generates an interactive web triage dashboard.
- **Author:** Farhad Jelve (B.Sc. Electrical Engineering at KTH, Cisco CCNP Enterprise, CCNA).

---

## 2. Technical Stack
- **Runtime:** Python 3.11+
- **Browser Automation:** `playwright` (async API with Chromium headless)
- **Networking & Probing:** `aiohttp`, `aiodns`, `asyncio`
- **DOM & Content Extraction:** `beautifulsoup4`
- **Visual Intelligence & Clustering:** `Pillow`, `imagehash` (difference / perceptual hashing for deduplicating default parking pages)
- **CLI & UX:** `rich`, `click` / `argparse`
- **Dashboard & Reporting:** `jinja2`, Tailwind CSS (single self-contained portable HTML report with modal gallery & fast search)

---

## 3. Pipeline Architecture
```
Targets (File / CLI / CIDR)
      │
      ▼
1. Pre-Flight Network Probe (async port & DNS filter: 80, 443, 8080, 8443)
      │
      ▼
2. Headless Browser Capture (Playwright Async Pool)
   - Viewport screenshot (1280x800)
   - HTTP Status code & redirect chains
   - TLS/SSL inspection
   - DOM Title & Meta tags extraction
      │
      ▼
3. Intelligence & Heuristic Analyzer
   - Login / Admin Portal Detection (password inputs, login forms, admin keywords)
   - Tech Stack Fingerprinting (Server, X-Powered-By, standard JS libraries)
   - Perceptual Image Hashing (dHash) to cluster visual clones (e.g. 50 Cloudflare default 404s)
      │
      ▼
4. Report & Dashboard Engine
   - Self-contained HTML gallery with dark mode
   - Filter by: Status (200, 30x, 40x, 50x), High Value Targets (HVT), Tech Stack
   - Search bar & Fullscreen screenshot lightbox
```

---

## 4. Key Differentiating Features
1. **Asynchronous Parallel Pool:** Can scan hundreds of web endpoints in seconds using controlled concurrency (`asyncio.Semaphore`).
2. **Visual Clustering (Anti-Fatigue):** Security analysts hate reviewing 100 identical default pages. NetLens clusters visual duplicates so you only review unique visual surfaces.
3. **High-Value Target (HVT) Flagging:** Automatically tags pages with login inputs (`<input type="password">`), admin panels (Grafana, Jenkins, phpMyAdmin, Cisco WebUI, Spring Actuator, Swagger UI).
4. **Standalone Portable Report:** The output report can be shared with clients or team leads as a single interactive HTML file with embedded or relative image assets.

---

## 5. Instructions for the Agent in the New Session
When opening this workspace:
1. Verify virtual environment or setup with `requirements.txt`.
2. Install Playwright browser dependencies via `playwright install chromium`.
3. Complete implementation of:
   - `src/scanner.py`
   - `src/analyzer.py`
   - `src/reporter.py`
   - `src/cli.py`
4. Run sample tests with test endpoints (e.g., `httpbin.org`, `example.com`, or mock local server).
5. Prepare Git repo and publish instructions for GitHub.
