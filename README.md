# Recon Framework

> **Zero-cost, open-source reconnaissance platform** with Passive, Active, and Hybrid modes.
> Built from real-world bug bounty and penetration testing methodology.
> **205 technology fingerprints** · **12 modules** · **Web UI** · **Docker ready** · **$0**

```
  ____  _____ ____  _   _ ______   _____ _____ _   _ ______ _____
 |  _ \| ____/ ___|| \ | |  _ \ \ / /_ _|  ___| \ | |  ____|  ___|
 | |_) |  _|| |    |  \| | | | \ V / | || |_  |  \| | |__  | |_
 |  _ <| |__| |___ | |\  | |_|  | |  | ||  _| | |\  |  __| |  _|
 |_| \_\_____\____||_| \_|____/  |_| |___|_|   |_| \_|_|    |_|
```

---

## Table of Contents

- [What It Does](#what-it-does)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Three Modes](#three-modes)
- [Web UI](#web-ui)
- [Docker](#docker)
- [Modules](#modules)
- [Technology Fingerprinting](#technology-fingerprinting)
- [Asset Ranking System](#asset-ranking-system)
- [Output Structure](#output-structure)
- [CLI Reference](#cli-reference)
- [API Reference](#api-reference)
- [Methodology](#methodology)
- [Contributing](#contributing)
- [Legal Disclaimer](#legal-disclaimer)
- [License](#license)

---

## What It Does

Recon Framework automates the **information gathering and attack surface mapping** phases of security testing. It discovers subdomains, fingerprints 300+ technologies, finds hidden endpoints, mines JavaScript for secrets, tests for common misconfigurations, and ranks assets by exploitability.

**Built for:** Bug bounty hunters, penetration testers, security researchers, and red teamers.

**Cost:** $0. All modules use free APIs, open-source tools, and public data sources. No API keys required.

---

## Quick Start

```bash
# Clone
git clone https://github.com/your-org/recon-framework.git
cd recon-framework

# Option A: One-line setup
bash setup.sh

# Option B: pip install
pip install -r requirements.txt && pip install -e .

# Option C: Docker
docker-compose up -d
```

**Run a scan:**

```bash
# CLI — hybrid mode (recommended)
python -m recon_framework.cli --target example.com --mode hybrid

# Web UI — open http://localhost:5000
python -m recon_framework.cli --web

# Docker — already running after docker-compose up
open http://localhost:5000
```

---

## Installation

### Method 1: Local Install

```bash
git clone https://github.com/your-org/recon-framework.git
cd recon-framework
pip install -r requirements.txt
pip install -e .
```

### Method 2: Setup Script (Interactive)

```bash
bash setup.sh
```

Presents a menu: local install, Docker, or both.

### Method 3: Makefile

```bash
make install    # pip install -e .
make web        # launch web UI on port 5000
make test       # run test suite
make docker     # build and run Docker container
```

### Method 4: Docker

```bash
docker-compose up -d
# Web UI available at http://localhost:5000
```

**No API keys required.** Works out of the box with free data sources (crt.sh, RapidDNS, Shodan CTL, Wayback Machine, AlienVault OTX).

---

## Three Modes

| Mode | What It Does | When to Use |
|------|-------------|-------------|
| **Passive** | Zero direct contact with target. Uses DNS, certificates, search engines, Wayback Machine, OSINT. | Stealth recon, pre-engagement intel, when you can't touch the target yet |
| **Active** | Direct probing: port scanning, directory brute-force, header analysis, endpoint discovery, tech fingerprinting. | Authorized testing, lab environments, full-scope engagements |
| **Hybrid** | Passive first (expand surface), then Active (deep probe ranked targets). | **Default recommended mode.** Bug bounty, pen tests, full assessments |

```bash
python -m recon_framework.cli --target example.com --mode passive   # stealth
python -m recon_framework.cli --target example.com --mode active    # aggressive
python -m recon_framework.cli --target example.com --mode hybrid    # best of both
```

---

## Web UI

A dark-themed dashboard with live scan progress, findings table, and report downloads.

```bash
# Launch
python -m recon_framework.cli --web

# Custom port
python -m recon_framework.cli --web --port 8080

# Via Makefile
make web
```

Open **http://localhost:5000** in your browser.

**Features:**
- Target input with mode selector (Passive / Active / Hybrid)
- Module selection checkboxes
- Live console output via Server-Sent Events (SSE)
- Findings table sorted by severity (Critical → Info)
- Stats cards with severity breakdown
- Markdown + JSON report download
- Scan history sidebar
- Dark terminal-style theme

**Screenshot:**

```
┌─────────────────────────────────────────────────────────────────┐
│  ⚡ reconframework                         [New Scan] [History] │
├──────────────┬──────────────────────────────────────────────────┤
│ Recent Scans │  🎯 New Reconnaissance Scan                     │
│              │                                                  │
│ ● example.com│  Target Domain                                   │
│   hybrid · 5 │  ┌──────────────────────────────────────────┐   │
│   findings   │  │ example.com                               │   │
│              │  └──────────────────────────────────────────┘   │
│ ● target.com │                                                 │
│   passive · 3│  [🔵 Passive] [🔴 Active] [🟣 Hybrid]          │
│              │                                                  │
│              │  ⚡ Start Scan                                   │
│              │                                                  │
│              │  ┌── 0 ──┐ ┌── 0 ──┐ ┌── 1 ──┐ ┌── 0 ──┐     │
│              │  │CRITICAL│ │ HIGH  │ │MEDIUM │ │  LOW  │     │
│              │  └────────┘ └───────┘ └───────┘ └───────┘     │
│              │                                                  │
│              │  [Console] [Findings] [Report]                   │
│              │  ▸ DNS Record Enumeration → example.com         │
│              │  ▸ Certificate Transparency → example.com       │
│              │    [INFO] 7 Subdomains Found                    │
└──────────────┴──────────────────────────────────────────────────┘
```

---

## Docker

### Build & Run

```bash
docker-compose up -d
```

This builds the image and starts the web UI on port 5000.

### Custom Port

```bash
RECON_PORT=8080 docker-compose up -d
```

### CLI Mode in Docker

```bash
docker run --rm recon-framework python -m recon_framework.cli --target example.com --mode passive
```

### View Logs

```bash
docker-compose logs -f
```

### Stop

```bash
docker-compose down
```

### Docker Compose Services

| Service | Port | Description |
|---------|------|-------------|
| `recon` | 5000 | Web UI + API (gunicorn, 2 workers, 4 threads) |

Output is persisted in a Docker volume (`recon-output`).

---

## Modules

### Passive Modules (no target contact)

| ID | Module | What It Finds |
|----|--------|--------------|
| `dns` | DNS Enumeration | A, AAAA, MX, NS, TXT, SOA, CNAME, SRV, CAA records; zone transfer attempts; wildcard DNS detection |
| `certs` | Certificate Transparency | Subdomains from crt.sh, Shodan CTL (`ctl.shodan.io`), RapidDNS, AlienVault OTX; issuer orgs; interesting subdomain flags |
| `wayback` | Wayback URLs | Historical URLs, deleted endpoints, old admin panels; sensitive file detection (`.sql`, `.bak`, `.env`, `.git`); status code distribution |
| `js` | JavaScript Analyzer | API endpoints, GraphQL paths, fetch calls, route tables; secrets (AWS keys, JWTs, API keys, tokens); S3 buckets; internal URLs; env variables; internal IPs |

### Active Modules (direct probing)

| ID | Module | What It Finds |
|----|--------|--------------|
| `ports` | Port Scanner | Open ports (top 1000, configurable); high-risk service alerts (Redis, MongoDB, Docker API, Kubelet, RDP); banner grabbing |
| `tech` | Technology Fingerprinting | **205+ signatures** — web servers, CMS, frameworks, JS libraries, CDN, WAF, analytics, payment processors, databases, hosting, fonts, widgets. Version extraction. Confidence scoring. See [Technology Fingerprinting](#technology-fingerprinting) |
| `headers` | Header Analysis | Security headers (HSTS, CSP, X-Frame-Options, etc.); CORS misconfiguration (wildcard, null, reflected origin); CSP analysis (unsafe-inline, unsafe-eval, wildcard sources); cookie flags (Secure, HttpOnly); mixed content; redirect chain; open redirect detection |
| `dirs` | Directory Bruteforce | Hidden directories, admin panels, backup files, config leaks, API docs, debug endpoints, `.git`/`.env` exposure; backup extension variants on discovered files |
| `endpoints` | Endpoint Probe | Swagger/OpenAPI docs, GraphQL (with introspection), robots.txt parsing, sitemap.xml, security.txt, Spring Actuator, common API versions, health/status endpoints |
| `bypass` | 403 Bypass | Path normalization payloads (Orange Tsai); header spoofing (X-Forwarded-For, X-Real-IP); method tricks (GET→POST, HTTP/1.0); double-slash, case-flip |

### Analysis Modules

| ID | Module | What It Does |
|----|--------|-------------|
| `rank` | Asset Ranker | Scores every discovered asset 0–5 on exploitability (auth surface, multi-tenant, money/PII, stale vibes, low traffic) |
| `report` | Report Generator | Markdown + JSON reports with severity-sorted findings, subdomains, ports, tech stack, ranked assets, discovered endpoints |

---

## Technology Fingerprinting

The fingerprint engine uses **205 embedded signatures** across **60 categories**, inspired by Wappalyzer. No external API calls — works offline.

### Pattern Types

Each signature can match on:

| Pattern | Confidence | Example |
|---------|-----------|---------|
| HTTP Headers | 100% | `Server: nginx/1.24.0` |
| Cookies | 90% | `PHPSESSID`, `laravel_session` |
| Meta Generator | 95% | `<meta name="generator" content="WordPress 6.5">` |
| Script Sources | 80% | `<script src="react.min.js">` |
| HTML Body | 70% | `__NEXT_DATA__`, `data-reactroot` |
| URL Paths | 75% | `/wp-admin/`, `/actuator/health` |
| JS Globals | 60% | `jQuery.fn.jquery`, `Vue.config` |
| Implied | 30% | `WordPress` → implies `PHP`, `MySQL` |

### Version Extraction

Versions are automatically extracted from headers, meta tags, script URLs, and body content:

```
[100%] Nginx v1.24.0          (headers)
[100%] PHP v8.2.10            (headers)
[95%]  WordPress v6.5         (meta)
[80%]  jQuery v3.7.1          (scripts)
[100%] Gunicorn v19.9.0       (headers)
```

### Detected Categories

| Category | Examples |
|----------|---------|
| Web Servers | Apache, Nginx, IIS, LiteSpeed, Tengine, Caddy, Gunicorn, Uvicorn, OpenResty, Envoy |
| CMS | WordPress, Drupal, Joomla, Shopify, Squarespace, Wix, Ghost, Hugo, Magento, WooCommerce |
| JS Frameworks | React, Vue.js, Angular, Next.js, Nuxt.js, Svelte, Gatsby, Ember.js, Alpine.js, htmx |
| JS Libraries | jQuery, D3.js, Three.js, Lodash, Moment.js, Axios, Webpack, Vite |
| Web Frameworks | Laravel, Django, Flask, FastAPI, Express, Rails, Spring, Symfony, NestJS, SvelteKit |
| CDN / WAF | Cloudflare, CloudFront, Akamai, Fastly, Imperva, Sucuri, BunnyCDN, ArvanCloud |
| Analytics | Google Analytics, GTM, Hotjar, Mixpanel, Segment, Matomo, Plausible, Clarity, Amplitude |
| Payment | Stripe, PayPal, Braintree, Square, Adyen, Razorpay, Klarna |
| Security | reCAPTCHA, hCaptcha, Turnstile, PerimeterX, DataDome, AWS WAF, ModSecurity |
| Chat / Widgets | Intercom, Drift, Zendesk Chat, LiveChat, Crisp, Tawk.to, HubSpot |
| PaaS / IaaS | AWS, Heroku, Vercel, Netlify, Firebase, DigitalOcean, Google Cloud, Azure |
| Databases | MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch, SQLite, MSSQL, Oracle |
| Fonts | Google Fonts, Font Awesome, Typekit, Material Icons |
| Maps | Google Maps, Leaflet, Mapbox, OpenStreetMap |
| Video | YouTube, Vimeo, Video.js, JW Player, HLS.js |
| Tag Managers | GTM, Segment, Optimizely, VWO |
| Monitoring | Sentry, Bugsnag, New Relic, Datadog |
| Search | Algolia, Elasticsearch |
| Cookie Banners | OneTrust, Osano, Cookie Consent |

---

## Asset Ranking System

Every discovered asset is scored 0–5 on five criteria:

| Criteria | Weight | Keywords |
|----------|--------|----------|
| Auth Surface | 1.0 | login, signin, auth, oauth, sso, token, api-key |
| Multi-tenant | 1.0 | org, tenant, account, team, workspace |
| Money / PII | 1.0 | payment, billing, invoice, export, kyc, profile |
| Stale Vibes | 1.0 | old, legacy, v1, beta, test, dev, staging, debug |
| Low Traffic | 1.0 | admin, internal, graphql, swagger, actuator, jenkins |

**Bonus:** AI widgets (+0.5), new features (+0.5), API docs exposed (+0.5)

**Capped at 5.0.** Hunt highest score first.

---

## Output Structure

```
recon-output/<scan_id>/
  passive/
    dns.json              # DNS records, zone transfer, wildcard
    certs.json            # CT logs, subdomains, issuers
    wayback.json          # Historical URLs, sensitive files
    js.json               # JS endpoints, secrets, routes
  active/
    ports.json            # Open ports, banners
    tech.json             # 205+ tech fingerprints, versions
    headers.json          # Security headers, CORS, CSP
    dirs.json             # Directory bruteforce results
    endpoints.json        # API docs, GraphQL, robots.txt
    bypass_403.json       # 403 bypass attempts
  analysis/
    asset_ranker.json     # Scored asset rankings
  report.md               # Markdown report
  report.json             # Structured JSON report
  recon.log               # Full debug log
```

---

## CLI Reference

```
usage: recon [-h] (-t TARGET | -T TARGETS) [-m {passive,active,hybrid}]
             [-o OUTPUT] [-M MODULES] [--threads THREADS] [--timeout TIMEOUT]
             [--rate-limit RATE_LIMIT] [--top-ports TOP_PORTS] [-v]
             [--list-modules] [--web] [--port PORT] [--version]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-t, --target` | Target domain or URL | required |
| `-T, --targets` | File with targets (one per line) | — |
| `-m, --mode` | `passive`, `active`, or `hybrid` | `hybrid` |
| `-o, --output` | Output directory | `./recon-output/<target>` |
| `-M, --modules` | Comma-separated module IDs | all |
| `--threads` | Concurrent threads | 10 |
| `--timeout` | HTTP timeout (seconds) | 30 |
| `--rate-limit` | Seconds between requests | 0.5 |
| `--top-ports` | Top N ports to scan | 1000 |
| `-v, --verbose` | Debug logging | off |
| `--list-modules` | List modules and exit | — |
| `--web` | Launch web UI dashboard | — |
| `--port` | Web UI port | 5000 |

### Examples

```bash
# Passive recon (stealth — no contact with target)
python -m recon_framework.cli --target example.com --mode passive

# Active recon (authorized testing)
python -m recon_framework.cli --target example.com --mode active

# Hybrid (recommended)
python -m recon_framework.cli --target example.com --mode hybrid

# Specific modules only
python -m recon_framework.cli --target example.com --mode active -M dns,tech,headers

# Multiple targets from file
python -m recon_framework.cli --targets targets.txt --mode passive

# Custom output + verbose
python -m recon_framework.cli --target example.com -o ./my-recon -v

# Web UI on custom port
python -m recon_framework.cli --web --port 8080

# List available modules
python -m recon_framework.cli --list-modules
```

---

## API Reference

The web UI exposes a REST API. All endpoints return JSON.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/modules` | List available modules (passive, active, analysis) |
| `POST` | `/api/scan` | Start a new scan |
| `GET` | `/api/scans` | List all scans |
| `GET` | `/api/scan/<id>` | Get scan status and results |
| `GET` | `/api/scan/<id>/logs` | Get scan logs (supports `?since=N`) |
| `GET` | `/api/scan/<id>/stream` | SSE live log stream |
| `GET` | `/api/scan/<id>/report` | Get markdown report (or `?format=json`) |
| `GET` | `/api/scan/<id>/download/<fmt>` | Download report (`md` or `json`) |

### Start a Scan

```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "mode": "hybrid", "threads": 10}'
```

Response:
```json
{"scan_id": "f157357508a0", "status": "queued"}
```

### Stream Live Logs

```bash
curl -N http://localhost:5000/api/scan/f157357508a0/stream
```

SSE events:
```
data: {"type": "log", "message": "[21:28:20] ▸ DNS Record Enumeration → example.com"}
data: {"type": "log", "message": "[21:28:20]   [INFO] MX Records Found (1)"}
data: {"type": "done", "status": "completed", "findings_count": 6}
```

### Get Results

```bash
curl http://localhost:5000/api/scan/f157357508a0
```

```json
{
  "id": "f157357508a0",
  "target": "example.com",
  "mode": "hybrid",
  "status": "completed",
  "findings": [
    {"severity": "medium", "title": "Interesting Subdomains in CT Logs (1)", "detail": "dev.example.com"},
    {"severity": "info", "title": "CT Logs: 6 Subdomains Found", "detail": "..."}
  ],
  "modules_run": ["dns", "certs", "wayback", "js", "ports", "tech", "headers", "dirs", "endpoints", "bypass"]
}
```

---

## Methodology

This framework implements a structured reconnaissance methodology based on real-world bug bounty and penetration testing practices:

1. **Expand** — Discover the full attack surface (subdomains, IPs, ports, services)
   - DNS records, Certificate Transparency (crt.sh + Shodan CTL + RapidDNS + OTX)
   - Wayback Machine historical URLs
   - JavaScript bundle mining for endpoints and secrets

2. **Fingerprint** — Identify technologies, frameworks, versions
   - 205+ signatures: headers, cookies, meta tags, script sources, HTML patterns, JS globals
   - Automatic version extraction
   - Confidence scoring (100% headers → 60% JS globals → 30% implied)

3. **Map** — Find entry points (endpoints, parameters, hidden paths)
   - Directory brute-force with backup extension variants
   - API docs, GraphQL, robots.txt, sitemap, security.txt
   - Spring Actuator, common API versions

4. **Mine** — Extract secrets, API keys, internal paths from JS/source
   - AWS keys, JWTs, generic API secrets
   - S3 buckets, internal URLs, private IPs
   - Environment variables, base64 blobs

5. **Rank** — Score assets by exploitability (money paths first)
   - Auth surface, multi-tenant, money/PII, stale vibes, low traffic
   - Bonus: AI widgets, new features, API docs

6. **Probe** — Test ranked targets for common misconfigurations
   - Security headers, CORS, CSP, cookie flags
   - 403 bypass (path normalization, header spoofing, method tricks)
   - Open redirects, mixed content

7. **Report** — Structured findings with evidence
   - Markdown + JSON reports
   - Severity-sorted findings table
   - Downloadable via CLI or web UI

---

## Adding a New Module

```python
# recon_framework/modules/my_module.py
from .base import BaseModule

class MyModule(BaseModule):
    name = "my_module"
    description = "What it does"
    mode = "passive"  # passive | active | both

    async def run(self, target: str) -> dict:
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        findings = []
        data = {}

        # Your recon logic here
        # ...
        # findings.append({"severity": "high", "title": "...", "detail": "..."})

        return {
            "module": self.name,
            "target": domain,
            "findings": findings,
            "data": data,
        }
```

Register it in `recon_framework/orchestrator.py` under `PASSIVE_MODULES` or `ACTIVE_MODULES`.

---

## Project Structure

```
recon-platform/
├── Dockerfile                    # Python 3.11 slim, gunicorn
├── docker-compose.yml            # One-command Docker setup
├── Makefile                      # install, web, docker, test, clean
├── setup.sh                      # Interactive setup script
├── requirements.txt              # Python dependencies
├── setup.py                      # Package metadata
├── .env.example                  # Environment variables template
├── .gitignore
├── LICENSE                       # MIT
├── README.md
├── tests/
│   └── test_framework.py         # Unit tests (10 tests)
└── recon_framework/
    ├── __init__.py
    ├── cli.py                    # CLI entry point (--web, --target, --mode)
    ├── config.py                 # ScanConfig, free API endpoints
    ├── orchestrator.py           # Module execution, mode routing
    ├── modules/
    │   ├── base.py               # BaseModule abstract class
    │   ├── dns_enum.py           # DNS records, zone transfer, wildcard
    │   ├── cert_transparency.py  # crt.sh, Shodan CTL, RapidDNS, OTX
    │   ├── wayback_urls.py       # Historical URLs, sensitive files
    │   ├── js_analyzer.py        # JS secrets, endpoints, routes
    │   ├── port_scan.py          # Async port scanner
    │   ├── tech_fingerprint.py   # 205+ tech fingerprint engine
    │   ├── header_analysis.py    # Security headers, CORS, CSP
    │   ├── dir_bruteforce.py     # Directory discovery
    │   ├── endpoint_probe.py     # API docs, GraphQL, robots.txt
    │   ├── bypass_403.py         # 403 bypass techniques
    │   ├── asset_ranker.py       # Exploitability scoring
    │   └── report_generator.py   # Markdown + JSON reports
    ├── utils/
    │   ├── fingerprints.py       # 205+ technology signatures
    │   ├── engine.py             # Pattern matching engine
    │   ├── logger.py             # Rich console + file logging
    │   └── networking.py         # HTTP client, DNS, URL utils
    └── web/
        ├── app.py                # Flask API (8 endpoints, SSE)
        └── templates/
            └── index.html        # Dark-themed SPA dashboard
```

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-module`)
3. Commit your changes (`git commit -am 'Add new module'`)
4. Push to the branch (`git push origin feature/new-module`)
5. Open a Pull Request

### Areas for Contribution

- New fingerprint signatures (add to `utils/fingerprints.py`)
- New recon modules (extend `modules/`)
- Additional passive data sources
- UI improvements
- Test coverage

---

## Legal Disclaimer

This tool is provided for **authorized security testing and educational purposes only**.

- **Always** get written authorization before testing
- **Respect** scope boundaries and rules of engagement
- **Never** test systems you don't own or have permission to test
- The authors are not responsible for misuse of this tool

---

## License

MIT License — see [LICENSE](LICENSE)

---

## Acknowledgments

Built from methodology documented in:
- [OWASP Web Security Testing Guide v4.2](https://owasp.org/www-project-web-security-testing-guide/v42/)
- Bug bounty hunter best practices and kill-loop methodology
- Wappalyzer fingerprint database (MIT licensed patterns)
- Community recon techniques (Amass, subfinder, httpx, ffuf patterns)
- Orange Tsai "Breaking Parser Logic" (403 bypass)
- James Kettle cache poisoning and request smuggling research
