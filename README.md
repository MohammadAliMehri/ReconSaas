# Recon Framework v2.0

> **Zero-cost, automated CLI reconnaissance framework**
> Passive · Active · Hybrid
> **205 tech fingerprints** · **12 modules** · **$0 API keys**

```
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝

   ███████╗██████╗  █████╗ ███╗   ███╗███████╗██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗
   ██╔════╝██╔══██╗██╔══██╗████╗ ████║██╔════╝██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝
   █████╗  ██████╔╝███████║██╔████╔██║█████╗  ██║ █╗ ██║██║   ██║██████╔╝█████╔╝
   ██╔══╝  ██╔══██╗██╔══██║██║╚██╔╝██║██╔══╝  ██║███╗██║██║   ██║██╔══██╗██╔═██╗
   ██║     ██║  ██║██║  ██║██║ ╚═╝ ██║███████╗╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗
   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝ ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
```

**GitHub:** https://github.com/MohammadAliMehri/ReconSaas
**Author:** MohammadAliMehri

---

## Quick Start

```bash
git clone https://github.com/MohammadAliMehri/ReconSaas.git
cd ReconSaas
pip install -r requirements.txt
pip install -e .
```

**Run:**

```bash
# Interactive guided menu
recon -i

# Direct CLI
recon --target example.com --mode hybrid

# Specific modules
recon --target example.com --mode active -M dns,tech,headers

# Multiple targets
recon --targets targets.txt --mode passive -v
```

---

## Three Modes

| Mode | What It Does | When |
|------|-------------|------|
| **Passive** | Zero contact. DNS, CT logs, Wayback, JS mining | Stealth, pre-engagement |
| **Active** | Direct probe. Ports, dirs, headers, fingerprint | Authorized testing |
| **Hybrid** | Passive expand → Active deep probe | **Recommended** |

---

## Modules

### Passive (no contact)

| ID | Module | Finds |
|----|--------|-------|
| `dns` | DNS Enumeration | A/AAAA/MX/NS/TXT/SOA/CNAME/SRV/CAA, zone transfer, wildcard |
| `certs` | Certificate Transparency | crt.sh, Shodan CTL, RapidDNS, OTX subdomains |
| `wayback` | Wayback URLs | Historical URLs, deleted endpoints, sensitive files |
| `js` | JavaScript Analyzer | API endpoints, secrets (AWS/JWT/tokens), routes, S3 buckets |

### Active (direct probe)

| ID | Module | Finds |
|----|--------|-------|
| `ports` | Port Scanner | Open ports (top 1000), high-risk services, banners |
| `tech` | Tech Fingerprinting | 205+ signatures: servers, CMS, frameworks, CDN, WAF, analytics, payment |
| `headers` | Header Analysis | Security headers, CORS, CSP, cookies, redirects, mixed content |
| `dirs` | Directory Bruteforce | Hidden dirs, backups, admin panels, .git/.env exposure |
| `endpoints` | Endpoint Probe | Swagger/OpenAPI, GraphQL introspection, robots.txt, Actuator |
| `bypass` | 403 Bypass | Path normalization, header spoofing, method tricks |

### Analysis

| ID | Module | Does |
|----|--------|------|
| `rank` | Asset Ranker | Scores assets 0–5 on exploitability |
| `report` | Report Generator | Markdown + JSON reports |

---

## Tech Fingerprinting

205 embedded signatures across 60 categories. No API calls — works offline.

**Pattern types:** HTTP headers (100%), cookies (90%), meta tags (95%), script src (80%), HTML body (70%), URL paths (75%), JS globals (60%), implied (30%).

**Auto version extraction:**
```
[100%] Nginx v1.24.0          (headers)
[100%] PHP v8.2.10            (headers)
[95%]  WordPress v6.5         (meta)
[80%]  jQuery v3.7.1          (scripts)
```

**Categories:** Web Servers, CMS, JS Frameworks, Web Frameworks, CDN/WAF, Analytics, Payment, Security, Chat/Widgets, PaaS/IaaS, Databases, Fonts, Maps, Video, Monitoring, Search, and more.

---

## CLI Reference

```
recon [-h] (-t TARGET | -T TARGETS) [-m {passive,active,hybrid}]
      [-o OUTPUT] [-M MODULES] [--threads THREADS] [--timeout TIMEOUT]
      [--rate-limit RATE_LIMIT] [--top-ports TOP_PORTS] [-v]
      [--list-modules] [-i] [--version]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-t, --target` | Target domain | required |
| `-T, --targets` | File with targets | — |
| `-m, --mode` | `passive`, `active`, `hybrid` | `hybrid` |
| `-o, --output` | Output directory | `./recon-output/<target>` |
| `-M, --modules` | Comma-separated module IDs | all |
| `--threads` | Concurrent threads | 10 |
| `--timeout` | HTTP timeout (seconds) | 30 |
| `--rate-limit` | Seconds between requests | 0.5 |
| `--top-ports` | Top N ports to scan | 1000 |
| `-v, --verbose` | Debug logging | off |
| `--list-modules` | List modules and exit | — |
| `-i, --interactive` | Interactive guided menu | — |

---

## Output

```
recon-output/<target>/
  passive/          dns.json, certs.json, wayback.json, js.json, subdomains.txt
  active/           ports.json, tech.json, headers.json, dirs.json, endpoints.json, bypass_403.json
  analysis/         asset_ranker.json
  report.md         Markdown report
  report.json       Structured JSON report
  recon.log         Debug log
```

---

## Adding a Module

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
        return {"module": self.name, "target": domain, "findings": findings, "data": data}
```

Register in `recon_framework/orchestrator.py` under `PASSIVE_MODULES` or `ACTIVE_MODULES`.

---

## Legal

**Authorized testing only.** Get written permission before scanning. Respect scope boundaries. The authors are not responsible for misuse.

---

## License

MIT — see [LICENSE](LICENSE)

## Acknowledgments

- OWASP Web Security Testing Guide v4.2
- Bug bounty hunter methodology
- Wappalyzer fingerprint patterns (MIT)
- Orange Tsai, James Kettle research
