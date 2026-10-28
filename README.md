# ReconSaas v3.0 (Go Rebuild)

> **Zero-cost, cross-platform CLI reconnaissance framework in Go**
> Single-binary · Passive · Active · Hybrid
> **205+ tech fingerprints** · **12 modules** · **$0 API keys required**

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
**License:** MIT  

---

## What's New in v3.0
- **Single Static Binary**: Rebuilt from the ground up in Go. Distributed as a standalone executable for Windows, Linux, and macOS without requiring Python or external runtimes.
- **Scope Enforcement**: Automatic IP validation, wildcard domain checking, and rejection of private networks (RFC 1918, RFC 6598, loopback, link-local, cloud metadata `169.254.169.254`).
- **Passive vs Active Boundary Safety**:
  - Passive JS inspection analyzes archival or local scripts; downloading target-hosted scripts requires active authorization.
  - DNS AXFR queries are classified as active probes requiring operator authorization (`--authorized`).
- **Atomic Event Streaming**: Finding events stream to `events.jsonl` in real time, preventing loss of discoveries during timeouts or user interruptions.
- **Embedded Fingerprint Catalog**: 205+ technology signatures across 60 categories embedded directly into the binary.

---

## Installation & Build

### From Source
```bash
git clone https://github.com/MohammadAliMehri/ReconSaas.git
cd ReconSaas

# Build binary
go build -o recon ./cmd/recon
```

---

## Quick Start

```bash
# Interactive guided menu
recon -i

# Passive scan (default, zero direct contact with target)
recon scan --target example.com --mode passive

# Active scan (requires explicit operator attestation)
recon scan --target example.com --mode active --authorized

# Hybrid scan (passive reconnaissance expanded into active probes)
recon scan --target example.com --mode hybrid --authorized

# Plan preview without sending network queries
recon scan --target example.com --dry-run

# Run specific modules
recon scan --target example.com -M dns,tech,headers --authorized

# Scan multiple targets
recon scan --targets targets.txt --mode passive -v

# List all available modules
recon modules list

# Validate YAML configuration
recon config validate --file configs/default.yaml
```

---

## Modes

| Mode | What It Does | Safety Requirement |
|---|---|---|
| **Passive** | Zero contact with target. DNS records, CT logs, Wayback machine, archived JS mining. | None (Default mode) |
| **Active** | Direct probe. TCP connect scan, directories, security headers, tech fingerprinting, 403 bypass. | Requires `--authorized` |
| **Hybrid** | Passive discovery followed by active targeted probing. | Requires `--authorized` |

---

## 12 Preserved Modules

### Passive
- `dns`: Resolves A, AAAA, MX, NS, TXT (SPF/DMARC), CNAME, SRV, CAA; wildcard detection.
- `certs`: Discovers subdomains from Certificate Transparency logs and passive DNS (crt.sh, AlienVault OTX, Shodan CTL, RapidDNS).
- `wayback`: Historical URL discovery via Wayback CDX API with sensitive extension filtering.
- `js`: Mines JavaScript bundles for API endpoints, routes, cloud buckets, and credentials (with automatic secret masking).

### Active
- `ports`: TCP connect port scanner with socket banner grabbing on authorized target IPs.
- `tech`: High-performance technology stack matcher against 205+ signatures across 60 categories.
- `headers`: Evaluates HSTS, CSP, XFO, XCTO, Referrer, Permissions, cookie attributes, and critical CORS misconfigurations.
- `dirs`: Bounded dictionary discovery for admin portals, sensitive backups, `.git`, and `.env` with soft-404 filtering.
- `endpoints`: Probes OpenAPI/Swagger documentation, GraphQL endpoints, `robots.txt`, `sitemap.xml`, and Spring Actuator routes.
- `bypass`: 403 Forbidden boundary testing using path normalization (`;`, `%2e/`, `..;`) and header spoofing (`X-Forwarded-For`).

### Analysis
- `rank`: Asset Ranker scoring assets 0–5 on exploitability using bug bounty money-path criteria.
- `report`: Synthesizes Markdown (`report.md`), structured JSON schema v1 (`report.json`), and individual module outputs.

---

## Output Structure

```
recon-output/<target>/
├── passive/
│   ├── dns.json
│   ├── certs.json
│   ├── wayback.json
│   ├── js.json
│   ├── subdomains.txt
│   └── wayback_urls.txt
├── active/
│   ├── ports.json
│   ├── tech.json
│   ├── headers.json
│   ├── dirs.json
│   ├── endpoints.json
│   └── bypass_403.json
├── analysis/
│   └── rank.json
├── events.jsonl        <-- Atomic event stream
├── report.md           <-- Markdown report
├── report.json         <-- Structured JSON schema v1
└── recon.log           <-- Execution logs
```

---

## Migration from Python v2
The legacy Python implementation has been archived at tag `v2-python-final` and branch `archive/python-v2`. See [`docs/migration.md`](docs/migration.md) for the detailed parity matrix, CLI flag mapping, and architectural decision records.

---

## Legal
**Authorized security testing only.** Written permission is required before scanning. Always respect scope boundaries and engagement rules. The authors assume no liability for unauthorized usage.
