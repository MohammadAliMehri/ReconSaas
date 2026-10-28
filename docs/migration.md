# ReconSaas v2.0 (Python) to v3.0 (Go) — Migration Specification & Parity Matrix

## 1. Executive Summary

This document provides a comprehensive migration guide, capability inventory, and parity verification matrix for transitioning ReconSaas from the legacy Python async implementation to the Go v3.0 engine.

---

## 2. Capability & Module Parity Matrix

| Module ID | Stage in v2 | v2 Python Implementation | v3 Go Implementation | Parity Status | Key Changes in v3 |
|---|---|---|---|---|---|
| `dns` | Passive | `recon_framework/modules/dns_enum.py` | `internal/modules/passive/dns` | Target 100% | Resolves A, AAAA, MX, NS, TXT, SOA, CNAME, SRV, CAA; wildcard checks. **Safety Change**: AXFR zone transfer is gated to active mode or requires explicit `--authorized`. |
| `certs` | Passive | `recon_framework/modules/cert_transparency.py` | `internal/modules/passive/certs` | Target 100% | crt.sh, AlienVault OTX, Shodan CTL, RapidDNS integration with deduplication and interesting prefix detection. |
| `wayback` | Passive | `recon_framework/modules/wayback_urls.py` | `internal/modules/passive/wayback` | Target 100% | CDX API queries, sensitive extension filtering, interesting path categorizations with error resilience and pagination. |
| `js` | Passive* | `recon_framework/modules/js_analyzer.py` | `internal/modules/passive/js` | Target 100% | **Safety Change**: In passive mode, parses *only* local or archived scripts. Direct HTTP downloading from target infrastructure requires active authorization. Masks candidate secrets in output. |
| `ports` | Active | `recon_framework/modules/port_scan.py` | `internal/modules/active/ports` | Target 100% | TCP connect scan across top ports (configurable top-N), socket banner grabbing, strict IP scope gating. |
| `tech` | Active | `recon_framework/modules/tech_fingerprint.py` | `internal/modules/active/tech` | Target 100% | Signature matcher against 205+ technologies across 60 categories. Checks headers, cookies, meta tags, script URLs, HTML patterns, and implied relationships. |
| `headers` | Active | `recon_framework/modules/header_analysis.py` | `internal/modules/active/headers` | Target 100% | Evaluates HSTS, CSP, XFO, XCTO, Referrer, Permissions-Policy, CORS reflection/credentials, and cookie flags (Secure, HttpOnly, SameSite). |
| `dirs` | Active | `recon_framework/modules/dir_bruteforce.py` | `internal/modules/active/dirs` | Target 100% | Bounded dictionary checks for admin portals, sensitive backups, `.git`, `.env`. Soft-404 filtering and redirect validation. |
| `endpoints` | Active | `recon_framework/modules/endpoint_probe.py` | `internal/modules/active/endpoints` | Target 100% | Probing of Swagger/OpenAPI docs, GraphQL endpoints, `robots.txt`, `sitemap.xml`, and Spring Actuator routes. |
| `bypass` | Active | `recon_framework/modules/bypass_403.py` | `internal/modules/active/bypass` | Target 100% | Non-destructive 403 diagnostics using path normalizations (`;`, `%2e/`, `..;`), spoofed headers (`X-Forwarded-For`), and HTTP methods. |
| `rank` | Analysis | `recon_framework/modules/asset_ranker.py` | `internal/analysis/rank` | Target 100% | Computes 0–5 asset exploitability scores using 5 core criteria (auth surface, multi-tenant, money/PII, stale vibes, low traffic) and bonus factors. |
| `report` | Analysis | `recon_framework/modules/report_generator.py` | `internal/report` | Target 100% | Produces clean Markdown report, structured JSON schema v1, and event logs. |

---

## 3. CLI Flags & Configuration Mapping

| v2 Flag | v3 Subcommand & Flag | Default | Notes |
|---|---|---|---|
| `-t, --target <str>` | `recon scan --target <str>` | none | Preserved. Single target domain or URL. |
| `-T, --targets <file>` | `recon scan --targets <file>` | none | Preserved. File with targets (one per line). |
| `-m, --mode <mode>` | `recon scan --mode <mode>` | `passive` (v3 default) | **Safety adjustment**: v3 defaults to `passive`. `active` and `hybrid` require `--authorized`. |
| `-o, --output <dir>` | `recon scan --output <dir>` | `./recon-output/<target>` | Preserved. Output directory for logs and reports. |
| `-M, --modules <list>`| `recon scan --modules <list>` | all mode modules | Preserved. Comma-separated list of module IDs. |
| `--threads <int>` | `recon scan --threads <int>` | `10` | Preserved. Concurrency limit. |
| `--timeout <int>` | `recon scan --timeout <int>` | `30` | Preserved. Network timeout in seconds. |
| `--rate-limit <float>`| `recon scan --rate-limit <float>` | `0.5` | Preserved. Minimum delay or token rate. |
| `--top-ports <int>` | `recon scan --top-ports <int>` | `1000` | Preserved. Top ports to scan. |
| `-v, --verbose` | `recon scan -v, --verbose` | `false` | Preserved. Structured debug logging. |
| `--list-modules` | `recon modules list` | — | Preserved via subcommand and flag alias. |
| `-i, --interactive` | `recon scan -i, --interactive` | `false` | Interactive wizard preserved. |
| `--version` | `recon version` / `recon -V` | — | Preserved. |
| *(New in v3)* | `recon scan --authorized` | `false` | **Required** for active scanning modes. |
| *(New in v3)* | `recon scan --dry-run` | `false` | Preview scan plan and budget without sending requests. |
| *(New in v3)* | `recon scan --config <file>` | `configs/default.yaml` | Load YAML configuration. |
| *(New in v3)* | `recon ai analyze --input <file>` | — | Optional offline AI summary and hypothesis generator. |

---

## 4. Output Schema and Directory Compatibility

v3 maintains strict filesystem layout compatibility with v2 output directories:
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
│   └── asset_ranker.json
├── events.jsonl        <-- New in v3: atomic event stream for crash recovery
├── report.md           <-- Markdown report
├── report.json         <-- Structured JSON schema v1
└── recon.log           <-- Structured execution logs
```

---

## 5. Intentional Behavioral & Safety Improvements

1. **Passive JS Isolation**:
   - *v2*: Downloaded `https://<target>` and fetched all remote scripts during `passive` mode.
   - *v3*: Only inspects archived scripts (via Wayback) or locally supplied files in passive mode. Active downloading requires explicit `--authorized` permission.
2. **DNS AXFR Gating**:
   - *v2*: Attempted DNS zone transfers against authoritative nameservers in passive mode.
   - *v3*: Classified as an active test; requires `--authorized`.
3. **Strict Network & Scope Policy**:
   - *v2*: Allowed connections to any IP address without verifying private CIDRs or cloud metadata.
   - *v3*: Enforces `internal/scope`. All connections to `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.169.254` (cloud metadata), and IPv6 link-local addresses are rejected unless explicitly allowlisted in configuration.
4. **Secret Masking**:
   - *v2*: Stored raw regex secret matches in plain text.
   - *v3*: Redacts detected tokens and high-entropy credentials by default before persisting or sending to the analysis layer.

---

## 6. Cutover & Safe Retirement Plan

The retirement of the legacy Python codebase will follow strict, non-destructive phased validation:

1. **Branching**: Develop v3 in `feature/v3-go-rebuild`. The Python implementation on `master` remains untouched and fully functional.
2. **Fixture Testing**: Record deterministic HTTP/DNS responses in `testdata/`. Run parallel validation between Python v2 and Go v3 to ensure identical output schemas.
3. **Cross-Compilation**: Build and smoke-test binaries for:
   - `windows/amd64` (`recon.exe`)
   - `linux/amd64` (`recon`)
   - `darwin/amd64` and `darwin/arm64` (`recon`)
4. **Parity Sign-Off Gate**:
   - All 12 modules implemented and passing offline fixture tests.
   - CLI commands, flags, and configuration validation passing.
   - Race conditions checked (`go test -race ./...`).
5. **Archival & Cutover (Requires Maintainer Approval)**:
   - Tag Python baseline as `v2-python-final`.
   - Create archival branch `archive/python-v2`.
   - Submit a dedicated cleanup PR removing `recon_framework/`, `requirements.txt`, and Python setup files.
   - Merge `feature/v3-go-rebuild` into `master`.

