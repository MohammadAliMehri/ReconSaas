# ReconSaas v3.0 — Architecture Specification & ADRs

## 1. Overview and System Vision

ReconSaas v3.0 is a zero-cost, cross-platform, single-binary CLI tool engineered in Go for authorized reconnaissance and security assessments. It replaces the legacy Python async implementation with a high-performance, deterministic engine featuring strict scope enforcement, bounded concurrency, cancellation, structured evidence tracking, and optional offline-capable AI interpretation via standard OpenAI-compatible endpoints.

### Key Architectural Tenets
1. **Zero External Paid Dependencies**: All discovery and fingerprinting works out-of-the-box without paid commercial API subscriptions.
2. **Deterministic & Bounded Execution**: The scanning engine relies on deterministic algorithms, explicit rate limits, and network safety controls—not language model whims.
3. **Strict Scope Control**: No traffic is emitted to unauthorized hosts, loopbacks, internal network ranges (RFC 1918/6598), or cloud metadata endpoints unless explicitly allowlisted.
4. **Separation of Evidence and Interpretation**: Raw observations (headers, status codes, HTML tags, response bytes) are preserved as structured evidence, decoupled from risk or exploit ratings.
5. **Single-Binary Portability**: Native self-contained binaries for Windows (`.exe`), Linux (ELF), and macOS (Mach-O) with embedded signatures and templates.

---

## 2. Component Architecture

```
                    ┌─────────────────────────┐
                    │        CLI Layer        │
                    │   (Cobra / Subcommands) │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │      Config & Scope     │
                    │   (YAML, Flags, CIDRs)  │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │    Orchestrator DAG     │
                    │  (Scheduler, Budgets)   │
                    └──────┬───────────┬──────┘
                           │           │
       ┌───────────────────▼──┐     ┌──▼───────────────────┐
       │   Passive Modules    │     │    Active Modules    │
       │  (dns, certs,        │     │  (ports, tech,       │
       │   wayback, js*)      │     │   headers, dirs,     │
       │                      │     │   endpoints, bypass) │
       └───────────┬──────────┘     └──┬───────────────────┘
                   │                   │
                   └─────────┬─────────┘
                             │ (Findings & Evidence Stream)
                    ┌────────▼────────┐
                    │ Storage Engine  │
                    │  (JSONL Events) │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │ Analysis Layer  │
                    │ (Ranker, Opt-AI)│
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │ Report Engine   │
                    │ (JSON, MD, SARIF│
                    └─────────────────┘
```

### Component Breakdown
- **CLI (`internal/cli`)**: Subcommands (`scan`, `modules`, `config`, `report`, `fingerprints`, `ai`, `version`). Manages command parsing, operator attestation (`--authorized`), and interactive terminal output.
- **Scope Engine (`internal/scope`)**: Canonical domain normalizer, CIDR matcher, DNS rebinding guard, and private network blocker. Inspects both target seeds and redirect URLs.
- **Transport Layer (`internal/transport`)**: Custom HTTP/DNS/TCP clients configured with rate limiters (`golang.org/x/time/rate`), connection pools, byte limits, and timeout contexts.
- **Engine & Orchestration (`internal/engine`)**: Module registry, dependency scheduler, bounded worker pools, graceful cancellation (`context.Context`), and finding event sink.
- **Modules (`internal/modules`)**:
  - `passive/dns`: DNS record query (A, AAAA, MX, NS, TXT, SOA, CNAME, SRV, CAA), wildcard detection.
  - `passive/certs`: Public CT log queries (crt.sh, AlienVault OTX, Shodan CTL, RapidDNS).
  - `passive/wayback`: Historical URL aggregation and sensitive pattern extraction via CDX APIs.
  - `passive/js`: Static AST/regex inspection of local or archived JavaScript bundles (strictly non-active in passive mode).
  - `active/ports`: TCP connect scanning with banner grabbing on authorized target IPs.
  - `active/tech`: High-speed signature matching across headers, cookies, scripts, meta tags, and body markers.
  - `active/headers`: Analysis of security headers (HSTS, CSP, XFO, etc.), CORS, and cookie flags.
  - `active/dirs`: Bounded wordlist discovery with soft-404 detection and redirect inspection.
  - `active/endpoints`: Probing of API documentation, GraphQL endpoints, robots.txt, and actuator paths.
  - `active/bypass`: 403 authorization boundary diagnostics via headers and path normalization.
- **Analysis (`internal/analysis`)**:
  - `rank`: Evidence-weighted and legacy keyword asset scoring (0–5 scale).
  - `ai`: Optional OpenAI-compatible client for summarizing findings, correlating evidence, and generating remediation guidance with zero data leakage of unredacted secrets.
- **Report (`internal/report`)**: Renders deterministic Markdown, schema-versioned JSON, and SARIF output.

---

## 3. Architectural Decision Records (ADRs)

### ADR-001: Migration from Python to Go
- **Context**: The v2 implementation relied on Python 3.10+ with asyncio, httpx, and numerous dependencies, requiring a local Python interpreter, virtual environment, and platform-specific wheels.
- **Decision**: Rebuild ReconSaas v3.0 in Go 1.23+.
- **Consequences**: Enables distribution of a single static executable per platform without runtime dependencies; native concurrency through goroutines and channels; lower memory footprint and predictable execution characteristics.

### ADR-002: Scope-Enforced Transport Layer
- **Context**: Autonomous or active reconnaissance tools risk straying out of scope during HTTP redirects, DNS rebinding, or link extraction, potentially probing unauthorized or internal assets (e.g. AWS metadata `169.254.169.254`, localhost).
- **Decision**: Modules are strictly forbidden from creating naked `net/http` or `net.Dial` connections. All network I/O must route through the `internal/transport` client, which queries the `internal/scope.Engine` before resolving, connecting, or following redirects.
- **Consequences**: Guarantees zero out-of-scope traffic; internal addresses and private networks are denied by default unless explicitly allowed by operator configuration.

### ADR-003: Classification of JS Analysis and DNS AXFR
- **Context**: In v2, the `js` module directly fetched HTML and scripts from the target in "passive" mode. Similarly, `dns` attempted full DNS Zone Transfers (AXFR) against authoritative target nameservers in passive mode.
- **Decision**:
  1. `js` in passive mode analyzes *only* archived scripts (e.g. via Wayback) or local files. Directly downloading JavaScript files from target servers requires active mode authorization (`--authorized`).
  2. DNS AXFR is gated as an active probe or requires explicit active consent because it initiates direct TCP queries to the target's authoritative nameservers.
- **Consequences**: Aligns operational behavior with true OSINT definitions; prevents unintentional alerts or defensive detection during passive recon engagements.

### ADR-004: Event Streaming Storage via JSONL with Final Report Synthesis
- **Context**: In long scans, process crashes, timeouts, or user cancellations could lose all in-memory findings if reports are only compiled at the very end.
- **Decision**: The engine streams atomic `Finding` events to a localized `events.jsonl` log as they are emitted. The final report generator reads the stream and renders `report.json` and `report.md`.
- **Consequences**: Crash resilience, memory efficiency, and real-time observability.

### ADR-005: Decoupled Deterministic Engine and Optional Local AI
- **Context**: AI models are non-deterministic, can hallucinate, and present data-confidentiality concerns if prompts transmit proprietary infrastructure details to third parties.
- **Decision**:
  1. The reconnaissance engine operates completely independently of any AI system.
  2. AI is an optional post-scan analysis phase (`recon ai analyze`) using a local OpenAI-compatible endpoint (LM Studio, Ollama) or explicitly configured remote provider.
  3. Sensitive leads (passwords, tokens, API keys) are deterministically redacted before being included in prompts.
- **Consequences**: Absolute functional autonomy without AI; complete data sovereignty and zero vendor lock-in.

### ADR-006: Versioned Fingerprint Data Model
- **Context**: Hardcoding 205+ technology fingerprints in Go source code reduces auditability and prevents security teams from adding custom signatures without recompilation.
- **Decision**: Technology signatures are stored as structured YAML/JSON files under `signatures/` and embedded into the Go binary using `go:embed`. Custom signature files can also be loaded at runtime via CLI or configuration.
- **Consequences**: Transparent, community-auditable signatures with the convenience of a self-contained single binary.

---

## 4. Concurrency, Cancellation & Budget Controls

- **Worker Pools**: Concurrency is managed via bounded worker pools (`errgroup` and buffered semaphores) governed by `limits.global_concurrency` and `limits.per_host_concurrency`.
- **Rate Limiting**: Implemented via token buckets (`golang.org/x/time/rate`) per target domain and globally.
- **Cancellation**: Every operation takes a root `context.Context` tied to OS signals (`SIGINT`, `SIGTERM`). On interruption, in-flight sockets are cleanly closed, pending tasks drain, and collected events up to the interrupt point are preserved.
- **Response Caps**: `limits.max_response_bytes` enforces streaming limits via `io.LimitReader` (default 2 MB) to prevent denial-of-service from large binary downloads.

