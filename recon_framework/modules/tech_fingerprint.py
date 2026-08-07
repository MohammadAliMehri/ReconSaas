"""
Technology Fingerprinting Module — Active
Identifies 300+ technologies using Wappalyzer-class signature engine.
Detects: web servers, frameworks, CMS, CDN, WAF, analytics, widgets,
payment processors, JS libraries, databases, hosting, and more.
"""
import re
import ssl
import socket
from .base import BaseModule
from ..utils.networking import HttpClient
from ..utils.engine import FingerprintEngine


class TechFingerprint(BaseModule):
    name = "tech_fingerprint"
    description = "Technology Stack Fingerprinting (300+ signatures)"
    mode = "active"

    def __init__(self, config):
        super().__init__(config)
        self.engine = FingerprintEngine()

    async def run(self, target: str) -> dict:
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        base_url = f"https://{domain}"

        results = {
            "technologies": [],     # full match list
            "tech_names": [],       # just the names
            "tech_count": 0,
            "by_category": {},      # category -> [tech names]
            "server": None,
            "cdn": None,
            "waf": None,
            "cms": None,
            "frameworks": [],
            "js_libraries": [],
            "analytics": [],
            "payment": [],
            "security": [],
            "hosting": None,
            "ssl_info": None,
            "headers_raw": {},
            "script_sources": [],
            "cookies": [],
        }
        findings = []

        async with HttpClient(timeout=30, rate_limit=0.5) as client:
            try:
                resp = await client.get(base_url)
                headers = dict(resp.headers)
                body = resp.text
                cookie_names = list(resp.cookies.keys())
                results["headers_raw"] = {k: v[:300] for k, v in headers.items()}
                results["cookies"] = cookie_names

                # Extract all <script src="..."> from body
                script_srcs = re.findall(
                    r'<script[^>]+src=["\']([^"\']+)["\']', body, re.IGNORECASE,
                )
                # Resolve relative URLs
                results["script_sources"] = [
                    s if s.startswith("http") else f"{base_url}{s}" if s.startswith("/") else f"{base_url}/{s}"
                    for s in script_srcs
                ]

                # Run the fingerprint engine
                matches = self.engine.analyze(
                    headers=headers,
                    cookies=cookie_names,
                    body=body,
                    url=base_url,
                    script_sources=results["script_sources"],
                )

                # Populate results from engine output
                for m in matches:
                    entry = {
                        "name": m.name,
                        "version": m.version,
                        "confidence": m.confidence,
                        "categories": m.category_names,
                        "matched_by": m.matched_by,
                    }
                    results["technologies"].append(entry)
                    results["tech_names"].append(m.name)

                    # Classify
                    for cat in m.category_names:
                        results["by_category"].setdefault(cat, []).append(m.name)

                    if m.name in ("Apache", "Nginx", "Microsoft IIS", "LiteSpeed",
                                  "Tengine", "Caddy", "Gunicorn", "Uvicorn",
                                  "OpenResty", "Jetty", "Kestrel"):
                        results["server"] = f"{m.name} {m.version}".strip()
                    if cat_is(m.categories, 27):
                        results["cdn"] = m.name
                    if cat_is(m.categories, 16):
                        if m.name not in ("reCAPTCHA", "hCaptcha", "Turnstile"):
                            results["waf"] = m.name
                    if cat_is(m.categories, 1):
                        results["cms"] = m.name
                    if cat_is(m.categories, 18):
                        results["frameworks"].append(m.name)
                    if cat_is(m.categories, 12):
                        results["js_libraries"].append(m.name)
                    if cat_is(m.categories, 10):
                        results["analytics"].append(m.name)
                    if cat_is(m.categories, 34):
                        results["payment"].append(m.name)
                    if cat_is(m.categories, 41, 42):
                        results["hosting"] = m.name

                results["tech_count"] = len(results["technologies"])

                # SSL/TLS certificate info
                try:
                    ctx = ssl.create_default_context()
                    with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                        s.settimeout(5)
                        s.connect((domain, 443))
                        cert = s.getpeercert()
                        issuer = dict(x[0] for x in cert.get("issuer", []))
                        subject = dict(x[0] for x in cert.get("subject", []))
                        results["ssl_info"] = {
                            "issuer": issuer.get("organizationName", ""),
                            "subject": subject.get("commonName", ""),
                            "not_before": cert.get("notBefore", ""),
                            "not_after": cert.get("notAfter", ""),
                            "serial": cert.get("serialNumber", ""),
                            "san": [e[1] for e in cert.get("subjectAltName", [])],
                        }
                except Exception as e:
                    self.logger.debug(f"SSL info grab failed: {e}")

                # Also check common path pages for additional fingerprints
                extra_pages = ["/robots.txt", "/sitemap.xml", "/favicon.ico"]
                for path in extra_pages:
                    try:
                        r = await client.get(f"{base_url}{path}")
                        if r.status_code == 200 and len(r.text) > 10:
                            extra_matches = self.engine.analyze(
                                headers=dict(r.headers),
                                body=r.text[:2000],
                                url=f"{base_url}{path}",
                            )
                            for m in extra_matches:
                                if m.name not in results["tech_names"]:
                                    results["technologies"].append({
                                        "name": m.name,
                                        "version": m.version,
                                        "confidence": m.confidence - 10,
                                        "categories": m.category_names,
                                        "matched_by": f"{m.matched_by} ({path})",
                                    })
                                    results["tech_names"].append(m.name)
                                    results["tech_count"] += 1
                    except Exception:
                        pass

            except Exception as e:
                self.logger.error(f"Tech fingerprint failed: {e}")

        # ── Generate findings ────────────────────────────────────
        if results["server"]:
            findings.append({
                "severity": "info",
                "title": f"Web Server: {results['server']}",
                "detail": f"Detected from HTTP headers",
            })
            # Check for outdated server versions
            outdated = self._check_outdated_server(results["server"])
            if outdated:
                findings.append({
                    "severity": "high",
                    "title": f"Potentially Outdated: {outdated}",
                    "detail": f"Server: {results['server']}",
                })

        if results["cms"]:
            cms_entry = next((t for t in results["technologies"] if t["name"] == results["cms"]), None)
            ver_str = f" v{cms_entry['version']}" if cms_entry and cms_entry["version"] else ""
            findings.append({
                "severity": "info",
                "title": f"CMS: {results['cms']}{ver_str}",
                "detail": f"CMS-specific attack surface: admin panels, plugins, themes",
            })

        if results["waf"]:
            findings.append({
                "severity": "info",
                "title": f"WAF Detected: {results['waf']}",
                "detail": "Active WAF — may need evasion for aggressive testing",
            })

        if results["cdn"]:
            findings.append({
                "severity": "info",
                "title": f"CDN: {results['cdn']}",
                "detail": "Traffic proxied through CDN",
            })

        if results["frameworks"]:
            findings.append({
                "severity": "info",
                "title": f"Frameworks: {', '.join(results['frameworks'])}",
                "detail": "Server-side frameworks detected — target framework-specific vulns",
            })

        if results["js_libraries"]:
            findings.append({
                "severity": "info",
                "title": f"JS Libraries: {', '.join(results['js_libraries'])}",
                "detail": "Client-side libraries — check for known CVEs in detected versions",
            })

        if results["analytics"]:
            findings.append({
                "severity": "info",
                "title": f"Analytics/Tracking: {', '.join(results['analytics'])}",
                "detail": "Third-party tracking scripts loaded",
            })

        if results["payment"]:
            findings.append({
                "severity": "medium",
                "title": f"Payment Processors: {', '.join(results['payment'])}",
                "detail": "Payment integrations found — high-value target for logic/IDOR bugs",
            })

        if results["security"]:
            findings.append({
                "severity": "info",
                "title": f"Security: {', '.join(results['security'])}",
                "detail": "Security products detected",
            })

        if results["hosting"]:
            findings.append({
                "severity": "info",
                "title": f"Hosting/PaaS: {results['hosting']}",
                "detail": "Hosting platform identified",
            })

        if results["ssl_info"]:
            issuer = results["ssl_info"].get("issuer", "")
            san_count = len(results["ssl_info"].get("san", []))
            findings.append({
                "severity": "info",
                "title": f"SSL Issuer: {issuer}",
                "detail": f"Certificate SANs: {san_count} entries",
            })

        if results["technologies"]:
            # Group by category for the detail line
            top_cats = sorted(results["by_category"].items(), key=lambda x: -len(x[1]))[:5]
            cat_summary = "; ".join(f"{cat}: {', '.join(techs[:3])}" for cat, techs in top_cats)
            findings.append({
                "severity": "info",
                "title": f"Fingerprint: {results['tech_count']} Technologies Detected",
                "detail": cat_summary,
            })

        return {
            "module": self.name,
            "target": domain,
            "findings": findings,
            "data": results,
        }

    def _check_outdated_server(self, server_str: str) -> str:
        """Check if server version is outdated."""
        checks = [
            (r"Apache/2\.[0-3]\.", "Apache 2.0-2.3 (EOL)"),
            (r"Apache/2\.4\.[0-9][^-]", "Apache 2.4.0-2.4.9 (multiple CVEs)"),
            (r"nginx/1\.(0|1|2|3|4|5|6|7|8|9|1[0-4])\.", "nginx <1.25 (check CVEs)"),
            (r"Microsoft-IIS/[6-8]\.", "IIS 6-8 (multiple CVEs)"),
            (r"PHP/[45]\.", "PHP 4/5 (EOL)"),
            (r"PHP/7\.[0-3]\.", "PHP 7.0-7.3 (EOL)"),
            (r"PHP/8\.0", "PHP 8.0 (EOL)"),
            (r"OpenSSL/1\.0", "OpenSSL 1.0 (EOL)"),
            (r"Apache-Coyote", "Apache Coyote (old Tomcat connector)"),
        ]
        for pattern, desc in checks:
            if re.search(pattern, server_str, re.IGNORECASE):
                return desc
        return ""


def cat_is(categories: list, *ids: int) -> bool:
    """Check if any of the category IDs match."""
    return any(c in categories for c in ids)
