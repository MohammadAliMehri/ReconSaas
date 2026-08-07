"""
Header Analysis Module — Active
Analyzes security headers, CORS, CSP, cookie flags.
"""
import re
from .base import BaseModule
from ..utils.networking import HttpClient
from ..config import SECURITY_HEADERS


class HeaderAnalysis(BaseModule):
    name = "header_analysis"
    description = "Security Header & CORS Analysis"
    mode = "active"

    async def run(self, target: str) -> dict:
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        base_url = f"https://{domain}"
        results = {
            "headers": {},
            "missing_headers": [],
            "cors": None,
            "csp": None,
            "cookies": [],
            "redirect_chain": [],
            "mixed_content": False,
        }
        findings = []

        async with HttpClient(timeout=30, rate_limit=0.5, follow_redirects=False) as client:
            try:
                # Get main page headers
                resp = await client.get(base_url)
                headers = dict(resp.headers)
                results["headers"] = {k: v[:500] for k, v in headers.items()}

                # Check security headers
                for header, info in SECURITY_HEADERS.items():
                    if header in headers:
                        findings.append({
                            "severity": info["severity"],
                            "title": f"{header}: Present",
                            "detail": f"{info['present']}: {headers[header][:200]}",
                        })
                    else:
                        results["missing_headers"].append(header)
                        findings.append({
                            "severity": info["severity"],
                            "title": f"Missing: {header}",
                            "detail": info["missing"],
                        })

                # CORS Analysis
                cors_headers = {
                    "Access-Control-Allow-Origin": headers.get("Access-Control-Allow-Origin"),
                    "Access-Control-Allow-Credentials": headers.get("Access-Control-Allow-Credentials"),
                    "Access-Control-Allow-Methods": headers.get("Access-Control-Allow-Methods"),
                    "Access-Control-Allow-Headers": headers.get("Access-Control-Allow-Headers"),
                    "Access-Control-Expose-Headers": headers.get("Access-Control-Expose-Headers"),
                    "Access-Control-Max-Age": headers.get("Access-Control-Max-Age"),
                }
                cors_headers = {k: v for k, v in cors_headers.items() if v}
                
                if cors_headers:
                    results["cors"] = cors_headers
                    
                    acao = cors_headers.get("Access-Control-Allow-Origin", "")
                    acac = cors_headers.get("Access-Control-Allow-Credentials", "").lower()
                    
                    if acao == "*":
                        if acac == "true":
                            findings.append({
                                "severity": "critical",
                                "title": "CORS: Wildcard with Credentials",
                                "detail": "Access-Control-Allow-Origin: * with Allow-Credentials: true. Allows cross-origin credential theft.",
                            })
                        else:
                            findings.append({
                                "severity": "low",
                                "title": "CORS: Wildcard Origin (no credentials)",
                                "detail": "ACAO: * without credentials. May allow reading public data cross-origin.",
                            })
                    elif acao == "null":
                        findings.append({
                            "severity": "high",
                            "title": "CORS: null Origin Allowed",
                            "detail": "ACAO: null allows sandboxed iframes to access data. Exploitable via data: URIs.",
                        })
                    elif acac == "true" and acao != "*":
                        # Check if origin is reflected
                        findings.append({
                            "severity": "medium",
                            "title": "CORS: Origin Reflected with Credentials",
                            "detail": f"ACAO reflects origin with credentials. Test if arbitrary origins are reflected.",
                        })

                # CSP Analysis
                csp = headers.get("Content-Security-Policy", "")
                if csp:
                    results["csp"] = csp
                    csp_findings = self._analyze_csp(csp)
                    findings.extend(csp_findings)
                else:
                    # Check meta CSP
                    meta_csp_match = re.search(
                        r'<meta[^>]+http-equiv=["\']Content-Security-Policy["\'][^>]+content=["\']([^"\']+)',
                        (await client.get(base_url)).text, re.I
                    )
                    if meta_csp_match:
                        results["csp"] = meta_csp_match.group(1)
                        findings.extend(self._analyze_csp(meta_csp_match.group(1)))

                # Cookie Analysis
                for cookie in resp.cookies.jar:
                    cookie_info = {
                        "name": cookie.name,
                        "domain": cookie.domain,
                        "path": cookie.path,
                        "secure": cookie.secure,
                        "httponly": "httponly" in str(cookie).lower(),
                    }
                    results["cookies"].append(cookie_info)
                    
                    issues = []
                    if not cookie.secure:
                        issues.append("missing Secure flag")
                    if "httponly" not in str(cookie).lower():
                        issues.append("missing HttpOnly flag")
                    if issues:
                        findings.append({
                            "severity": "medium",
                            "title": f"Cookie '{cookie.name}': {', '.join(issues)}",
                            "detail": f"Cookie may be vulnerable to interception or XSS theft",
                        })

                # Check for mixed content (HTTP resources on HTTPS page)
                if base_url.startswith("https"):
                    body = (await client.get(base_url)).text
                    http_resources = re.findall(r'(?:src|href|action)=["\']http://[^"\']+["\']', body, re.I)
                    if http_resources:
                        results["mixed_content"] = True
                        findings.append({
                            "severity": "medium",
                            "title": f"Mixed Content: {len(http_resources)} HTTP resources on HTTPS page",
                            "detail": "HTTPS page loads resources over HTTP, allowing MITM",
                        })

                # Check redirect chain
                current_url = base_url
                for _ in range(5):
                    r = await client.get(current_url, follow_redirects=False)
                    if r.status_code in (301, 302, 303, 307, 308):
                        location = r.headers.get("Location", "")
                        results["redirect_chain"].append({
                            "from": current_url,
                            "to": location,
                            "status": r.status_code,
                        })
                        # Check for open redirect patterns
                        if location and not location.startswith("/") and domain not in location:
                            findings.append({
                                "severity": "medium",
                                "title": "External Redirect Detected",
                                "detail": f"{current_url} redirects to {location}",
                            })
                        current_url = location if location.startswith("http") else f"https://{domain}{location}"
                    else:
                        break

                # Check X-Powered-By (info disclosure)
                if "X-Powered-By" in headers:
                    findings.append({
                        "severity": "low",
                        "title": "X-Powered-By Header Exposed",
                        "detail": f"Technology disclosed: {headers['X-Powered-By']}",
                    })

                # Check Server header (info disclosure)
                if "Server" in headers:
                    server = headers["Server"]
                    if any(v in server.lower() for v in ["version", "/", "microsoft", "apache/", "nginx/"]):
                        findings.append({
                            "severity": "low",
                            "title": "Server Version Disclosed",
                            "detail": f"Server: {server}",
                        })

            except Exception as e:
                self.logger.error(f"Header analysis failed: {e}")

        return {
            "module": self.name,
            "target": domain,
            "findings": findings,
            "data": results,
        }

    def _analyze_csp(self, csp: str) -> list:
        """Analyze Content-Security-Policy header."""
        findings = []
        csp_lower = csp.lower()

        # Check for unsafe directives
        if "'unsafe-inline'" in csp_lower:
            findings.append({
                "severity": "medium",
                "title": "CSP: 'unsafe-inline' Present",
                "detail": "Allows inline scripts/styles. Weakens XSS protection.",
            })

        if "'unsafe-eval'" in csp_lower:
            findings.append({
                "severity": "medium",
                "title": "CSP: 'unsafe-eval' Present",
                "detail": "Allows eval(). May enable XSS via eval-based sinks.",
            })

        if "data:" in csp_lower:
            findings.append({
                "severity": "low",
                "title": "CSP: data: URI Allowed",
                "detail": "data: URIs can be used to bypass script-src in some browsers.",
            })

        # Check for overly permissive sources
        if "script-src" in csp_lower:
            if "*." in csp and "script-src" in csp:
                # Wildcard subdomain in script-src
                wildcards = re.findall(r'script-src[^;]*(\*\.[a-zA-Z0-9.-]+)', csp)
                for wc in wildcards:
                    findings.append({
                        "severity": "medium",
                        "title": f"CSP: Wildcard Script Source ({wc})",
                        "detail": f"Any subdomain of {wc} can serve scripts. Check for subdomain takeover.",
                    })

        # Check for report-uri (can be used for exfil)
        if "report-uri" in csp_lower or "report-to" in csp_lower:
            report_match = re.search(r'report-uri\s+([^\s;]+)', csp, re.I)
            if report_match:
                findings.append({
                    "severity": "info",
                    "title": "CSP: report-uri Configured",
                    "detail": f"CSP reports sent to: {report_match.group(1)[:100]}",
                })

        # Check for missing base-uri
        if "base-uri" not in csp_lower and "script-src" in csp_lower:
            findings.append({
                "severity": "low",
                "title": "CSP: Missing base-uri Directive",
                "detail": "Without base-uri, <base> tag can redirect relative URLs.",
            })

        return findings
