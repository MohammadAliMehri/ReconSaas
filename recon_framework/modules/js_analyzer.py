"""
JavaScript Analyzer Module — Passive
Mines JS bundles for API endpoints, secrets, internal paths, and routes.
"""
import re
import json
from .base import BaseModule
from ..utils.networking import HttpClient


class JSAnalyzer(BaseModule):
    name = "js_analyzer"
    description = "JavaScript Bundle Analysis"
    mode = "passive"

    # Regex patterns for finding secrets and endpoints
    PATTERNS = {
        "api_endpoint": re.compile(
            r'(?:"|\'|`)(/api/[a-zA-Z0-9/_-]+|https?://[a-zA-Z0-9.-]+/api/[a-zA-Z0-9/_-]+)(?:"|\'|`)',
            re.IGNORECASE,
        ),
        "graphql": re.compile(
            r'(?:"|\'|`)(/graphql|/gql|/query)(?:"|\'|`)',
            re.IGNORECASE,
        ),
        "swagger": re.compile(
            r'(?:"|\'|`)(/(?:swagger|openapi|api-docs)[^"\']*\.?(?:json|yaml)?)(?:"|\'|`)',
            re.IGNORECASE,
        ),
        "aws_key": re.compile(r'(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}'),
        "aws_secret": re.compile(r'(?i)aws_secret_access_key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})'),
        "generic_secret": re.compile(
            r'(?i)(?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|secret[_-]?key|'
            r'private[_-]?key|client[_-]?secret|app[_-]?secret)\s*[=:]\s*["\']([A-Za-z0-9_\-./+=]{16,})["\']',
        ),
        "jwt": re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-]+'),
        "internal_url": re.compile(
            r'https?://(?:internal|admin|staging|dev|test|qa|beta|stage|pre-prod|preprod)[-.][a-zA-Z0-9.-]+',
            re.IGNORECASE,
        ),
        "s3_bucket": re.compile(
            r'(?:https?://)?[a-zA-Z0-9.-]*\.s3[.-](?:[a-z0-9-]+\.)?amazonaws\.com|'
            r's3://[a-zA-Z0-9][a-zA-Z0-9.-]*',
            re.IGNORECASE,
        ),
        "ip_address": re.compile(r'\b(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}\b'),
        "route_path": re.compile(
            r'(?:"|\'|`)(/[a-zA-Z0-9/_-]{3,})(?:"|\'|`)\s*[,;\)]',
        ),
        "fetch_call": re.compile(
            r'(?:(?:fetch|axios|http|request)\s*\(|'
            r'\.(?:get|post|put|patch|delete|head)\s*\()\s*["\'`]'
            r'([^"\'`]+)["\'`]',
            re.IGNORECASE,
        ),
        "env_variable": re.compile(
            r'(?:process\.env|import\.meta\.env)\.([A-Z_][A-Z0-9_]*)',
        ),
        "base64_blob": re.compile(
            r'(?:atob\s*\(\s*["\']|btoa\s*\(\s*["\']|base64,)([A-Za-z0-9+/=]{20,})',
        ),
    }

    async def run(self, target: str) -> dict:
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        base_url = f"https://{domain}"
        results = {
            "js_files": [],
            "endpoints": set(),
            "secrets": [],
            "internal_urls": set(),
            "routes": set(),
            "env_vars": set(),
            "s3_buckets": set(),
            "internal_ips": set(),
            "graphql_endpoints": set(),
        }
        findings = []

        async with HttpClient(timeout=30, rate_limit=0.5) as client:
            # First, fetch the main page to find JS files
            try:
                resp = await client.get(base_url)
                html = resp.text
                
                # Extract JS file URLs
                js_pattern = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.IGNORECASE)
                js_urls = js_pattern.findall(html)
                
                # Also check for inline scripts with interesting content
                inline_scripts = re.compile(r'<script[^>]*>(.*?)</script>', re.DOTALL | re.IGNORECASE)
                for match in inline_scripts.finditer(html):
                    script_content = match.group(1)
                    if len(script_content) > 50:  # Skip tiny scripts
                        self._analyze_script(script_content, base_url, results)

                # Also look for link preload of JS
                preload_pattern = re.compile(r'<link[^>]+href=["\']([^"\']+\.js[^"\']*)["\']', re.IGNORECASE)
                js_urls.extend(preload_pattern.findall(html))

                # Resolve relative URLs and deduplicate
                full_js_urls = set()
                for url in js_urls:
                    if url.startswith("//"):
                        full_js_urls.add(f"https:{url}")
                    elif url.startswith("/"):
                        full_js_urls.add(f"{base_url}{url}")
                    elif url.startswith("http"):
                        full_js_urls.add(url)
                    else:
                        full_js_urls.add(f"{base_url}/{url}")

                # Fetch and analyze each JS file
                for js_url in sorted(full_js_urls):
                    if domain in js_url or js_url.startswith("/"):
                        try:
                            js_resp = await client.get(js_url)
                            if js_resp.status_code == 200 and len(js_resp.text) > 10:
                                self._analyze_script(js_resp.text, js_url, results)
                                results["js_files"].append({
                                    "url": js_url,
                                    "size": len(js_resp.text),
                                    "status": js_resp.status_code,
                                })
                        except Exception as e:
                            self.logger.debug(f"Failed to fetch {js_url}: {e}")

                # Try common JS bundle paths
                common_bundles = [
                    "/static/js/main.js", "/static/js/app.js", "/static/js/bundle.js",
                    "/js/main.js", "/js/app.js", "/assets/js/main.js",
                    "/_next/static/chunks/main.js", "/_next/static/chunks/pages/_app.js",
                    "/build/static/js/main.js", "/dist/js/app.js",
                ]
                for path in common_bundles:
                    try:
                        resp = await client.get(f"{base_url}{path}", follow_redirects=True)
                        if resp.status_code == 200 and len(resp.text) > 50:
                            self._analyze_script(resp.text, f"{base_url}{path}", results)
                            if not any(f["url"] == f"{base_url}{path}" for f in results["js_files"]):
                                results["js_files"].append({
                                    "url": f"{base_url}{path}",
                                    "size": len(resp.text),
                                    "status": resp.status_code,
                                })
                    except Exception:
                        pass

            except Exception as e:
                self.logger.error(f"Failed to fetch main page: {e}")

        # Convert sets for JSON
        results["endpoints"] = sorted(results["endpoints"])
        results["internal_urls"] = sorted(results["internal_urls"])
        results["routes"] = sorted(results["routes"])
        results["env_vars"] = sorted(results["env_vars"])
        results["s3_buckets"] = sorted(results["s3_buckets"])
        results["internal_ips"] = sorted(results["internal_ips"])
        results["graphql_endpoints"] = sorted(results["graphql_endpoints"])

        # Generate findings
        if results["secrets"]:
            findings.append({
                "severity": "critical",
                "title": f"Secrets Found in JavaScript ({len(results['secrets'])})",
                "detail": f"API keys, tokens, or credentials exposed in JS bundles",
                "evidence": results["secrets"][:10],
            })

        if results["internal_urls"]:
            findings.append({
                "severity": "high",
                "title": f"Internal URLs in JavaScript ({len(results['internal_urls'])})",
                "detail": "Internal/staging/dev URLs leaked in client-side code",
                "evidence": sorted(results["internal_urls"])[:15],
            })

        if results["endpoints"]:
            findings.append({
                "severity": "medium",
                "title": f"API Endpoints in JavaScript ({len(results['endpoints'])})",
                "detail": "API paths and routes discovered from JS bundles",
                "evidence": sorted(results["endpoints"])[:20],
            })

        if results["s3_buckets"]:
            findings.append({
                "severity": "high",
                "title": f"S3 Buckets Referenced in JavaScript ({len(results['s3_buckets'])})",
                "detail": "Cloud storage buckets found in JS code",
                "evidence": sorted(results["s3_buckets"]),
            })

        if results["internal_ips"]:
            findings.append({
                "severity": "medium",
                "title": f"Internal IPs in JavaScript ({len(results['internal_ips'])})",
                "detail": "Private IP addresses leaked in client-side code",
                "evidence": sorted(results["internal_ips"]),
            })

        if results["env_vars"]:
            findings.append({
                "severity": "info",
                "title": f"Environment Variables Referenced ({len(results['env_vars'])})",
                "detail": "process.env variables may leak configuration",
                "evidence": sorted(results["env_vars"])[:20],
            })

        findings.append({
            "severity": "info",
            "title": f"JS Analysis: {len(results['js_files'])} Files Analyzed",
            "detail": f"{len(results['endpoints'])} endpoints, {len(results['secrets'])} potential secrets",
        })

        return {
            "module": self.name,
            "target": domain,
            "findings": findings,
            "data": results,
        }

    def _analyze_script(self, content: str, source: str, results: dict):
        """Analyze a JS script for interesting patterns."""
        # Find API endpoints
        for match in self.PATTERNS["api_endpoint"].finditer(content):
            endpoint = match.group(1)
            results["endpoints"].add(endpoint)

        # Find GraphQL endpoints
        for match in self.PATTERNS["graphql"].finditer(content):
            results["graphql_endpoints"].add(match.group(1))

        # Find swagger/openapi
        for match in self.PATTERNS["swagger"].finditer(content):
            results["endpoints"].add(match.group(1))

        # Find fetch calls
        for match in self.PATTERNS["fetch_call"].finditer(content):
            url = match.group(1)
            if url.startswith("/") or "api" in url.lower():
                results["endpoints"].add(url)

        # Find route paths
        for match in self.PATTERNS["route_path"].finditer(content):
            path = match.group(1)
            if len(path) > 3 and not path.startswith("//") and "/" in path[1:]:
                # Filter out common false positives
                if not any(fp in path.lower() for fp in ["/node_modules", "/dist/", "/build/", ".css", ".png", ".jpg"]):
                    results["routes"].add(path)

        # Find AWS keys
        for match in self.PATTERNS["aws_key"].finditer(content):
            results["secrets"].append({
                "type": "aws_key",
                "value": match.group()[:20] + "...",
                "source": source,
            })

        # Find generic secrets
        for match in self.PATTERNS["generic_secret"].finditer(content):
            results["secrets"].append({
                "type": "api_secret",
                "key": match.group(0).split("=")[0].split(":")[0].strip(),
                "value": match.group(1)[:10] + "...",
                "source": source,
            })

        # Find JWTs
        for match in self.PATTERNS["jwt"].finditer(content):
            results["secrets"].append({
                "type": "jwt_token",
                "value": match.group()[:30] + "...",
                "source": source,
            })

        # Find internal URLs
        for match in self.PATTERNS["internal_url"].finditer(content):
            results["internal_urls"].add(match.group())

        # Find S3 buckets
        for match in self.PATTERNS["s3_bucket"].finditer(content):
            results["s3_buckets"].add(match.group())

        # Find internal IPs
        for match in self.PATTERNS["ip_address"].finditer(content):
            results["internal_ips"].add(match.group())

        # Find env variables
        for match in self.PATTERNS["env_variable"].finditer(content):
            results["env_vars"].add(match.group(1))
