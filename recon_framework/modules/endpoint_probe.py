"""
Endpoint Probe Module — Active
Discovers API docs, GraphQL, robots.txt, sitemap.xml, common endpoints.
"""
import re
import json
from .base import BaseModule
from ..utils.networking import HttpClient


class EndpointProbe(BaseModule):
    name = "endpoint_probe"
    description = "API & Endpoint Discovery"
    mode = "active"

    ENDPOINTS_TO_PROBE = [
        # API documentation
        ("/swagger", "Swagger UI"),
        ("/swagger/ui", "Swagger UI"),
        ("/swagger-ui.html", "Swagger UI"),
        ("/swagger/index.html", "Swagger UI"),
        ("/api-docs", "API Docs"),
        ("/api/docs", "API Docs"),
        ("/openapi.json", "OpenAPI Spec"),
        ("/swagger.json", "Swagger Spec"),
        ("/swagger.yaml", "Swagger Spec"),
        ("/redoc", "ReDoc"),
        ("/rapidoc", "RapiDoc"),
        ("/v1/swagger", "V1 Swagger"),
        ("/v2/swagger", "V2 Swagger"),
        # GraphQL
        ("/graphql", "GraphQL"),
        ("/gql", "GraphQL"),
        ("/query", "GraphQL Query"),
        ("/graphiql", "GraphiQL"),
        ("/graphql/console", "GraphQL Console"),
        ("/playground", "GraphQL Playground"),
        # Common API versions
        ("/api/v1", "API v1"),
        ("/api/v2", "API v2"),
        ("/api/v3", "API v3"),
        ("/v1", "v1 API"),
        ("/v2", "v2 API"),
        ("/api/internal", "Internal API"),
        ("/api/admin", "Admin API"),
        ("/api/debug", "Debug API"),
        # Common paths
        ("/robots.txt", "Robots.txt"),
        ("/sitemap.xml", "Sitemap"),
        ("/sitemap.xml.gz", "Sitemap (gzipped)"),
        ("/crossdomain.xml", "Cross-domain Policy"),
        ("/clientaccesspolicy.xml", "Client Access Policy"),
        ("/.well-known/security.txt", "Security.txt"),
        ("/security.txt", "Security.txt"),
        ("/humans.txt", "Humans.txt"),
        ("/favicon.ico", "Favicon"),
        ("/manifest.json", "Web Manifest"),
        ("/service-worker.js", "Service Worker"),
        ("/.well-known/openid-configuration", "OpenID Configuration"),
        ("/.well-known/jwks.json", "JWKS"),
        ("/.well-known/assetlinks.json", "Asset Links"),
        ("/.well-known/apple-app-site-association", "Apple App Site Assoc"),
        # Common frameworks
        ("/wp-json", "WordPress REST API"),
        ("/wp-json/wp/v2/users", "WordPress Users API"),
        ("/wp-login.php", "WordPress Login"),
        ("/xmlrpc.php", "WordPress XML-RPC"),
        ("/api/users", "Users API"),
        ("/api/user", "User API"),
        ("/api/me", "Current User API"),
        ("/api/config", "Config API"),
        ("/api/health", "Health API"),
        ("/api/status", "Status API"),
        ("/health", "Health Check"),
        ("/healthcheck", "Health Check"),
        ("/ping", "Ping"),
        ("/status", "Status"),
        ("/metrics", "Metrics"),
        ("/actuator", "Spring Actuator"),
        ("/actuator/health", "Actuator Health"),
        ("/actuator/env", "Actuator Env"),
        ("/actuator/info", "Actuator Info"),
        ("/actuator/mappings", "Actuator Mappings"),
        # Cloud / infra
        ("/.aws/", "AWS Config"),
        ("/.azure/", "Azure Config"),
        ("/docker-compose.yml", "Docker Compose"),
        ("/Dockerfile", "Dockerfile"),
        ("/.git/config", "Git Config"),
        ("/.git/HEAD", "Git HEAD"),
        ("/.svn/entries", "SVN Entries"),
        # Misc
        ("/elmah.axd", "ELMAH Error Log"),
        ("/trace.axd", "ASP.NET Trace"),
        ("/server-status", "Apache Server Status"),
        ("/server-info", "Apache Server Info"),
        ("/jolokia", "Jolokia JMX"),
        ("/.env", "Environment File"),
        ("/config.json", "Config JSON"),
        ("/debug", "Debug Endpoint"),
        ("/debug/vars", "Debug Vars"),
        ("/debug/pprof", "Go pprof"),
        ("/info.php", "PHP Info"),
        ("/test.php", "Test PHP"),
    ]

    async def run(self, target: str) -> dict:
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        base_url = f"https://{domain}"
        results = {
            "discovered": [],
            "swagger_specs": [],
            "graphql_introspection": None,
            "robots_txt": None,
            "sitemap": None,
            "security_txt": None,
            "total_probed": 0,
        }
        findings = []

        async with HttpClient(timeout=15, rate_limit=0.2, follow_redirects=True) as client:
            semaphore = asyncio.Semaphore(self.config.threads)
            import asyncio

            async def probe(path: str, label: str):
                async with semaphore:
                    try:
                        url = f"{base_url}{path}"
                        resp = await client.get(url, follow_redirects=False)
                        results["total_probed"] += 1
                        
                        if resp.status_code in (200, 201, 301, 302):
                            content = resp.text[:5000]
                            entry = {
                                "path": path,
                                "url": url,
                                "status": resp.status_code,
                                "label": label,
                                "size": len(resp.text),
                                "content_type": resp.headers.get("content-type", ""),
                            }
                            results["discovered"].append(entry)
                            
                            # Special handling for specific endpoints
                            if "swagger" in label.lower() or "openapi" in label.lower():
                                results["swagger_specs"].append(entry)
                            
                            if "graphql" in label.lower():
                                await self._probe_graphql(client, url, results, findings)
                            
                            if label == "Robots.txt":
                                results["robots_txt"] = content
                                self._parse_robots(content, findings)
                            
                            if label == "Sitemap":
                                results["sitemap"] = content[:1000]
                            
                            if label == "Security.txt":
                                results["security_txt"] = content
                                self._parse_security_txt(content, findings)
                            
                            if "actuator" in path.lower() and resp.status_code == 200:
                                try:
                                    data = resp.json()
                                    findings.append({
                                        "severity": "critical",
                                        "title": f"Spring Actuator Exposed: {path}",
                                        "detail": f"Actuator endpoint accessible. May leak env vars, beans, config.",
                                    })
                                except Exception:
                                    pass

                    except Exception:
                        pass

            # Probe all endpoints
            tasks = [probe(path, label) for path, label in self.ENDPOINTS_TO_PROBE]
            await asyncio.gather(*tasks, return_exceptions=True)

        # Generate findings
        if results["swagger_specs"]:
            for spec in results["swagger_specs"]:
                findings.append({
                    "severity": "high",
                    "title": f"API Documentation Exposed: {spec['path']}",
                    "detail": f"{spec['label']} accessible at {spec['url']}",
                })

        if results["graphql_introspection"]:
            findings.append({
                "severity": "high",
                "title": "GraphQL Introspection Enabled",
                "detail": "Full schema readable. May expose all types, queries, mutations.",
                "evidence": results["graphql_introspection"],
            })

        if results["discovered"]:
            findings.append({
                "severity": "info",
                "title": f"Endpoint Discovery: {len(results['discovered'])} Endpoints Found",
                "detail": f"Probed {results['total_probed']} paths. {len(results['swagger_specs'])} API docs, {len(results['discovered'])} live endpoints.",
            })

        return {
            "module": self.name,
            "target": domain,
            "findings": findings,
            "data": results,
        }

    async def _probe_graphql(self, client, url: str, results: dict, findings: list):
        """Probe GraphQL endpoint for introspection."""
        introspection_query = {
            "query": """
            {
                __schema {
                    queryType { name }
                    mutationType { name }
                    types {
                        name
                        kind
                        fields {
                            name
                            type { name kind }
                        }
                    }
                }
            }
            """
        }
        try:
            resp = await client.post(url, json_data=introspection_query)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if "__schema" in str(data) or "data" in str(data):
                        types = []
                        if isinstance(data.get("data"), dict):
                            schema = data["data"].get("__schema", {})
                            types = [t["name"] for t in schema.get("types", []) 
                                    if not t["name"].startswith("__")]
                        results["graphql_introspection"] = {
                            "types_count": len(types),
                            "types": types[:30],
                        }
                except Exception:
                    pass
        except Exception:
            pass

    def _parse_robots(self, content: str, findings: list):
        """Parse robots.txt for interesting paths."""
        paths = []
        for line in content.split("\n"):
            line = line.strip()
            if line.lower().startswith(("disallow:", "allow:")):
                path = line.split(":", 1)[1].strip()
                if path and path != "/":
                    paths.append(path)
        
        if paths:
            # Check for admin/secret paths
            interesting = [p for p in paths if any(
                kw in p.lower() for kw in ["admin", "internal", "private", "secret", "api", "config", "debug"]
            )]
            if interesting:
                findings.append({
                    "severity": "medium",
                    "title": f"Interesting Paths in robots.txt ({len(interesting)})",
                    "detail": f"Potentially sensitive paths: {', '.join(interesting[:10])}",
                })
            findings.append({
                "severity": "info",
                "title": f"robots.txt: {len(paths)} Paths Listed",
                "detail": f"Disallowed paths reveal application structure",
            })

    def _parse_security_txt(self, content: str, findings: list):
        """Parse security.txt for useful info."""
        contacts = re.findall(r'Contact:\s*(.+)', content, re.I)
        if contacts:
            findings.append({
                "severity": "info",
                "title": "security.txt: Contact Info Found",
                "detail": f"Contacts: {', '.join(c.strip() for c in contacts[:3])}",
            })
