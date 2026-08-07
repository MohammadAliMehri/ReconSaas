"""
Wayback Machine URL Discovery — Passive
Finds historical URLs, deleted endpoints, old admin panels.
"""
import json
from .base import BaseModule
from ..utils.networking import HttpClient


class WaybackURLs(BaseModule):
    name = "wayback_urls"
    description = "Wayback Machine URL Discovery"
    mode = "passive"

    # Interesting extensions that may contain sensitive data
    SENSITIVE_EXTENSIONS = {
        ".sql", ".bak", ".old", ".zip", ".tar.gz", ".tar", ".gz",
        ".conf", ".config", ".cfg", ".ini", ".env", ".properties",
        ".xml", ".json", ".yaml", ".yml", ".toml",
        ".log", ".txt", ".csv", ".xls", ".xlsx", ".doc", ".docx", ".pdf",
        ".pem", ".key", ".crt", ".cer", ".p12", ".pfx",
        ".swp", ".swo", "~",
    }

    # Interesting path patterns
    INTERESTING_PATHS = [
        "/admin", "/internal", "/api/", "/graphql", "/swagger", "/docs",
        "/debug", "/console", "/shell", "/manager", "/wp-admin",
        "/phpmyadmin", "/.git", "/.svn", "/.env", "/config",
        "/backup", "/test", "/dev", "/staging", "/login", "/auth",
    ]

    async def run(self, target: str) -> dict:
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        results = {
            "total_urls": 0,
            "urls": [],
            "sensitive_files": [],
            "interesting_paths": [],
            "status_codes": {},
            "unique_paths": set(),
        }
        findings = []

        async with HttpClient(timeout=120, rate_limit=2.0) as client:
            try:
                # Wayback Machine CDX API
                url = (
                    f"https://web.archive.org/cdx/search/cdx?"
                    f"url={domain}/*&output=json&fl=original,statuscode,mimetype,timestamp"
                    f"&collapse=urlkey&limit=10000"
                )
                resp = await client.get(url)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                    except json.JSONDecodeError:
                        data = []
                    
                    if len(data) > 1:
                        # First row is headers
                        headers_row = data[0]
                        urls_data = data[1:]
                        
                        for row in urls_data:
                            entry = {
                                "url": row[0] if len(row) > 0 else "",
                                "status": row[1] if len(row) > 1 else "",
                                "mimetype": row[2] if len(row) > 2 else "",
                                "timestamp": row[3] if len(row) > 3 else "",
                            }
                            results["urls"].append(entry)
                            
                            # Track status codes
                            status = entry["status"]
                            if status:
                                results["status_codes"][status] = results["status_codes"].get(status, 0) + 1
                            
                            # Check for sensitive extensions
                            url_lower = entry["url"].lower()
                            for ext in self.SENSITIVE_EXTENSIONS:
                                if url_lower.endswith(ext) or f"{ext}?" in url_lower:
                                    results["sensitive_files"].append(entry["url"])
                                    break
                            
                            # Check for interesting paths
                            for path in self.INTERESTING_PATHS:
                                if path in url_lower:
                                    results["interesting_paths"].append(entry["url"])
                                    break
                            
                            # Track unique paths
                            from urllib.parse import urlparse
                            parsed = urlparse(entry["url"])
                            results["unique_paths"].add(parsed.path)

                        results["total_urls"] = len(results["urls"])

                        # Generate findings
                        if results["sensitive_files"]:
                            findings.append({
                                "severity": "high",
                                "title": f"Sensitive Files in Wayback ({len(results['sensitive_files'])})",
                                "detail": f"Found {len(results['sensitive_files'])} potentially sensitive files (backups, configs, DB dumps)",
                                "evidence": results["sensitive_files"][:20],
                            })

                        if results["interesting_paths"]:
                            unique_paths = list(set([
                                u.split("?")[0] for u in results["interesting_paths"]
                            ]))[:30]
                            findings.append({
                                "severity": "medium",
                                "title": f"Interesting Historical Paths ({len(results['interesting_paths'])})",
                                "detail": f"Admin panels, APIs, debug endpoints found in web archive",
                                "evidence": unique_paths,
                            })

                        # Check for 404 vs 200 patterns (may indicate deleted sensitive content)
                        deleted_sensitive = [
                            u for u in results["sensitive_files"]
                            if any(s in u.lower() for s in [".sql", ".bak", ".env", ".git", ".config"])
                        ]
                        if deleted_sensitive:
                            findings.append({
                                "severity": "medium",
                                "title": "Deleted Sensitive Files Found in Archive",
                                "detail": f"{len(deleted_sensitive)} sensitive files were once live (may still be accessible)",
                                "evidence": deleted_sensitive[:10],
                            })

                        findings.append({
                            "severity": "info",
                            "title": f"Wayback Machine: {results['total_urls']} Historical URLs",
                            "detail": f"{len(results['unique_paths'])} unique paths, status codes: {dict(list(results['status_codes'].items())[:5])}",
                        })
                else:
                    self.logger.warning(f"Wayback API returned {resp.status_code}")

            except Exception as e:
                self.logger.error(f"Wayback query failed: {e}")

        # Convert sets for JSON
        results["unique_paths"] = sorted(results["unique_paths"])

        return {
            "module": self.name,
            "target": domain,
            "findings": findings,
            "data": results,
        }
