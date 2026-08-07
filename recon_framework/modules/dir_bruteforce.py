"""
Directory Bruteforce Module — Active
Discovers hidden directories, backup files, admin panels.
"""
import asyncio
from .base import BaseModule
from ..utils.networking import HttpClient


class DirBruteforce(BaseModule):
    name = "dir_bruteforce"
    description = "Directory & File Bruteforce"
    mode = "active"

    # Built-in wordlist (top entries from common lists)
    COMMON_DIRS = [
        # Admin panels
        "admin", "administrator", "admin-panel", "cpanel", "webmail",
        "phpmyadmin", "adminer", "manager", "panel", "dashboard",
        "console", "control", "cms", "backend", "backoffice",
        # API endpoints
        "api", "api/v1", "api/v2", "api/v3", "api/docs", "api/swagger",
        "graphql", "gql", "query", "rest", "soap", "rpc",
        # Common files
        "robots.txt", "sitemap.xml", "sitemap.xml.gz", "crossdomain.xml",
        "security.txt", ".well-known/security.txt", "humans.txt",
        "favicon.ico", "manifest.json", "browserconfig.xml",
        # Config/backup exposure
        ".env", ".env.local", ".env.production", ".env.staging",
        ".git/HEAD", ".git/config", ".svn/entries", ".hg/dirstate",
        ".htaccess", ".htpasswd", "web.config",
        "wp-config.php.bak", "config.php.bak", "database.yml",
        ".DS_Store", "Thumbs.db", ".bash_history",
        # Backup files
        "backup", "backups", "bak", "old", "archive", "dump",
        "db.sql", "database.sql", "dump.sql", "backup.sql",
        "backup.zip", "backup.tar.gz", "site.zip", "www.zip",
        # Debug/dev
        "debug", "trace", "debug/vars", "debug/pprof",
        "server-status", "server-info", "info.php", "test.php",
        "phpinfo.php", "test", "testing", "dev", "development",
        "staging", "stage", "qa", "uat", "pre-prod",
        # Swagger/docs
        "swagger", "swagger/ui", "swagger-ui.html", "swagger/index.html",
        "docs", "api-docs", "openapi.json", "swagger.json", "swagger.yaml",
        "redoc", "rapidoc",
        # Common app paths
        "login", "signin", "signup", "register", "logout",
        "account", "profile", "settings", "user", "users",
        "search", "feed", "news", "blog", "static",
        "assets", "uploads", "files", "media", "images", "img",
        "fonts", "css", "js", "vendor", "lib",
        # Version control
        ".git", ".svn", ".hg", "CVS",
        ".gitignore", ".svnignore",
        # CI/CD
        "jenkins", "ci", "cd", "deploy", "build",
        ".travis.yml", ".circleci", "Jenkinsfile",
        ".github/workflows", "docker-compose.yml", "Dockerfile",
        # Cloud
        ".aws", ".azure", ".gcp",
        "s3", "bucket",
        # Misc interesting
        "internal", "private", "secret", "hidden",
        "temp", "tmp", "cache", "log", "logs",
        "error", "errors", "404", "500",
        "install", "setup", "upgrade", "migration",
        "status", "health", "healthcheck", "ping",
        "metrics", "prometheus", "grafana", "kibana",
        "actuator", "actuator/health", "actuator/env", "actuator/info",
        "elmah.axd", "trace.axd",
        "wp-admin", "wp-login.php", "wp-content", "wp-includes",
        "xmlrpc.php", "wp-json", "wp-json/wp/v2/users",
    ]

    # Backup extensions to try on discovered files
    BACKUP_EXTENSIONS = [".bak", ".old", ".orig", ".save", ".swp", "~", ".copy", ".tmp"]

    async def run(self, target: str) -> dict:
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        base_url = f"https://{domain}"
        results = {
            "found": [],
            "interesting": [],
            "total_requests": 0,
            "status_codes": {},
        }
        findings = []

        # Get baseline response for comparison
        async with HttpClient(timeout=15, rate_limit=0.2, follow_redirects=False) as client:
            try:
                baseline = await client.get(f"{base_url}/nonexistent-path-8f7a9b2c")
                baseline_status = baseline.status_code
                baseline_len = len(baseline.text)
                baseline_hash = hash(baseline.text[:1000])
            except Exception:
                baseline_status = 404
                baseline_len = 0
                baseline_hash = 0

            # Scan directories
            semaphore = asyncio.Semaphore(self.config.threads)

            async def check_path(path: str):
                async with semaphore:
                    try:
                        url = f"{base_url}/{path}"
                        resp = await client.get(url, follow_redirects=False)
                        results["total_requests"] += 1
                        
                        status = resp.status_code
                        content_len = len(resp.text)
                        content_hash = hash(resp.text[:1000])
                        
                        # Track status codes
                        results["status_codes"][str(status)] = results["status_codes"].get(str(status), 0) + 1
                        
                        # Skip if same as baseline (custom 404 page)
                        if status == baseline_status and abs(content_len - baseline_len) < 50:
                            return
                        
                        # Skip common false positives
                        if status in (404, 410, 502, 503):
                            return
                        
                        # Interesting status codes
                        if status in (200, 301, 302, 303, 307, 308, 401, 403, 405, 500):
                            entry = {
                                "path": path,
                                "url": url,
                                "status": status,
                                "size": content_len,
                                "title": self._extract_title(resp.text),
                            }
                            results["found"].append(entry)
                            
                            severity = self._classify_severity(path, status)
                            if severity != "info":
                                results["interesting"].append(entry)

                    except Exception:
                        pass

            # Run all path checks
            tasks = [check_path(path) for path in self.COMMON_DIRS]
            await asyncio.gather(*tasks, return_exceptions=True)

            # Also try backup extensions on found files
            found_files = [f for f in results["found"] if "." in f["path"].split("/")[-1]]
            backup_tasks = []
            for f in found_files[:20]:  # Limit backup checks
                for ext in self.BACKUP_EXTENSIONS:
                    backup_path = f["path"] + ext
                    backup_tasks.append(check_path(backup_path))
            if backup_tasks:
                await asyncio.gather(*backup_tasks[:100], return_exceptions=True)

        # Generate findings
        critical_paths = [f for f in results["found"] if self._classify_severity(f["path"], f["status"]) == "critical"]
        high_paths = [f for f in results["found"] if self._classify_severity(f["path"], f["status"]) == "high"]
        medium_paths = [f for f in results["found"] if self._classify_severity(f["path"], f["status"]) == "medium"]

        if critical_paths:
            findings.append({
                "severity": "critical",
                "title": f"Critical Paths Found ({len(critical_paths)})",
                "detail": "Exposed sensitive files/paths",
                "evidence": [f"{p['url']} [{p['status']}]" for p in critical_paths[:10]],
            })

        if high_paths:
            findings.append({
                "severity": "high",
                "title": f"High-Interest Paths Found ({len(high_paths)})",
                "detail": "Admin panels, debug endpoints, backups",
                "evidence": [f"{p['url']} [{p['status']}]" for p in high_paths[:10]],
            })

        if medium_paths:
            findings.append({
                "severity": "medium",
                "title": f"Medium-Interest Paths Found ({len(medium_paths)})",
                "detail": "API docs, swagger, development endpoints",
                "evidence": [f"{p['url']} [{p['status']}]" for p in medium_paths[:10]],
            })

        if results["found"]:
            findings.append({
                "severity": "info",
                "title": f"Directory Bruteforce: {len(results['found'])} Paths Found",
                "detail": f"Scanned {results['total_requests']} paths. {len(results['interesting'])} interesting.",
            })

        return {
            "module": self.name,
            "target": domain,
            "findings": findings,
            "data": results,
        }

    def _extract_title(self, html: str) -> str:
        """Extract title from HTML."""
        import re
        match = re.search(r"<title[^>]*>([^<]+)</title>", html, re.I)
        return match.group(1).strip()[:100] if match else ""

    def _classify_severity(self, path: str, status: int) -> str:
        """Classify path severity."""
        path_lower = path.lower()
        
        critical_patterns = [
            ".env", ".git/HEAD", ".htpasswd", "wp-config", "config.php",
            "database.sql", "dump.sql", ".aws", "actuator/env",
            ".git/config", "private_key", "id_rsa",
        ]
        high_patterns = [
            "admin", "phpmyadmin", "debug", "swagger", "graphql",
            "backup", ".bak", "jenkins", "console", "elmah",
            "trace.axd", "server-status", "phpinfo",
            "actuator", "metrics", "grafana", "kibana",
            ".svn", ".hg", "docker-compose",
        ]
        medium_patterns = [
            "api-docs", "openapi", "docs", "test", "staging",
            "dev", "internal", "status", "health",
        ]
        
        for p in critical_patterns:
            if p in path_lower and status in (200, 301, 302):
                return "critical"
        for p in high_patterns:
            if p in path_lower and status in (200, 301, 302, 401, 403):
                return "high"
        for p in medium_patterns:
            if p in path_lower and status in (200, 301, 302):
                return "medium"
        
        return "info"
