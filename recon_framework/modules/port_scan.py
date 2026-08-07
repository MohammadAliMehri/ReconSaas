"""
Port Scanner Module — Active
Discovers open ports and service banners.
"""
import asyncio
import socket
from .base import BaseModule


class PortScanner(BaseModule):
    name = "port_scan"
    description = "Port & Service Scanner"
    mode = "active"

    # Top ports by frequency
    TOP_PORTS = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
        80: "http", 110: "pop3", 111: "rpc", 135: "msrpc", 139: "netbios",
        143: "imap", 443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
        1433: "mssql", 1521: "oracle", 2049: "nfs", 3306: "mysql",
        3389: "rdp", 5432: "postgres", 5900: "vnc", 6379: "redis",
        8080: "http-alt", 8443: "https-alt", 8888: "http-alt2",
        9090: "web-console", 9200: "elasticsearch", 11211: "memcached",
        27017: "mongodb", 50000: "sap", 50070: "hadoop",
        # Common dev/admin ports
        4200: "angular-dev", 3000: "node-dev", 5000: "flask-dev",
        8000: "django-dev", 8001: "http-dev", 4443: "https-dev",
        15672: "rabbitmq-mgmt", 2379: "etcd", 2375: "docker",
        10250: "kubelet", 6443: "kubernetes-api",
    }

    SERVICE_BANNERS = {}

    async def run(self, target: str) -> dict:
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        results = {
            "open_ports": [],
            "closed_ports": [],
            "filtered_ports": [],
            "banners": {},
            "ip_addresses": [],
        }
        findings = []

        # Resolve IP
        try:
            import dns.resolver
            answers = dns.resolver.resolve(domain, "A")
            results["ip_addresses"] = [str(r) for r in answers]
        except Exception:
            try:
                ip = socket.gethostbyname(domain)
                results["ip_addresses"] = [ip]
            except Exception:
                findings.append({
                    "severity": "info",
                    "title": "Could not resolve target IP",
                    "detail": f"DNS resolution failed for {domain}",
                })
                return {"module": self.name, "target": domain, "findings": findings, "data": results}

        target_ip = results["ip_addresses"][0]
        
        # Get ports to scan
        top_n = self.config.port_scan_top
        ports = sorted(self.TOP_PORTS.keys())[:top_n]

        # Scan ports concurrently
        semaphore = asyncio.Semaphore(50)  # Limit concurrent connections

        async def check_port(port: int):
            async with semaphore:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(target_ip, port),
                        timeout=self.config.port_scan_timeout,
                    )
                    writer.close()
                    await writer.wait_closed()
                    return port, True
                except (ConnectionRefusedError, ConnectionResetError):
                    return port, False
                except (asyncio.TimeoutError, OSError, socket.error):
                    return port, None  # Filtered

        tasks = [check_port(port) for port in ports]
        results_list = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results_list:
            if isinstance(result, Exception):
                continue
            port, status = result
            if status is True:
                service = self.TOP_PORTS.get(port, "unknown")
                results["open_ports"].append({"port": port, "service": service})
                
                # Try to grab banner
                try:
                    banner = await self._grab_banner(target_ip, port)
                    if banner:
                        results["banners"][port] = banner[:500]
                except Exception:
                    pass
            elif status is None:
                results["filtered_ports"].append(port)
            else:
                results["closed_ports"].append(port)

        # Generate findings
        open_count = len(results["open_ports"])
        if open_count > 0:
            port_list = ", ".join([f"{p['port']}/{p['service']}" for p in results["open_ports"][:20]])
            findings.append({
                "severity": "info",
                "title": f"{open_count} Open Ports Found",
                "detail": f"Ports: {port_list}",
            })

            # Check for high-risk services
            high_risk = {
                21: ("FTP open — cleartext protocol", "medium"),
                23: ("Telnet open — cleartext protocol", "high"),
                445: ("SMB open — check for EternalBlue, null sessions", "high"),
                1433: ("MSSQL exposed — check for weak auth", "high"),
                3306: ("MySQL exposed — check for weak auth", "high"),
                3389: ("RDP exposed — brute force risk", "high"),
                5432: ("PostgreSQL exposed — check for weak auth", "high"),
                5900: ("VNC exposed — check for weak auth", "high"),
                6379: ("Redis exposed — often no auth required", "critical"),
                9200: ("Elasticsearch exposed — check for auth", "high"),
                11211: ("Memcached exposed — DDoS amplification risk", "high"),
                27017: ("MongoDB exposed — check for auth", "critical"),
                2375: ("Docker API exposed — container takeover", "critical"),
                2379: ("etcd exposed — cluster secrets leak", "critical"),
                10250: ("Kubelet API exposed — container access", "critical"),
                6443: ("Kubernetes API exposed", "high"),
            }
            for port_info in results["open_ports"]:
                port = port_info["port"]
                if port in high_risk:
                    msg, sev = high_risk[port]
                    findings.append({
                        "severity": sev,
                        "title": msg,
                        "detail": f"Port {port} is open on {target_ip}",
                    })

            # Check for banners with version info
            for port, banner in results["banners"].items():
                if any(v in banner.lower() for v in ["version", "server:", "ssh-", "ftp", "220"]):
                    findings.append({
                        "severity": "low",
                        "title": f"Service Banner Exposed (port {port})",
                        "detail": banner[:200],
                    })

        if results["filtered_ports"]:
            findings.append({
                "severity": "info",
                "title": f"{len(results['filtered_ports'])} Filtered Ports",
                "detail": "Ports may be behind firewall/ACL",
            })

        return {
            "module": self.name,
            "target": domain,
            "findings": findings,
            "data": results,
        }

    async def _grab_banner(self, ip: str, port: int) -> str:
        """Attempt to grab service banner."""
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=3,
            )
            # Wait briefly for banner
            await asyncio.sleep(0.5)
            writer.close()
            await writer.wait_closed()
            return ""
        except Exception:
            return ""
