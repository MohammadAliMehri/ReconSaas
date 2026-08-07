"""
Certificate Transparency Module — Passive
Discovers subdomains from CT logs via crt.sh.
"""
import json
from .base import BaseModule
from ..utils.networking import HttpClient


class CertTransparency(BaseModule):
    name = "cert_transparency"
    description = "Certificate Transparency Log Search"
    mode = "passive"

    async def run(self, target: str) -> dict:
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        results = {"certificates": [], "subdomains": set(), "issuer_orgs": set()}
        findings = []

        async with HttpClient(timeout=60, rate_limit=1.0) as client:
            # crt.sh query
            try:
                url = f"https://crt.sh/?q=%25.{domain}&output=json"
                resp = await client.get(url)
                if resp.status_code == 200:
                    try:
                        certs = resp.json()
                    except json.JSONDecodeError:
                        certs = []
                    
                    for cert in certs:
                        name = cert.get("name_value", "")
                        issuer = cert.get("issuer_name", "")
                        not_before = cert.get("not_before", "")
                        not_after = cert.get("not_after", "")
                        
                        # Extract subdomains from cert names
                        for sub in name.split("\n"):
                            sub = sub.strip().lower()
                            if sub and "*" not in sub:
                                if sub.endswith(f".{domain}") or sub == domain:
                                    results["subdomains"].add(sub)
                        
                        # Track issuers
                        if issuer:
                            # Extract org from issuer
                            for part in issuer.split(","):
                                if "O=" in part:
                                    org = part.split("O=")[1].strip()
                                    results["issuer_orgs"].add(org)
                        
                        results["certificates"].append({
                            "name": name[:200],
                            "issuer": issuer[:200],
                            "not_before": not_before,
                            "not_after": not_after,
                        })

                    if results["subdomains"]:
                        findings.append({
                            "severity": "info",
                            "title": f"CT Logs: {len(results['subdomains'])} Subdomains Found",
                            "detail": f"From {len(certs)} certificates. Issuers: {', '.join(list(results['issuer_orgs'])[:5])}",
                        })
                        
                        # Check for interesting subdomains
                        interesting_prefixes = [
                            "admin", "internal", "dev", "staging", "stage", "test", "qa",
                            "vpn", "mail", "webmail", "portal", "api", "auth", "sso",
                            "jenkins", "gitlab", "grafana", "kibana", "elastic", "jira",
                            "confluence", "bitbucket", "harbor", "docker", "k8s", "kube",
                            "grafana", "prometheus", "consul", "vault", "argocd",
                        ]
                        interesting = [s for s in results["subdomains"] 
                                     if any(s.startswith(f"{p}.") or f".{p}." in s 
                                           for p in interesting_prefixes)]
                        if interesting:
                            findings.append({
                                "severity": "medium",
                                "title": f"Interesting Subdomains in CT Logs ({len(interesting)})",
                                "detail": ", ".join(sorted(interesting)[:20]),
                            })
                else:
                    self.logger.warning(f"crt.sh returned {resp.status_code}")
            except Exception as e:
                self.logger.error(f"crt.sh query failed: {e}")

            # Also try AlienVault OTX
            try:
                otx_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
                resp = await client.get(otx_url)
                if resp.status_code == 200:
                    data = resp.json()
                    for record in data.get("passive_dns", []):
                        hostname = record.get("hostname", "")
                        if hostname and hostname.endswith(f".{domain}"):
                            results["subdomains"].add(hostname)
                    if data.get("passive_dns"):
                        findings.append({
                            "severity": "info",
                            "title": f"OTX: {len(data.get('passive_dns', []))} Passive DNS Records",
                            "detail": f"Additional subdomains from AlienVault OTX",
                        })
            except Exception as e:
                self.logger.debug(f"OTX query failed: {e}")

            # Try Shodan CTL (free, no API key)
            try:
                shodan_ctl_url = f"https://ctl.shodan.io/api/v1/domain/{domain}/hostnames"
                resp = await client.get(shodan_ctl_url)
                if resp.status_code == 200:
                    try:
                        hostnames = resp.json()
                        if isinstance(hostnames, list):
                            for h in hostnames:
                                h = h.strip().lower()
                                if h and h.endswith(f".{domain}"):
                                    results["subdomains"].add(h)
                            findings.append({
                                "severity": "info",
                                "title": f"Shodan CTL: {len(hostnames)} Hostnames",
                                "detail": "Subdomains from Shodan Certificate Transparency",
                            })
                    except Exception:
                        pass
            except Exception as e:
                self.logger.debug(f"Shodan CTL query failed: {e}")

            # Try RapidDNS
            try:
                rapiddns_url = f"https://rapiddns.io/subdomain/{domain}?full=1"
                resp = await client.get(rapiddns_url)
                if resp.status_code == 200:
                    text = resp.text
                    import re
                    # Extract subdomains from HTML table
                    pattern = re.compile(r'<td>([a-zA-Z0-9.-]+\.' + re.escape(domain) + r')</td>')
                    found = pattern.findall(text)
                    for sub in found:
                        results["subdomains"].add(sub.lower())
                    if found:
                        findings.append({
                            "severity": "info",
                            "title": f"RapidDNS: {len(found)} Subdomains",
                            "detail": "Additional subdomains from RapidDNS",
                        })
            except Exception as e:
                self.logger.debug(f"RapidDNS query failed: {e}")

        # Convert sets for JSON serialization
        results["subdomains"] = sorted(results["subdomains"])
        results["issuer_orgs"] = sorted(results["issuer_orgs"])
        results["total_subdomains"] = len(results["subdomains"])

        return {
            "module": self.name,
            "target": domain,
            "findings": findings,
            "data": results,
        }
