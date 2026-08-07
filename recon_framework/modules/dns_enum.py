"""
DNS Enumeration Module — Passive
Discovers DNS records: A, AAAA, MX, NS, TXT, SOA, CNAME.
"""
import dns.resolver
import dns.zone
import dns.query
from .base import BaseModule


class DNSEnum(BaseModule):
    name = "dns_enum"
    description = "DNS Record Enumeration"
    mode = "passive"

    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV", "CAA"]

    async def run(self, target: str) -> dict:
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        results = {"records": {}, "zone_transfer": None, "nameservers": []}
        findings = []

        # Query each record type
        for rtype in self.RECORD_TYPES:
            try:
                answers = dns.resolver.resolve(domain, rtype, lifetime=10)
                records = []
                for r in answers:
                    record = str(r).strip('"')
                    records.append(record)
                if records:
                    results["records"][rtype] = records
                    self.logger.debug(f"  {rtype}: {len(records)} records")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            except dns.resolver.NoNameservers:
                self.logger.debug(f"  {rtype}: no nameservers responded")
            except Exception as e:
                self.logger.debug(f"  {rtype}: {e}")

        # Extract nameservers for zone transfer attempt
        if "NS" in results["records"]:
            results["nameservers"] = results["records"]["NS"]
            for ns in results["nameservers"]:
                ns_clean = ns.rstrip(".")
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_clean, domain, timeout=10))
                    if zone:
                        records_list = []
                        for name, node in zone.nodes.items():
                            for rdataset in node.rdatasets:
                                for rdata in rdataset:
                                    records_list.append(f"{name} {rdataset.rdtype} {rdata}")
                        results["zone_transfer"] = {
                            "nameserver": ns_clean,
                            "records": records_list[:100],
                            "total": len(records_list),
                        }
                        findings.append({
                            "severity": "critical",
                            "title": f"DNS Zone Transfer Allowed on {ns_clean}",
                            "detail": f"Zone transfer exposed {len(records_list)} records. Full DNS zone readable.",
                            "evidence": records_list[:20],
                        })
                except Exception:
                    pass

        # Check for wildcard DNS
        import random
        import string
        random_sub = ''.join(random.choices(string.ascii_lowercase, k=16))
        try:
            answers = dns.resolver.resolve(f"{random_sub}.{domain}", "A", lifetime=5)
            wildcard_ips = [str(r) for r in answers]
            results["wildcard_dns"] = wildcard_ips
            findings.append({
                "severity": "info",
                "title": "Wildcard DNS Detected",
                "detail": f"Random subdomain resolves to: {', '.join(wildcard_ips)}. Subdomain enumeration may produce false positives.",
            })
        except Exception:
            results["wildcard_dns"] = None

        # Analyze findings
        if "MX" in results["records"]:
            findings.append({
                "severity": "info",
                "title": f"MX Records Found ({len(results['records']['MX'])})",
                "detail": f"Mail servers: {', '.join(results['records']['MX'][:5])}",
            })

        if "TXT" in results["records"]:
            for txt in results["records"]["TXT"]:
                if "spf" in txt.lower():
                    findings.append({
                        "severity": "info",
                        "title": "SPF Record Found",
                        "detail": txt[:200],
                    })
                if "dmarc" in txt.lower():
                    findings.append({
                        "severity": "info",
                        "title": "DMARC Record Found",
                        "detail": txt[:200],
                    })

        # Check for interesting CNAME targets
        if "CNAME" in results["records"]:
            for cname in results["records"]["CNAME"]:
                for service in ["amazonaws", "herokuapp", "github.io", "azurewebsites", 
                               "cloudfront", "fastly", "pantheon", "shopify", "squarespace",
                               "zendesk", "freshdesk", "surge.sh", "netlify", "vercel"]:
                    if service in cname.lower():
                        findings.append({
                            "severity": "info",
                            "title": f"CNAME Points to {service}",
                            "detail": f"CNAME: {cname}",
                        })
                        break

        return {
            "module": self.name,
            "target": domain,
            "findings": findings,
            "data": results,
        }
