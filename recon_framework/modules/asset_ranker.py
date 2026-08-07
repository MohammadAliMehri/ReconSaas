"""
Asset Ranker — Analysis Module
Scores each discovered asset 0-5 on exploitability.
Based on bug bounty methodology: money paths first.
"""
from .base import BaseModule


class AssetRanker(BaseModule):
    name = "asset_ranker"
    description = "Asset Exploitability Scoring"
    mode = "both"

    # Scoring criteria weights
    CRITERIA = {
        "auth_surface": {
            "weight": 1.0,
            "keywords": ["login", "signin", "auth", "oauth", "sso", "token", "session", "jwt", "api-key"],
            "description": "Auth surface (login, SSO, OAuth, API keys)",
        },
        "multi_tenant": {
            "weight": 1.0,
            "keywords": ["org", "tenant", "account", "team", "workspace", "org_id", "account_id"],
            "description": "Multi-tenant / object IDs visible",
        },
        "money_pii": {
            "weight": 1.0,
            "keywords": ["payment", "billing", "invoice", "checkout", "order", "export", "kyc",
                        "profile", "settings", "user", "email", "phone", "address", "ssn"],
            "description": "Money or PII endpoints",
        },
        "stale_vibes": {
            "weight": 1.0,
            "keywords": ["old", "legacy", "v1", "beta", "test", "dev", "staging", "debug",
                        "backup", ".bak", "php", "asp", "cgi"],
            "description": "Stale/old tech indicators",
        },
        "low_traffic": {
            "weight": 1.0,
            "keywords": ["admin", "internal", "api", "graphql", "swagger", "actuator",
                        "jenkins", "grafana", "kibana", "prometheus"],
            "description": "Low hunter traffic (internal/dev tools)",
        },
    }

    # Bonus keywords
    BONUS_KEYWORDS = {
        "ai_widget": ["chat", "ai", "bot", "assistant", "copilot", "agent"],
        "new_feature": ["v2", "v3", "beta", "new", "preview"],
        "api_exposed": ["api", "swagger", "openapi", "graphql", "rest"],
    }

    async def run(self, all_results: dict) -> dict:
        """
        Rank all discovered assets from all modules.
        
        Args:
            all_results: Combined results from all modules
        """
        target = all_results.get("target", "unknown")
        assets = []
        findings = []

        # Collect all discovered URLs/paths/endpoints
        all_paths = set()

        # From dir bruteforce
        dir_results = all_results.get("dir_bruteforce", {}).get("data", {}).get("found", [])
        for item in dir_results:
            all_paths.add(item.get("path", ""))

        # From endpoint probe
        ep_results = all_results.get("endpoint_probe", {}).get("data", {}).get("discovered", [])
        for item in ep_results:
            all_paths.add(item.get("path", ""))

        # From wayback
        wb_results = all_results.get("wayback_urls", {}).get("data", {}).get("unique_paths", [])
        for path in wb_results[:200]:
            all_paths.add(path)

        # From JS analysis
        js_results = all_results.get("js_analyzer", {}).get("data", {}).get("endpoints", [])
        for endpoint in js_results:
            all_paths.add(endpoint)

        # From robots.txt
        robots = all_results.get("endpoint_probe", {}).get("data", {}).get("robots_txt", "")
        if robots:
            for line in robots.split("\n"):
                if line.strip().lower().startswith(("disallow:", "allow:")):
                    path = line.split(":", 1)[1].strip()
                    if path and path != "/":
                        all_paths.add(path)

        # From subdomains
        subdomains = all_results.get("cert_transparency", {}).get("data", {}).get("subdomains", [])
        for sub in subdomains:
            all_paths.add(f"[subdomain] {sub}")

        # Score each asset
        for path in sorted(all_paths):
            if not path:
                continue
            score = self._score_asset(path)
            if score > 0:
                assets.append({
                    "path": path,
                    "score": score["total"],
                    "breakdown": score["breakdown"],
                    "bonus": score["bonus"],
                })

        # Sort by score descending
        assets.sort(key=lambda x: x["score"], reverse=True)

        # Top assets
        top_assets = assets[:20]
        if top_assets:
            findings.append({
                "severity": "info",
                "title": f"Asset Ranking: {len(assets)} assets scored",
                "detail": f"Top {len(top_assets)} targets ranked by exploitability",
                "evidence": top_assets[:10],
            })

        # High-value targets
        high_value = [a for a in assets if a["score"] >= 3.0]
        if high_value:
            findings.append({
                "severity": "medium",
                "title": f"{len(high_value)} High-Value Targets (score ≥ 3.0)",
                "detail": "These should be tested first: " + ", ".join(a["path"][:50] for a in high_value[:5]),
            })

        return {
            "module": self.name,
            "target": target,
            "findings": findings,
            "data": {
                "total_assets": len(assets),
                "ranked_assets": assets[:50],
                "top_targets": top_assets,
                "high_value_count": len(high_value) if top_assets else 0,
            },
        }

    def _score_asset(self, path: str) -> dict:
        """Score a single asset."""
        path_lower = path.lower()
        breakdown = {}
        bonus = 0

        # Score each criterion
        for criterion, config in self.CRITERIA.items():
            hits = sum(1 for kw in config["keywords"] if kw in path_lower)
            if hits > 0:
                breakdown[criterion] = min(hits * config["weight"], config["weight"])
            else:
                breakdown[criterion] = 0.0

        total = sum(breakdown.values())

        # Bonus points
        for bonus_name, keywords in self.BONUS_KEYWORDS.items():
            if any(kw in path_lower for kw in keywords):
                bonus += 0.5

        total += bonus

        # Cap at 5.0
        total = min(total, 5.0)

        return {
            "total": round(total, 1),
            "breakdown": {k: round(v, 1) for k, v in breakdown.items()},
            "bonus": round(bonus, 1),
        }
