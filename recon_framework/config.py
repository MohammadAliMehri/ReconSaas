"""
Configuration management for Recon Framework.
"""
import os
import yaml
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ScanConfig:
    """Scan configuration."""
    target: str
    mode: str = "hybrid"  # passive | active | hybrid
    output_dir: str = ""
    threads: int = 10
    timeout: int = 30
    rate_limit: float = 0.5  # seconds between requests
    user_agent: str = "ReconFramework/1.0 (Security Research)"
    verbose: bool = False
    modules: list = field(default_factory=list)
    # API keys (optional, free tiers)
    shodan_api_key: str = ""
    censys_api_id: str = ""
    censys_api_secret: str = ""
    # Port scan config
    port_scan_top: int = 1000
    port_scan_timeout: float = 1.0
    # Dir brute config
    dir_brute_depth: int = 2
    dir_brute_extensions: list = field(default_factory=lambda: [
        "", ".html", ".php", ".asp", ".aspx", ".jsp", ".js", ".txt",
        ".bak", ".old", ".zip", ".tar.gz", ".sql", ".conf", ".xml", ".json"
    ])
    # Param discovery
    param_wordlist_size: int = 500

    def __post_init__(self):
        if not self.output_dir:
            safe_target = self.target.replace("://", "_").replace("/", "_").replace(":", "_")
            self.output_dir = os.path.join("recon-output", safe_target)

    @classmethod
    def from_file(cls, path: str) -> "ScanConfig":
        """Load config from YAML file."""
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls(**data)

    @classmethod
    def from_target(cls, target: str, mode: str = "hybrid", **kwargs) -> "ScanConfig":
        """Quick config from target string."""
        # Normalize target
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"
        return cls(target=target, mode=mode, **kwargs)


# Free API endpoints (no key required)
FREE_ENDPOINTS = {
    "crt_sh": "https://crt.sh/?q=%25.{domain}&output=json",
    "wayback": "https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original,statuscode,mimetype&collapse=urlkey",
    "otx": "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
    "urlscan": "https://urlscan.io/api/v1/search/?q=domain:{domain}",
    "threatcrowd": "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}",
    "rapiddns": "https://rapiddns.io/subdomain/{domain}?full=1",
    "dnsrepo": "https://dnsrepo.noc.org/?search={domain}",
    "hackertarget": "https://api.hackertarget.com/hostsearch/?q={domain}",
    "virustotal_subdomains": "https://www.virustotal.com/vtapi/v2/domain/report?apikey={apikey}&domain={domain}",
}

# Default user agents rotation
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
]

# Technology fingerprints
TECH_FINGERPRINTS = {
    "headers": {
        "X-Powered-By": {
            "PHP": "php",
            "Express": "node.js/express",
            "ASP.NET": "asp.net",
            "Next.js": "next.js",
        },
        "Server": {
            "Apache": "apache",
            "nginx": "nginx",
            "Microsoft-IIS": "iis",
            "LiteSpeed": "litespeed",
            "Cloudflare": "cloudflare",
            "AmazonS3": "aws-s3",
            "Tengine": "tengine",
        },
        "X-AspNet-Version": {"*": "asp.net"},
        "X-Generator": {"*": "cms-generator"},
    },
    "cookies": {
        "PHPSESSID": "php",
        "JSESSIONID": "java",
        "ASP.NET_SessionId": "asp.net",
        "connect.sid": "express",
        "_rails_session": "ruby-on-rails",
        "csrftoken": "django",
        "_gitlab_session": "gitlab",
        "XSRF-TOKEN": "angular/laravel",
    },
    "meta": {
        "generator": {
            "WordPress": "wordpress",
            "Joomla": "joomla",
            "Drupal": "drupal",
            "Shopify": "shopify",
            "Squarespace": "squarespace",
            "Wix": "wix",
            "Ghost": "ghost",
            "Hugo": "hugo",
            "Gatsby": "gatsby",
            "Next.js": "nextjs",
        }
    },
    "body_patterns": {
        "wp-content": "wordpress",
        "wp-includes": "wordpress",
        "/sites/default/files": "drupal",
        "media/jui": "joomla",
        "Joomla": "joomla",
        "Shopify.theme": "shopify",
        "__NEXT_DATA__": "nextjs",
        "_app_/components": "nuxtjs",
        "react-root": "react",
        "ng-version": "angular",
        "vue-router": "vue.js",
        "data-reactroot": "react",
    }
}

# Security headers to check
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "present": "HSTS enabled",
        "missing": "No HSTS — allows downgrade attacks",
        "severity": "medium",
    },
    "Content-Security-Policy": {
        "present": "CSP enabled",
        "missing": "No CSP — XSS risk",
        "severity": "medium",
    },
    "X-Frame-Options": {
        "present": "Clickjacking protection",
        "missing": "No X-Frame-Options — clickjacking risk",
        "severity": "low",
    },
    "X-Content-Type-Options": {
        "present": "MIME sniffing protection",
        "missing": "No X-Content-Type-Options",
        "severity": "low",
    },
    "X-XSS-Protection": {
        "present": "XSS filter enabled",
        "missing": "No X-XSS-Protection (deprecated but still checked)",
        "severity": "info",
    },
    "Referrer-Policy": {
        "present": "Referrer policy set",
        "missing": "No Referrer-Policy",
        "severity": "info",
    },
    "Permissions-Policy": {
        "present": "Permissions policy set",
        "missing": "No Permissions-Policy",
        "severity": "info",
    },
}
