"""
Shared HTTP client and networking utilities.
"""
import asyncio
import random
import time
from typing import Optional
from urllib.parse import urlparse, urljoin

import httpx

from ..config import USER_AGENTS


class HttpClient:
    """Async HTTP client with rate limiting and retries."""

    def __init__(self, timeout: int = 30, rate_limit: float = 0.5, follow_redirects: bool = True):
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.follow_redirects = follow_redirects
        self._last_request_time = 0
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self):
        self._client = httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=self.follow_redirects,
            verify=False,
            limits=httpx.Limits(max_connections=50, max_keepalive_connections=20),
        )
        return self

    async def __aexit__(self, *args):
        if self._client:
            await self._client.aclose()

    def _get_headers(self, extra_headers: dict = None) -> dict:
        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }
        if extra_headers:
            headers.update(extra_headers)
        return headers

    async def _rate_limit_wait(self):
        """Enforce rate limiting between requests."""
        now = time.time()
        elapsed = now - self._last_request_time
        if elapsed < self.rate_limit:
            await asyncio.sleep(self.rate_limit - elapsed)
        self._last_request_time = time.time()

    async def get(self, url: str, headers: dict = None, params: dict = None, allow_redirects: bool = None) -> httpx.Response:
        """GET request with rate limiting."""
        await self._rate_limit_wait()
        resp = await self._client.get(
            url,
            headers=self._get_headers(headers),
            params=params,
            follow_redirects=allow_redirects if allow_redirects is not None else self.follow_redirects,
        )
        return resp

    async def head(self, url: str, headers: dict = None) -> httpx.Response:
        """HEAD request with rate limiting."""
        await self._rate_limit_wait()
        return await self._client.head(url, headers=self._get_headers(headers))

    async def post(self, url: str, headers: dict = None, data: dict = None, json_data: dict = None) -> httpx.Response:
        """POST request with rate limiting."""
        await self._rate_limit_wait()
        return await self._client.post(
            url,
            headers=self._get_headers(headers),
            data=data,
            json=json_data,
        )

    async def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        """Generic request with rate limiting."""
        await self._rate_limit_wait()
        kwargs.setdefault("headers", self._get_headers(kwargs.get("headers")))
        return await self._client.request(method, url, **kwargs)


def extract_domain(url: str) -> str:
    """Extract domain from URL."""
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    parsed = urlparse(url)
    return parsed.netloc or parsed.path.split("/")[0]


def extract_root_domain(domain: str) -> str:
    """Extract root domain (e.g., sub.example.com -> example.com)."""
    import tldextract
    ext = tldextract.extract(domain)
    return f"{ext.domain}.{ext.suffix}"


def normalize_url(url: str) -> str:
    """Normalize URL."""
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    return url.rstrip("/")


def is_valid_domain(domain: str) -> bool:
    """Validate domain format."""
    import re
    pattern = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )
    return bool(pattern.match(domain))


def is_private_ip(ip: str) -> bool:
    """Check if IP is private/internal."""
    import ipaddress
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


async def resolve_dns(domain: str, record_type: str = "A") -> list:
    """Resolve DNS records."""
    import dns.resolver
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [str(r) for r in answers]
    except Exception:
        return []
