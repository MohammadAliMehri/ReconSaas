"""
Fingerprint Engine — Pattern matching against the signature database.
Applies header, cookie, meta, script, HTML, URL, and JS patterns.
Extracts versions and computes confidence scores.
"""
import re
from typing import Optional
from dataclasses import dataclass, field

from .fingerprints import FINGERPRINTS, CATEGORIES


@dataclass
class MatchResult:
    """A single technology match."""
    name: str
    version: str = ""
    confidence: int = 100
    categories: list = field(default_factory=list)
    category_names: list = field(default_factory=list)
    implies: list = field(default_factory=list)
    matched_by: str = ""           # which pattern type triggered it
    matched_pattern: str = ""      # the specific pattern that matched


class FingerprintEngine:
    """Run fingerprint patterns against HTTP response data."""

    def __init__(self):
        self.fingerprints = FINGERPRINTS
        self.categories = CATEGORIES

    def analyze(
        self,
        headers: dict = None,
        cookies: dict = None,
        body: str = "",
        url: str = "",
        script_sources: list = None,
    ) -> list[MatchResult]:
        """
        Analyze response data and return matched technologies.

        Args:
            headers: HTTP response headers (dict)
            cookies: Cookie names (dict or list of names)
            body: Response body HTML
            url: Request URL (for URL pattern matching)
            script_sources: List of <script src="..."> URLs

        Returns:
            List of MatchResult sorted by confidence descending
        """
        headers = headers or {}
        script_sources = script_sources or []
        cookie_names = list(cookies.keys()) if isinstance(cookies, dict) else (cookies or [])

        # Normalize header values for matching
        header_str = ""
        for k, v in headers.items():
            header_str += f"{k}: {v}\n"

        matches: dict[str, MatchResult] = {}

        for tech_name, fp in self.fingerprints.items():
            result = self._check_technology(
                tech_name, fp, headers, header_str, cookie_names,
                body, url, script_sources,
            )
            if result:
                # Keep highest confidence match per tech
                if tech_name not in matches or result.confidence > matches[tech_name].confidence:
                    matches[tech_name] = result

        # Resolve implies — if A implies B and B isn't detected, add B at lower confidence
        implied = set()
        for m in matches.values():
            for dep in m.implies:
                if dep not in matches and dep not in implied:
                    implied.add(dep)

        for dep_name in implied:
            dep_fp = self.fingerprints.get(dep_name)
            if dep_fp:
                cat_ids = dep_fp.get("categories", [])
                cat_names = [self.categories.get(c, str(c)) for c in cat_ids]
                matches[dep_name] = MatchResult(
                    name=dep_name,
                    confidence=30,  # low — inferred only
                    categories=cat_ids,
                    category_names=cat_names,
                    matched_by="implied",
                )

        # Sort by confidence
        results = sorted(matches.values(), key=lambda m: -m.confidence)
        return results

    def _check_technology(
        self, name: str, fp: dict,
        headers: dict, header_str: str,
        cookie_names: list, body: str,
        url: str, script_sources: list,
    ) -> Optional[MatchResult]:
        """Check one technology against all available data."""
        cat_ids = fp.get("categories", [])
        cat_names = [self.categories.get(c, str(c)) for c in cat_ids]
        version = ""
        best_confidence = 0
        best_match_type = ""
        best_pattern = ""
        matched = False

        # 1. Header patterns (highest confidence)
        for hdr_name, hdr_pattern in fp.get("headers", {}).items():
            actual = headers.get(hdr_name, "")
            if not actual:
                # Case-insensitive fallback
                for k, v in headers.items():
                    if k.lower() == hdr_name.lower():
                        actual = v
                        break
            if actual and re.search(hdr_pattern, str(actual), re.IGNORECASE):
                matched = True
                conf = 100
                if conf > best_confidence:
                    best_confidence = conf
                    best_match_type = "headers"
                    best_pattern = f"{hdr_name}: {hdr_pattern}"
                # Try version extraction
                if not version:
                    version = self._extract_version(hdr_pattern, str(actual))

        # 2. Cookie patterns
        for cookie_pat in fp.get("cookies", []):
            for cname in cookie_names:
                if re.search(cookie_pat, cname, re.IGNORECASE):
                    matched = True
                    conf = 90
                    if conf > best_confidence:
                        best_confidence = conf
                        best_match_type = "cookies"
                        best_pattern = cookie_pat
                    break

        # 3. Meta generator
        for meta_name, meta_pattern in fp.get("meta", {}).items():
            # Look for <meta name="generator" content="...">
            m = re.search(
                rf'<meta[^>]+name=["\']{re.escape(meta_name)}["\'][^>]+content=["\']([^"\']+)',
                body, re.IGNORECASE,
            )
            if not m:
                m = re.search(
                    rf'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']{re.escape(meta_name)}["\']',
                    body, re.IGNORECASE,
                )
            if m:
                content = m.group(1)
                if re.search(meta_pattern, content, re.IGNORECASE):
                    matched = True
                    conf = 95
                    if conf > best_confidence:
                        best_confidence = conf
                        best_match_type = "meta"
                        best_pattern = f"{meta_name}: {meta_pattern}"
                    if not version:
                        version = self._extract_version(meta_pattern, content)

        # 4. Script src patterns
        for script_pat in fp.get("scripts", []):
            for src in script_sources:
                if re.search(script_pat, src, re.IGNORECASE):
                    matched = True
                    conf = 80
                    if conf > best_confidence:
                        best_confidence = conf
                        best_match_type = "scripts"
                        best_pattern = script_pat
                    if not version:
                        version = self._extract_version(script_pat, src)
                    break
            if matched and best_match_type == "scripts":
                break

        # 5. HTML body patterns
        for html_pat in fp.get("html", []):
            if re.search(html_pat, body, re.IGNORECASE):
                matched = True
                conf = 70
                if conf > best_confidence:
                    best_confidence = conf
                    best_match_type = "html"
                    best_pattern = html_pat
                if not version:
                    version = self._extract_version(html_pat, body)
                break  # one match is enough

        # 6. URL patterns
        for url_pat in fp.get("url", []):
            if re.search(re.escape(url_pat), url, re.IGNORECASE):
                matched = True
                conf = 75
                if conf > best_confidence:
                    best_confidence = conf
                    best_match_type = "url"
                    best_pattern = url_pat
                break

        # 7. JS global variable patterns (in body)
        for js_var in fp.get("js", []):
            if re.search(re.escape(js_var), body):
                matched = True
                conf = 60
                if conf > best_confidence:
                    best_confidence = conf
                    best_match_type = "js"
                    best_pattern = js_var
                break

        if not matched:
            return None

        # Apply version from dedicated regex if we haven't found one yet
        if not version and "version" in fp:
            # Try against headers first, then body
            version = self._extract_version(fp["version"], header_str) or \
                      self._extract_version(fp["version"], body[:5000])

        return MatchResult(
            name=name,
            version=version,
            confidence=best_confidence,
            categories=cat_ids,
            category_names=cat_names,
            implies=fp.get("implies", []),
            matched_by=best_match_type,
            matched_pattern=best_pattern,
        )

    def _extract_version(self, pattern: str, text: str) -> str:
        """Try to extract a version from a regex pattern with one capture group."""
        try:
            m = re.search(pattern, text, re.IGNORECASE)
            if m and m.lastindex and m.lastindex >= 1:
                ver = m.group(1)
                if ver and re.match(r"^[\d.]+$", ver):
                    return ver
        except re.error:
            pass
        return ""

    def get_category_summary(self, results: list[MatchResult]) -> dict:
        """Group matches by category."""
        summary: dict[str, list[str]] = {}
        for r in results:
            for cat in r.category_names:
                entry = r.name + (f" {r.version}" if r.version else "")
                summary.setdefault(cat, []).append(entry)
        return summary
