from __future__ import annotations

import asyncio
import html
import re
from urllib.parse import urlparse

from app.models import AccessMode, ResultCategory
from app.services.recon.base import (
    AdapterError,
    AdapterFinding,
    ReconAdapter,
    discover_same_domain_links,
    fetch_robots_parser,
    gather_limited,
    path_allowed,
)
from app.services.ssrf_guard import UnsafeUrlError, safe_get

_LEADERSHIP_PATHS = ("/leadership", "/about/leadership", "/team", "/about")

# Real corporate sites often publish leadership bios under deep, CMS-specific URLs rather than
# the conventional paths above. Scanning the homepage's own navigation for these keywords finds
# the organization's actual leadership/about page regardless of URL shape.
_DISCOVERY_KEYWORDS = {
    "leadership": "leadership",
    "executive": "leadership",
    "management-team": "leadership",
    "our-team": "team",
    "meet-the-team": "team",
    "team": "team",
    "about-us": "about",
    "about": "about",
}
_ROLE = (
    r"(?:Chief Executive Officer|CEO|Chief Financial Officer|CFO|Chief Technology Officer|CTO|"
    r"Chief Operating Officer|COO|Chief Information Security Officer|CISO|President)"
)
_NAME = r"([A-Z][A-Za-z.'-]+(?:\s+[A-Z][A-Za-z.'-]+){1,3})"
_NAME_FIRST = re.compile(rf"{_NAME}\s*(?:,|—|–|-)\s*({_ROLE})")
_ROLE_FIRST = re.compile(rf"({_ROLE})\s*(?:,|:|—|–|-)\s*{_NAME}")
# Many modern component-based leadership pages render the title as a label directly above the
# name heading (e.g. <span class="eyebrow">Chief Executive Officer</span><h2>Sean Ryan</h2>)
# with no punctuation between them once tags are stripped -- just whitespace. This catches that
# common "title card" layout, which the punctuated patterns above miss entirely.
_ROLE_THEN_NAME_LOOSE = re.compile(rf"({_ROLE})\s+{_NAME}(?=\s|$)")
_TAG_RE = re.compile(r"<[^>]+>")
_SCRIPT_STYLE_RE = re.compile(r"<(?:script|style)[^>]*>.*?</(?:script|style)>", re.IGNORECASE | re.DOTALL)


def _clean_captured_name(name: str) -> str:
    """Trims artifacts from flattening a "title card" layout to plain text, where a name
    heading is immediately followed by a bio sentence that opens with the same name/first name
    again (e.g. "Sean Ryan Sean has served..." -> captured as "Sean Ryan Sean"). Collapses a
    fully repeated name ("Kenneth Sardoni Kenneth Sardoni") and drops a trailing word that
    duplicates an earlier word in the same match."""
    words = name.split()
    for size in range(len(words) // 2, 0, -1):
        if words[:size] == words[size : size * 2]:
            return " ".join(words[:size])
    while len(words) > 2 and words[-1] in words[:-1]:
        words = words[:-1]
    return " ".join(words)


def _published_executives(markup: str) -> list[tuple[str, str]]:
    """Best-effort extraction of executive name/title pairs from official public-page text."""
    text = _SCRIPT_STYLE_RE.sub(" ", markup)
    text = html.unescape(_TAG_RE.sub(" ", text))
    text = re.sub(r"\s+", " ", text)
    pairs: set[tuple[str, str]] = set()
    for match in _NAME_FIRST.finditer(text):
        pairs.add((_clean_captured_name(match.group(1)), match.group(2)))
    for match in _ROLE_FIRST.finditer(text):
        pairs.add((_clean_captured_name(match.group(2)), match.group(1)))
    for match in _ROLE_THEN_NAME_LOOSE.finditer(text):
        pairs.add((_clean_captured_name(match.group(2)), match.group(1)))
    return sorted(pairs, key=lambda pair: (pair[1], pair[0]))


class LeadershipAdapter(ReconAdapter):
    name = "Official Leadership Pages"
    modes = frozenset({AccessMode.AUTHORIZED_PASSIVE})
    timeout_budget_multiplier = 4

    async def run(self, *, domain: str, organization_name: str, timeout: float) -> list[AdapterFinding]:
        domain_parser = await fetch_robots_parser(domain, timeout=timeout)

        candidate_urls: list[str] = [f"https://{domain}{path}" for path in _LEADERSHIP_PATHS]

        if path_allowed(domain_parser, "/"):
            try:
                homepage = await safe_get(f"https://{domain}/", timeout=timeout)
            except Exception:
                homepage = None
            if homepage is not None and homepage.status_code == 200:
                discovered = discover_same_domain_links(
                    domain, str(homepage.url), homepage.text[:500_000], _DISCOVERY_KEYWORDS
                )
                seen_urls = set(candidate_urls)
                for url, _label in discovered:
                    if url not in seen_urls:
                        seen_urls.add(url)
                        candidate_urls.append(url)

        other_hosts = {urlparse(url).hostname for url in candidate_urls} - {domain}
        other_parsers = await asyncio.gather(
            *(fetch_robots_parser(host, timeout=timeout) for host in other_hosts)
        )
        robots_by_host = {domain: domain_parser, **dict(zip(other_hosts, other_parsers))}

        allowed_urls = [
            url
            for url in candidate_urls
            if path_allowed(robots_by_host.get(urlparse(url).hostname), urlparse(url).path or "/")
        ]

        async def fetch(url: str):
            try:
                response = await safe_get(url, timeout=timeout)
            except UnsafeUrlError:
                return url, None
            except Exception:
                return url, None
            return url, response

        fetched = await gather_limited((fetch(u) for u in allowed_urls))

        # Leadership bios are frequently linked one hop deeper than the homepage -- e.g. from
        # an "About" or "Team" page rather than the main nav. Follow leadership-looking links
        # found on pages we already fetched, bounded so this can't spiral into a real crawl.
        second_hop_urls: list[str] = []
        seen_urls = set(allowed_urls)
        for url, response in fetched:
            if response is None or response.status_code != 200:
                continue
            for hop_url, _label in discover_same_domain_links(
                domain, str(response.url), response.text[:500_000], _DISCOVERY_KEYWORDS,
                per_label_limit=2, limit=6,
            ):
                if hop_url not in seen_urls:
                    seen_urls.add(hop_url)
                    second_hop_urls.append(hop_url)

        if second_hop_urls:
            hop_hosts = {urlparse(u).hostname for u in second_hop_urls} - set(robots_by_host)
            hop_parsers = await asyncio.gather(
                *(fetch_robots_parser(h, timeout=timeout) for h in hop_hosts)
            )
            robots_by_host.update(zip(hop_hosts, hop_parsers))
            second_hop_allowed = [
                u for u in second_hop_urls
                if path_allowed(robots_by_host.get(urlparse(u).hostname), urlparse(u).path or "/")
            ]
            fetched = fetched + await gather_limited((fetch(u) for u in second_hop_allowed))

        findings: list[AdapterFinding] = []
        reachable = False
        seen: set[str] = set()
        for url, response in fetched:
            if response is None:
                continue
            reachable = True
            if response.status_code != 200:
                continue
            # Large component-framework pages carry heavy hydration script payloads before the
            # actual visible content -- 300k chars of a >500k-char page was cutting off before
            # reaching the executive cards entirely. The SSRF guard already caps responses at
            # 2MB, so slicing at that same size means real pages are never truncated in practice.
            for name, role in _published_executives(response.text[:2_000_000]):
                key = f"{name.lower()}:{role.lower()}"
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    AdapterFinding(
                        category=ResultCategory.PEOPLE,
                        title=f"{name} — {role}",
                        summary="Executive role shown on the organization's official public page.",
                        dedupe_key=f"official-executive:{domain}:{key}",
                        source_name="Official Leadership Pages",
                        source_url=url,
                        confidence=0.8,
                        rationale="Public executive name/title pair found on an official organization page.",
                    )
                )
        if not reachable:
            raise AdapterError(f"Could not reach official leadership pages for {domain}")
        return findings
