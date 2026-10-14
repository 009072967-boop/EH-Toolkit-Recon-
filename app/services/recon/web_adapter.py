from __future__ import annotations

import re

from app.models import AccessMode, ResultCategory
from app.services.recon.base import AdapterError, AdapterFinding, ReconAdapter, robots_allows
from app.services.ssrf_guard import UnsafeUrlError, safe_get

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_DESC_RE = re.compile(
    r'<meta[^>]+name=["\']description["\'][^>]+content=["\'](.*?)["\']', re.IGNORECASE | re.DOTALL
)
_HREF_RE = re.compile(r'href=["\'](https?://[^"\'\s<>]+)["\']', re.IGNORECASE)
_SAME_AS_RE = re.compile(r'"sameAs"\s*:\s*(\[[^\]]*\]|"[^"]*")', re.IGNORECASE)
_URL_IN_TEXT_RE = re.compile(r'https?://[^"\'\s,\]]+')

# Official brand accounts linked from the organization's own homepage (header/footer icons, or
# the schema.org "sameAs" list). Patterns are anchored to account-level URLs so share buttons
# ("facebook.com/sharer...", "twitter.com/intent/...") and individual posts are not mistaken for
# the organization's account. LinkedIn is limited to /company/ pages -- never personal /in/ profiles.
_SOCIAL_PATTERNS = [
    ("LinkedIn", re.compile(r"^https?://(?:[a-z]{2,3}\.)?linkedin\.com/company/([A-Za-z0-9_.%-]+)/?$", re.I)),
    ("X (Twitter)", re.compile(r"^https?://(?:www\.)?(?:twitter|x)\.com/([A-Za-z0-9_]{1,15})/?$", re.I)),
    ("Facebook", re.compile(r"^https?://(?:www\.)?facebook\.com/([A-Za-z0-9.\-]{2,})/?$", re.I)),
    ("Instagram", re.compile(r"^https?://(?:www\.)?instagram\.com/([A-Za-z0-9_.]{2,30})/?$", re.I)),
    ("YouTube", re.compile(r"^https?://(?:www\.)?youtube\.com/((?:@|c/|channel/|user/)[A-Za-z0-9_.\-]+)/?$", re.I)),
    ("GitHub", re.compile(r"^https?://(?:www\.)?github\.com/([A-Za-z0-9-]{1,39})/?$", re.I)),
    ("TikTok", re.compile(r"^https?://(?:www\.)?tiktok\.com/(@[A-Za-z0-9_.]{2,24})/?$", re.I)),
]
_RESERVED_HANDLES = {"share", "sharer", "intent", "home", "login", "signup", "hashtag", "search", "watch", "about"}


def social_accounts(markup: str) -> list[tuple[str, str, str]]:
    """(platform, handle, url) for each official account linked from a homepage."""
    urls = [u for u in _HREF_RE.findall(markup)]
    for block in _SAME_AS_RE.findall(markup):
        urls.extend(_URL_IN_TEXT_RE.findall(block))
    found: dict[tuple[str, str], tuple[str, str]] = {}
    for raw in urls:
        url = raw.split("?", 1)[0].split("#", 1)[0]
        for platform, pattern in _SOCIAL_PATTERNS:
            match = pattern.match(url)
            if match:
                handle = match.group(1)
                if handle.lower().lstrip("@") not in _RESERVED_HANDLES:
                    found.setdefault((platform, handle.lower()), (handle, url))
                break
    return [(platform, handle, url) for (platform, _key), (handle, url) in sorted(found.items())]


class WebPresenceAdapter(ReconAdapter):
    """Fetches the organization's own public homepage -- the same request any visitor's browser
    makes -- to record its title/description and any technology hints volunteered in response
    headers. Honors robots.txt and never follows links off the confirmed domain."""

    name = "Official Website"
    modes = frozenset({AccessMode.PUBLIC_PROFILE, AccessMode.AUTHORIZED_PASSIVE})

    async def run(self, *, domain: str, organization_name: str, timeout: float) -> list[AdapterFinding]:
        allowed = await robots_allows(domain, "/", timeout=timeout)
        if not allowed:
            raise AdapterError(f"robots.txt disallows fetching {domain}/")

        url = f"https://{domain}/"
        try:
            response = await safe_get(url, timeout=timeout)
        except UnsafeUrlError as exc:
            raise AdapterError(str(exc)) from exc
        except Exception as exc:
            raise AdapterError(f"Could not reach {domain}: {exc}") from exc

        if response.status_code >= 400:
            raise AdapterError(f"{domain} returned status {response.status_code}")

        html = response.text[:500_000]
        title_match = _TITLE_RE.search(html)
        desc_match = _DESC_RE.search(html)
        title = (title_match.group(1).strip() if title_match else domain)[:300]
        description = desc_match.group(1).strip()[:500] if desc_match else None

        findings = [
            AdapterFinding(
                category=ResultCategory.WEB_PRESENCE,
                title=f"Official website: {domain}",
                summary=description or title,
                dedupe_key=f"official-site:{domain}",
                source_name="Official Website",
                source_url=url,
                confidence=1.0,
                rationale="Confirmed organization domain responded with a public homepage.",
            )
        ]

        for platform, handle, social_url in social_accounts(html):
            findings.append(
                AdapterFinding(
                    category=ResultCategory.WEB_PRESENCE,
                    title=f"Official {platform} account: {handle}",
                    summary=f"{platform} account linked from the organization's own homepage.",
                    # Same key shape as the Wikidata adapter, so an account both sources report
                    # is shown once rather than twice.
                    dedupe_key=f"social:{platform.lower()}:{handle.lower()}",
                    source_name="Official Website",
                    source_url=social_url,
                    confidence=0.9,
                    rationale=f"Linked from https://{domain}/ (navigation/footer link or schema.org sameAs).",
                )
            )

        return findings
