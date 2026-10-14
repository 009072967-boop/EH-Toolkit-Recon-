from __future__ import annotations

import re

import httpx

from app.models import AccessMode, ResultCategory
from app.services.recon.base import AdapterError, AdapterFinding, ReconAdapter

# Conservative patterns for named leadership roles mentioned in a public encyclopedia summary.
# We deliberately do not scrape professional-network profiles or attempt to enumerate staff --
# only surface names Wikipedia's own editors already attribute a public role to.
_ROLE_PATTERNS = [
    (re.compile(r"founded by ([A-Z][\w.\-]+(?: [A-Z][\w.\-]+){0,3})"), "Founder"),
    (re.compile(r"[Cc]hief [Ee]xecutive [Oo]fficer,? ([A-Z][\w.\-]+(?: [A-Z][\w.\-]+){0,3})"), "CEO"),
    (re.compile(r"([A-Z][\w.\-]+(?: [A-Z][\w.\-]+){0,3}),? (?:is|serves as) (?:the )?CEO"), "CEO"),
    (
        re.compile(
            r"([A-Z][\w.\-]+(?: [A-Z][\w.\-]+){0,3})\s+(?:is|serves as)\s+(?:the )?"
            r"(?:president and )?(?:CEO|[Cc]hief [Ee]xecutive [Oo]fficer)"
        ),
        "CEO",
    ),
]


class PeopleAdapter(ReconAdapter):
    """Best-effort extraction of publicly attributed leadership names/titles from the same public
    encyclopedia summary used for the organization overview. Never collects personal contact
    details, and returns nothing rather than guessing when no clear public attribution exists."""

    name = "Wikipedia"
    modes = frozenset({AccessMode.AUTHORIZED_PASSIVE})

    async def run(self, *, domain: str, organization_name: str, timeout: float) -> list[AdapterFinding]:
        title = organization_name.strip().replace(" ", "_")
        url = f"https://en.wikipedia.org/api/rest_v1/page/summary/{title}"
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
                response = await client.get(url, headers={"User-Agent": "EthicalHawkRecon/0.2"})
        except httpx.HTTPError as exc:
            raise AdapterError(f"Wikipedia request failed: {exc}") from exc

        if response.status_code != 200:
            return []

        extract = (response.json().get("extract") or "")
        seen: set[str] = set()
        findings: list[AdapterFinding] = []
        for pattern, role in _ROLE_PATTERNS:
            for match in pattern.finditer(extract):
                name = match.group(1).strip().rstrip(".")
                key = f"{role}:{name}"
                if not name or key in seen:
                    continue
                seen.add(key)
                findings.append(
                    AdapterFinding(
                        category=ResultCategory.PEOPLE,
                        title=f"{name} -- {role}",
                        summary=f"Publicly attributed as {role.lower()} in the org's public encyclopedia summary.",
                        dedupe_key=f"person:{name}:{role}",
                        source_name="Wikipedia",
                        source_url=response.json().get("content_urls", {}).get("desktop", {}).get("page", url),
                        confidence=0.5,
                        rationale="Text-pattern match against a public encyclopedia summary; verify independently.",
                    )
                )
        return findings
