from __future__ import annotations

import asyncio
import html
import re
import urllib.robotparser
from abc import ABC, abstractmethod
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

from app.models import AccessMode, ResultCategory
from app.services.ssrf_guard import safe_get

USER_AGENT = "EthicalHawkRecon/0.2 (+passive-research-tool; authorized-use-only)"


class AdapterError(Exception):
    """Raised when a source adapter cannot complete. Caught per-adapter by the pipeline
    so one flaky/blocked source degrades the run to 'incomplete' rather than failing it."""


@dataclass(frozen=True)
class AdapterFinding:
    category: ResultCategory
    title: str
    summary: str | None
    dedupe_key: str
    source_name: str
    source_url: str | None
    confidence: float
    rationale: str | None = None


class ReconAdapter(ABC):
    name: str
    modes: frozenset[AccessMode]
    # How many multiples of the per-request timeout the pipeline should allow this adapter's
    # whole run() call. Most adapters make one or two sequential requests (a robots.txt check,
    # one page). Adapters that chain robots.txt -> homepage -> discovered pages -> a bounded
    # second hop need more headroom and should override this rather than the pipeline giving
    # every adapter the same generous budget regardless of how much work it actually does.
    timeout_budget_multiplier: int = 2

    @abstractmethod
    async def run(self, *, domain: str, organization_name: str, timeout: float) -> list[AdapterFinding]:
        """Return normalized findings. Raise AdapterError on failure; never raise other exceptions."""


async def fetch_robots_parser(domain: str, *, timeout: float) -> urllib.robotparser.RobotFileParser | None:
    """Fetches and parses robots.txt once. None means unreachable -- callers should treat that
    as allow-all, matching robots_allows' fail-open behavior. Lets multi-path adapters check many
    paths against a single fetch instead of one network round-trip per path."""
    try:
        response = await safe_get(f"https://{domain}/robots.txt", timeout=timeout)
    except Exception:
        return None
    if response.status_code >= 400:
        return None
    parser = urllib.robotparser.RobotFileParser()
    parser.parse(response.text.splitlines())
    return parser


# Statuses a site (or its CDN/WAF, e.g. Cloudflare) returns when it is refusing automated
# requests rather than saying "this page doesn't exist".
_BLOCKED_STATUSES = {401, 403, 429, 503}


def raise_if_blocked(domain: str, statuses: list[int]) -> None:
    """An adapter whose every page came back as a refusal must report that as a failure.
    Returning an empty list instead makes a blocked scan indistinguishable from an organization
    that genuinely publishes nothing -- the run would show empty categories with no warning."""
    if not statuses or 200 in statuses:
        return
    blocked = sorted(s for s in set(statuses) if s in _BLOCKED_STATUSES)
    if blocked:
        codes = ", ".join(f"HTTP {s}" for s in blocked)
        raise AdapterError(f"{domain} refused automated requests ({codes}); try again later")


async def gather_limited(coros, *, limit: int = 5) -> list:
    """Runs coroutines concurrently but capped at `limit` in flight at once. Fetching every
    candidate/discovered URL fully in parallel can put 20-30+ simultaneous connections on a
    single target host, which is impolite and reliably trips rate-limiting/WAF blocking on
    real sites -- this keeps adapters fast without bursting a target that hard."""
    semaphore = asyncio.Semaphore(limit)

    async def run(coro):
        async with semaphore:
            return await coro

    return await asyncio.gather(*(run(c) for c in coros))


def path_allowed(parser: urllib.robotparser.RobotFileParser | None, path: str) -> bool:
    if parser is None:
        return True
    try:
        return parser.can_fetch(USER_AGENT, path)
    except Exception:
        return True


async def robots_allows(domain: str, path: str, *, timeout: float) -> bool:
    """Best-effort robots.txt check. Fails open (allows) only if robots.txt itself is unreachable,
    since an unreachable robots.txt is not a disallow signal -- but any parsed rule is honored."""
    parser = await fetch_robots_parser(domain, timeout=timeout)
    return path_allowed(parser, path)


_ANCHOR_RE = re.compile(r'<a\b[^>]*href=["\']([^"\'#]+)["\'][^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL)
_INNER_TAG_RE = re.compile(r"<[^>]+>")


def discover_same_domain_links(
    domain: str,
    base_url: str,
    markup: str,
    keywords: dict[str, str],
    *,
    per_label_limit: int = 3,
    limit: int = 24,
) -> list[tuple[str, str]]:
    """Scans a page's own <a> tags for links whose path or visible text match a keyword (e.g.
    "contact", "leadership"), restricted to the organization's own domain or a subdomain of it.
    Many real corporate sites don't use conventional paths like /contact or /leadership -- this
    lets an adapter follow the site's actual published navigation instead of guessing a fixed
    path list, while staying within the same never-leave-the-confirmed-domain guarantee.

    Caps how many links are kept per label (not just overall) -- a nav with twenty "About"-style
    links and one "Contact" link must not let the About links crowd the single Contact link out
    of a flat overall cap, which is what a simple first-N-encountered limit would do."""
    seen: set[str] = set()
    by_label: dict[str, list[tuple[str, str]]] = {}
    for match in _ANCHOR_RE.finditer(markup):
        href, inner_html = match.group(1), match.group(2)
        absolute = urljoin(base_url, href).split("#", 1)[0]
        parsed = urlparse(absolute)
        if parsed.scheme not in ("http", "https"):
            continue
        host = (parsed.hostname or "").lower()
        if host != domain and not host.endswith(f".{domain}"):
            continue
        if absolute in seen:
            continue
        text = html.unescape(_INNER_TAG_RE.sub(" ", inner_html)).strip().lower()
        haystack = f"{parsed.path.lower()} {text}"
        for keyword, label in keywords.items():
            if keyword in haystack:
                bucket = by_label.setdefault(label, [])
                if len(bucket) < per_label_limit:
                    seen.add(absolute)
                    bucket.append((absolute, label))
                break
    found: list[tuple[str, str]] = []
    for bucket in by_label.values():
        found.extend(bucket)
    return found[:limit]
