from __future__ import annotations

import asyncio
import html
import json
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
    raise_if_blocked,
)
from app.services.ssrf_guard import UnsafeUrlError, safe_get

_LEADERSHIP_PATHS = (
    "/leadership",
    "/about/leadership",
    "/company/leadership",
    "/leadership-team",
    "/team",
    "/our-team",
    "/about/team",
    "/board",
    "/about",
    "/about-us",
)

# Real corporate sites often publish leadership bios under deep, CMS-specific URLs rather than
# the conventional paths above. Scanning the homepage's own navigation for these keywords finds
# the organization's actual leadership/about page regardless of URL shape.
_DISCOVERY_KEYWORDS = {
    "leadership": "leadership",
    "executive": "leadership",
    "management-team": "leadership",
    "board-of-directors": "board",
    "directors": "board",
    "governance": "board",
    "founders": "team",
    "our-team": "team",
    "meet-the-team": "team",
    "team": "team",
    "people": "team",
    "who-we-are": "about",
    "about-us": "about",
    "about": "about",
}

_TITLE_WORD = r"[A-Z][a-z]+"
_DEPARTMENT = rf"{_TITLE_WORD}(?: +(?:and +|& +)?{_TITLE_WORD}){{0,2}}"
# Titles that end unambiguously, safe to match directly against an adjacent name even with
# only whitespace between them (the "title card" layout below).
_ROLE_CORE = (
    r"(?:(?:Co-?)?[Ff]ounder|"
    rf"Chief +{_TITLE_WORD}(?: +(?:and +|& +)?{_TITLE_WORD}){{0,3}} +Officer|"
    r"C[A-Z]{1,3}O|[ES]VP|"
    r"(?:Executive +|Senior +|Corporate +)?Vice +President|"
    r"President|Chair(?:man|woman|person)?(?: +of +the +Board)?|"
    r"General +Counsel|Managing +(?:Director|Partner)|"
    r"(?:Independent +|Non-Executive +|Lead +Independent +)?Director|Board +Member|"
    r"Treasurer|Corporate +Secretary)"
)
# Words within a title or name are joined by spaces only, never a line break (block-element
# boundary). With explicit punctuation between title and name, a trailing department ("Vice President,
# Engineering", "Head of Security") can be captured without swallowing the name itself -- but
# only after a comma or "of", so "Chief Executive Officer Vice President" stays two titles.
_ROLE = rf"(?:{_ROLE_CORE}(?:, *(?:of +)?{_DEPARTMENT}| +of +{_DEPARTMENT})?|Head +of +{_DEPARTMENT})"
_NAME = r"([A-Z][A-Za-z.'-]+(?: +[A-Z][A-Za-z.'-]+){1,3})"
_NAME_FIRST = re.compile(rf"{_NAME}\s*(?:,|—|–|-|\|)\s*\b({_ROLE})\b")
_ROLE_FIRST = re.compile(rf"\b({_ROLE})\s*(?:,|:|—|–|-|\|)\s*{_NAME}")
# Many modern component-based leadership pages render the title as a label directly above the
# name heading (e.g. <span class="eyebrow">Chief Executive Officer</span><h2>Sean Ryan</h2>)
# with no punctuation between them once tags are stripped -- just whitespace. This catches that
# common "title card" layout, which the punctuated patterns above miss entirely.
_ROLE_THEN_NAME_LOOSE = re.compile(rf"\b({_ROLE_CORE})\s+{_NAME}(?=\s|$)")
# ...and the reverse card layout: name heading, then the title beneath it ("Kyle Hanslovan CEO &
# Cofounder"), optionally a second joined title.
_NAME_THEN_ROLE_LOOSE = re.compile(rf"{_NAME}\s+\b({_ROLE_CORE}(?:\s*(?:&|and)\s*{_ROLE_CORE})?)\b")
_TAG_RE = re.compile(r"<[^>]+>")
# Block-level tags become line breaks so separate headings/paragraphs/cards don't run together
# into one sentence ("Sam Lee Priya Shah") once markup is stripped.
_BLOCK_TAG_RE = re.compile(
    r"<(?:/?(?:h[1-6]|p|div|li|ul|ol|tr|td|th|dt|dd|section|article|header|footer|figcaption|blockquote)|br)\b[^>]*>",
    re.IGNORECASE,
)
_SCRIPT_STYLE_RE = re.compile(r"<(?:script|style)[^>]*>.*?</(?:script|style)>", re.IGNORECASE | re.DOTALL)
_JSON_LD_RE = re.compile(
    r"<script[^>]+type=[\"']application/ld\+json[\"'][^>]*>(.*?)</script>", re.IGNORECASE | re.DOTALL
)

# Words that show a "name" capture is really UI text or another title ("Learn More", "Read
# Bio", "Board Directors"), not a person. Any one of them in a capture rejects it.
_NOT_NAME_WORDS = {
    "about", "all", "and", "back", "bio", "biography", "board", "chair", "chairman", "chief", "close",
    "company", "contact", "corp", "counsel", "director", "directors", "download", "email", "executive",
    "executives", "founder", "full", "general", "head", "home", "inc", "leadership", "learn", "linkedin",
    "llc", "management", "managing", "meet", "member", "members", "menu", "more", "news", "next", "of",
    "officer", "officers", "our", "partner", "president", "previous", "profile", "read", "see", "senior",
    "team", "the", "twitter", "us", "vice", "video", "view", "watch",
    # Department/organization words that get glued onto a neighbouring name when a card layout
    # is flattened to text ("Corporate Development Ronnie Parikh", "Smithfield Foods Jim Nelms").
    "capital", "co-founder", "cofounder", "corporate", "council", "current", "customer", "customers", "deputy",
    "development", "market",
    "engineer", "engineering", "finance", "foods", "former", "global", "group", "holdings", "human",
    "interim", "international", "investor", "investors", "legal", "marketing", "offensive", "operations",
    "partners", "people", "platform", "product", "products", "resources", "revenue", "sales", "security",
    "services", "solutions", "strategy", "success", "systems", "technologies", "technology", "united",
    "ventures",
}
_HONORIFICS = {"dr.", "jr.", "sr.", "mr.", "ms.", "mrs.", "st."}
# schema.org Person objects under these keys describe someone other than the organization's own
# staff -- a customer quoted in a testimonial (Review.author), an article's writer, etc.
_NON_STAFF_KEYS = {"author", "review", "reviews", "creator", "editor", "contributor", "mentions", "citation"}


_PEOPLE_PAGE_HINTS = (
    "leadership", "team", "about", "board", "director", "people", "management", "executive", "founder",
    "governance", "who-we-are", "company",
)


def _is_people_page(url: str) -> bool:
    """Only pages whose own path reads as a leadership/team/about page are scanned for names. A
    product or case-study page reached via a loosely matching nav link mostly names *customers*
    (testimonial quotes), not the organization's own staff."""
    path = urlparse(url).path.lower()
    if path in ("", "/"):
        return True
    # Whole hyphen-separated words of a path segment, so "/our-team" and "/leadership-council"
    # count but a marketing page like "/it-security-teams" doesn't.
    words = {word for segment in path.split("/") for word in segment.split("-")}
    return any(hint in words or hint in path.split("/") for hint in _PEOPLE_PAGE_HINTS)


def _looks_like_person(name: str, organization_name: str = "") -> bool:
    words = name.split()
    if not 2 <= len(words) <= 4:
        return False
    org_words = {w.lower() for w in re.findall(r"[A-Za-z]{4,}", organization_name)}
    for word in words:
        # A word ending in a period that isn't an initial or honorific ends the previous
        # sentence ("...Suffolk University. Robert Taccini") -- not part of this name.
        if word.endswith(".") and len(word) > 2 and word.lower() not in _HONORIFICS:
            return False
        bare = word.strip(".,'-")
        # All-caps tokens are titles/acronyms (CEO, SVP) or company names (FDJ), not name parts;
        # single-letter initials like "J." are fine.
        if len(bare) >= 2 and bare.isupper():
            return False
        if bare.lower() in _NOT_NAME_WORDS or bare.lower() in org_words:
            return False
    return True


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


def _published_executives(markup: str, organization_name: str = "") -> list[tuple[str, str]]:
    """Best-effort extraction of executive name/title pairs from official public-page text."""
    text = _SCRIPT_STYLE_RE.sub(" ", markup)
    text = html.unescape(_TAG_RE.sub(" ", _BLOCK_TAG_RE.sub("\n", text)))
    text = re.sub(r"[^\S\n]+", " ", text)  # collapse spaces/tabs but keep line breaks
    text = re.sub(r" *\n\s*", "\n", text)  # one line break per boundary, no stray spaces around it
    pairs: set[tuple[str, str]] = set()
    for match in _NAME_FIRST.finditer(text):
        pairs.add((_clean_captured_name(match.group(1)), match.group(2)))
    for match in _ROLE_FIRST.finditer(text):
        pairs.add((_clean_captured_name(match.group(2)), match.group(1)))
    # The two unpunctuated card layouts are mirror images: on a "Title Name Title Name" page the
    # name-then-title reading pairs each person with the *next* card's title, and vice versa.
    # A page uses one layout, and the correct reading always yields one more complete pair than
    # the shifted one -- so use whichever reading produces more pairs, never both.
    role_first = [(m.group(2), m.group(1)) for m in _ROLE_THEN_NAME_LOOSE.finditer(text)]
    name_first = [(m.group(1), m.group(2)) for m in _NAME_THEN_ROLE_LOOSE.finditer(text)]
    loose = name_first if len(name_first) > len(role_first) else role_first
    for name, role in loose:
        pairs.add((_clean_captured_name(name), role))
    cleaned: set[tuple[str, str]] = set()
    for name, role in pairs:
        person = _trim_to_person(name, organization_name)
        if person:
            cleaned.add((person, re.sub(r"\s+", " ", role)))
    return sorted(cleaned, key=lambda pair: (pair[1], pair[0]))


def _trim_to_person(name: str, organization_name: str) -> str | None:
    """A capture can begin with a heading or company word that preceded the actual name
    ("Leadership Kyle Hanslovan"). Drops leading words until what remains reads as a person,
    rather than discarding a real name because of its neighbour."""
    words = name.split()
    for start in range(len(words) - 1):
        candidate = " ".join(words[start:])
        if _looks_like_person(candidate, organization_name):
            return candidate
    return None


def _structured_data_people(markup: str, organization_name: str = "") -> list[tuple[str, str]]:
    """Name/jobTitle pairs from schema.org Person objects in the page's JSON-LD -- the
    structured markup sites publish for search engines, far more reliable than text patterns
    when present. Only the name and job title are read; never email, telephone, or address."""
    pairs: set[tuple[str, str]] = set()

    def walk(node, depth=0):
        if depth > 8:
            return
        if isinstance(node, list):
            for item in node:
                walk(item, depth + 1)
            return
        if not isinstance(node, dict):
            return
        types = node.get("@type")
        types = types if isinstance(types, list) else [types]
        if "Person" in types:
            name = node.get("name")
            title = node.get("jobTitle")
            if isinstance(title, list):
                title = title[0] if title else None
            if isinstance(title, dict):
                title = title.get("name")
            if isinstance(name, str) and isinstance(title, str):
                name, title = " ".join(name.split()), " ".join(title.split())
                plausible_title = 1 < len(title) <= 120 and title.lower() != name.lower()
                if plausible_title and _looks_like_person(name, organization_name):
                    pairs.add((name, title))
        for key, value in node.items():
            if isinstance(value, (dict, list)) and key not in _NON_STAFF_KEYS:
                walk(value, depth + 1)

    for block in _JSON_LD_RE.findall(markup):
        try:
            walk(json.loads(html.unescape(block.strip())))
        except (ValueError, RecursionError):
            continue
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
        robots_by_host = {domain: domain_parser, **dict(zip(other_hosts, other_parsers, strict=False))}

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
        for _url, response in fetched:
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
            robots_by_host.update(zip(hop_hosts, hop_parsers, strict=False))
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
            if response.status_code != 200 or not _is_people_page(url):
                continue
            # Large component-framework pages carry heavy hydration script payloads before the
            # actual visible content -- 300k chars of a >500k-char page was cutting off before
            # reaching the executive cards entirely. The SSRF guard already caps responses at
            # 2MB, so slicing at that same size means real pages are never truncated in practice.
            markup = response.text[:2_000_000]
            extracted = [
                (name, role, 0.85, "Name/job title published in the page's schema.org structured data.")
                for name, role in _structured_data_people(markup, organization_name)
            ] + [
                (name, role, 0.7, "Public name/title pair found in an official organization page's text.")
                for name, role in _published_executives(markup, organization_name)
            ]
            for name, role, confidence, rationale in extracted:
                key = f"{name.lower()}:{role.lower()}"
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    AdapterFinding(
                        category=ResultCategory.PEOPLE,
                        title=f"{name} — {role}",
                        summary="Professional role shown on the organization's official public page.",
                        dedupe_key=f"official-executive:{domain}:{key}",
                        source_name="Official Leadership Pages",
                        source_url=url,
                        confidence=confidence,
                        rationale=rationale,
                    )
                )
        raise_if_blocked(domain, [r.status_code for _u, r in fetched if r is not None])
        if not reachable:
            raise AdapterError(f"Could not reach official leadership pages for {domain}")
        return findings
