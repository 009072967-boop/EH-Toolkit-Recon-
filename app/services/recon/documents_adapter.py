from __future__ import annotations

import asyncio
import re
from urllib.parse import unquote, urlparse

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

# Conventional, widely-used public paths, tried on the confirmed domain regardless of what the
# homepage links to -- this is what still finds a security.txt file, since it's rarely linked
# from navigation. We only ever visit URLs on the organization's own confirmed domain (or a
# subdomain of it) -- never a third-party search index -- and only if robots.txt permits it.
_CANDIDATE_PATHS = {
    "/press": "Press/News",
    "/newsroom": "Press/News",
    "/news": "Press/News",
    "/investors": "Investor Relations",
    "/about": "About",
    "/careers": "Careers",
    "/contact": "Contact",
    "/support": "Support",
    "/help": "Help Center",
    "/leadership": "Leadership",
    "/team": "Team",
    "/security.txt": "Security Policy",
    "/.well-known/security.txt": "Security Policy",
}

# Real corporate sites often don't use the conventional paths above (many CMS platforms use
# deep, locale-prefixed URLs instead). Scanning the homepage's own navigation for links matching
# these keywords finds the organization's actual pages regardless of URL shape. Order matters:
# the first matching keyword decides a link's label, so more specific terms are listed first.
_DISCOVERY_KEYWORDS = {
    "leadership": "Leadership",
    "executive": "Leadership",
    "management-team": "Leadership",
    "our-team": "Team",
    "meet-the-team": "Team",
    "team": "Team",
    "contact-us": "Contact",
    "contact": "Contact",
    "support": "Support",
    "help": "Help Center",
    "about-us": "About",
    "about": "About",
    "newsroom": "Press/News",
    "press": "Press/News",
    "media": "Press/News",
    "news": "Press/News",
    "investor": "Investor Relations",
    "career": "Careers",
    "security": "Security Policy",
}

_PHONE_SCAN_LABELS = {"Contact", "Support", "Help Center"}
# A page merely mentioning "support" (a job listing for a "Support Specialist", a blog post)
# gets labeled Support/Help Center by the loose substring match above, but is not an actual
# contact page and must not have its full script/JSON body regex-scanned for phone numbers --
# that's what produced false positives like CSS breakpoint values. Require the URL's own final
# path segment to look like a genuine contact-style page before scanning it for numbers.
_STRONG_CONTACT_SLUGS = ("contact", "support", "help", "customer-service", "helpdesk")


def _looks_like_contact_page(url: str) -> bool:
    slug = urlparse(url).path.rstrip("/").rsplit("/", 1)[-1].lower()
    return any(slug == s or slug.startswith(f"{s}-") or slug.endswith(f"-{s}") for s in _STRONG_CONTACT_SLUGS)

# Only organization-role inboxes are surfaced. A security.txt file can legally contain
# a person's address, but the product deliberately does not aggregate personal contacts.
_ORGANIZATION_MAILBOXES = {
    "abuse",
    "contact",
    "csirt",
    "help",
    "helpdesk",
    "info",
    "noc",
    "privacy",
    "security",
    "soc",
    "support",
}

_MAILTO_RE = re.compile(r"mailto:([^\s\"'<>?#]+)", re.IGNORECASE)
_PLAIN_EMAIL_RE = re.compile(r"(?<![\w.+-])([a-z0-9._+-]+@[a-z0-9.-]+\.[a-z]{2,63})(?![\w.-])", re.IGNORECASE)
_TEL_RE = re.compile(r"tel:([^\s\"'<>?#]+)", re.IGNORECASE)
# Requires realistic phone-style grouping -- a leading (country/area) chunk, at least one
# middle chunk, and a final subscriber-style chunk of 3-4 digits -- so this does not match
# bare digit runs or decimal-looking values (IDs, version strings, coordinates) embedded in
# script-heavy pages. Deliberately excludes "." as a separator, since periods in scraped
# script/JSON text are far more often decimals than phone-number grouping. Free-standing
# tel: links are still accepted via _TEL_RE regardless of formatting, since those are
# deliberate markup rather than free-text pattern matches.
_PHONE_RE = re.compile(
    r"(?<!\w)(\+?\(?[0-9]{1,4}\)?(?:[ \-]\(?[0-9]{2,4}\)?){1,5}[ \-]\(?[0-9]{3,4}\)?)(?!\w)"
)


def _published_security_contact(value: str) -> str | None:
    """Return a deliberately published organization contact endpoint, if safe to retain."""
    value = value.strip()
    if value.lower().startswith("mailto:"):
        address = unquote(value[7:]).split("?", 1)[0].strip()
        if "@" not in address:
            return None
        local_part = address.split("@", 1)[0].lower().split("+", 1)[0]
        return address if local_part in _ORGANIZATION_MAILBOXES else None
    if value.lower().startswith(("https://", "http://")):
        return value
    return None


def _organization_inboxes_from_page(domain: str, url: str, text: str) -> list[AdapterFinding]:
    """Extract only generic inboxes deliberately displayed on an official public page."""
    candidates = set(_MAILTO_RE.findall(text)) | set(_PLAIN_EMAIL_RE.findall(text))
    findings: list[AdapterFinding] = []
    for raw_address in sorted(candidates, key=str.lower):
        address = unquote(raw_address).split("?", 1)[0].strip().lower()
        if "@" not in address:
            continue
        local_part, email_domain = address.rsplit("@", 1)
        if local_part.split("+", 1)[0] not in _ORGANIZATION_MAILBOXES:
            continue
        if email_domain != domain and not email_domain.endswith(f".{domain}"):
            continue
        findings.append(
            AdapterFinding(
                category=ResultCategory.DOCUMENTS,
                title=f"Published organization contact for {domain}",
                summary=address,
                dedupe_key=f"organization-contact:{domain}:{address}",
                source_name="Official public page",
                source_url=url,
                confidence=0.9,
                rationale="Role-based inbox displayed on an official, publicly accessible page.",
            )
        )
    return findings


def _customer_phone_numbers(domain: str, url: str, text: str) -> list[AdapterFinding]:
    """Return phone numbers only from an official customer-contact style page."""
    candidates = set(_TEL_RE.findall(text)) | set(_PHONE_RE.findall(text))
    findings: list[AdapterFinding] = []
    for raw_number in sorted(candidates):
        number = unquote(raw_number).split("?", 1)[0].strip()
        digits = re.sub(r"\D", "", number)
        if not 7 <= len(digits) <= 16:
            continue
        findings.append(
            AdapterFinding(
                category=ResultCategory.DOCUMENTS,
                title=f"Published customer contact number for {domain}",
                summary=number,
                dedupe_key=f"customer-phone:{domain}:{digits}",
                source_name="Official public page",
                source_url=url,
                confidence=0.9,
                rationale="Phone number displayed on an official public contact, support, or help page.",
            )
        )
    return findings


def _security_txt_findings(domain: str, path: str, url: str, text: str) -> list[AdapterFinding]:
    findings: list[AdapterFinding] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        field, value = line.split(":", 1)
        if field.strip().lower() != "contact":
            continue
        contact = _published_security_contact(value)
        if contact is None:
            continue
        findings.append(
            AdapterFinding(
                category=ResultCategory.DOCUMENTS,
                title=f"Published security contact for {domain}",
                summary=contact,
                dedupe_key=f"security-contact:{domain}:{contact.lower()}",
                source_name="Official security.txt",
                source_url=url,
                confidence=1.0,
                rationale=f"Organization-published Contact field in {path}.",
            )
        )
    return findings


class PublicDocumentsAdapter(ReconAdapter):
    """Checks a small set of conventional public paths on the organization's own domain (press,
    investor relations, security.txt, etc.) rather than scraping any third-party search index --
    keeping this within source ToS and away from access-controlled material."""

    name = "Public Pages"
    modes = frozenset({AccessMode.AUTHORIZED_PASSIVE})
    timeout_budget_multiplier = 4

    async def run(self, *, domain: str, organization_name: str, timeout: float) -> list[AdapterFinding]:
        domain_parser = await fetch_robots_parser(domain, timeout=timeout)

        candidates: list[tuple[str, str]] = [
            (f"https://{domain}{path}", doc_type) for path, doc_type in _CANDIDATE_PATHS.items()
        ]

        if path_allowed(domain_parser, "/"):
            try:
                homepage = await safe_get(f"https://{domain}/", timeout=timeout)
            except Exception:
                homepage = None
            if homepage is not None and homepage.status_code == 200:
                discovered = discover_same_domain_links(
                    domain, str(homepage.url), homepage.text[:500_000], _DISCOVERY_KEYWORDS
                )
                seen_urls = {url for url, _ in candidates}
                for url, label in discovered:
                    if url not in seen_urls:
                        seen_urls.add(url)
                        candidates.append((url, label))

        other_hosts = {urlparse(url).hostname for url, _ in candidates} - {domain}
        other_parsers = await asyncio.gather(
            *(fetch_robots_parser(host, timeout=timeout) for host in other_hosts)
        )
        robots_by_host = {domain: domain_parser, **dict(zip(other_hosts, other_parsers))}

        allowed = [
            (url, label)
            for url, label in candidates
            if path_allowed(robots_by_host.get(urlparse(url).hostname), urlparse(url).path or "/")
        ]

        async def fetch(url: str):
            try:
                response = await safe_get(url, timeout=timeout)
            except UnsafeUrlError:
                return None
            except Exception:
                return None
            return response

        fetched = await gather_limited((fetch(url) for url, _ in allowed))

        # Contact/leadership pages are frequently linked one hop deeper than the homepage --
        # e.g. from an "About" page rather than the main nav. Follow matching links found on
        # pages we already fetched, bounded so this can't spiral into a real crawl.
        second_hop: list[tuple[str, str]] = []
        seen_urls = {url for url, _ in allowed}
        for (_url, _doc_type), response in zip(allowed, fetched):
            if response is None or response.status_code != 200:
                continue
            for hop_url, hop_label in discover_same_domain_links(
                domain, str(response.url), response.text[:500_000], _DISCOVERY_KEYWORDS,
                per_label_limit=2, limit=6,
            ):
                if hop_url not in seen_urls:
                    seen_urls.add(hop_url)
                    second_hop.append((hop_url, hop_label))

        if second_hop:
            hop_hosts = {urlparse(u).hostname for u, _ in second_hop} - set(robots_by_host)
            hop_parsers = await asyncio.gather(
                *(fetch_robots_parser(h, timeout=timeout) for h in hop_hosts)
            )
            robots_by_host.update(zip(hop_hosts, hop_parsers))
            hop_allowed = [
                (u, label) for u, label in second_hop
                if path_allowed(robots_by_host.get(urlparse(u).hostname), urlparse(u).path or "/")
            ]
            fetched = fetched + await gather_limited((fetch(u) for u, _ in hop_allowed))
            allowed = allowed + hop_allowed

        findings: list[AdapterFinding] = []
        reachable = False

        for (url, doc_type), response in zip(allowed, fetched):
            if response is None:
                continue

            reachable = True
            if response.status_code == 200:
                parsed = urlparse(url)
                location = f"{parsed.hostname}{parsed.path}"
                findings.append(
                    AdapterFinding(
                        category=ResultCategory.DOCUMENTS,
                        title=f"{doc_type}: {location}",
                        summary=f"Publicly accessible {doc_type.lower()} page on the confirmed domain.",
                        dedupe_key=f"public-page:{location}",
                        source_name="Public Pages",
                        source_url=url,
                        confidence=0.9,
                        rationale="Public page on the organization's own domain returned HTTP 200 without authentication.",
                    )
                )
                if parsed.path.endswith("security.txt"):
                    findings.extend(_security_txt_findings(domain, parsed.path, url, response.text[:100_000]))
                else:
                    findings.extend(_organization_inboxes_from_page(domain, url, response.text[:250_000]))
                    if doc_type in _PHONE_SCAN_LABELS and _looks_like_contact_page(url):
                        findings.extend(_customer_phone_numbers(domain, url, response.text[:250_000]))

        if not reachable:
            raise AdapterError(f"Could not reach any known public paths on {domain}")
        return findings
