from __future__ import annotations

import html
import re

import httpx

from app.config import get_settings
from app.models import AccessMode, ResultCategory
from app.services.recon import wikidata
from app.services.recon.base import AdapterError, AdapterFinding, ReconAdapter, gather_limited

_SUBMISSIONS_URL = "https://data.sec.gov/submissions/CIK{cik:010d}.json"
_ARCHIVE_URL = "https://www.sec.gov/Archives/edgar/data/{cik}/{accession}/{document}"

# Key organization-published filings worth surfacing as Public Documents, newest first.
_KEY_FORMS = {
    "10-K": "Annual report (10-K)",
    "20-F": "Annual report, foreign issuer (20-F)",
    "10-Q": "Quarterly report (10-Q)",
    "DEF 14A": "Proxy statement (DEF 14A) — lists directors and executive officers",
    "8-K": "Current report (8-K)",
}
_PER_FORM_LIMIT = {"8-K": 3}
# Forms 3/4 are statutory insider filings: each names a director or officer and their title.
# Bounded so a company with hundreds of filings can't turn one run into hundreds of requests.
_INSIDER_FORMS = {"3", "4"}
_MAX_INSIDER_FILINGS = 25
_NAME_SUFFIXES = {"JR", "JR.", "SR", "SR.", "II", "III", "IV"}


def _xml_field(xml: str, tag: str) -> str | None:
    match = re.search(rf"<{tag}>\s*(.*?)\s*</{tag}>", xml, re.DOTALL)
    return html.unescape(match.group(1).strip()) if match else None


def _display_name(filed_name: str) -> str:
    """EDGAR lists reporting owners surname-first ('SEIFERT THOMAS J', 'Zatlyn Michelle').
    Reorders to 'Thomas J Seifert' and title-cases all-caps filings, keeping suffixes last."""
    parts = filed_name.split()
    if len(parts) < 2:
        return filed_name.strip()
    suffix = [parts.pop()] if parts[-1].upper() in _NAME_SUFFIXES and len(parts) > 2 else []
    ordered = parts[1:] + parts[:1] + suffix
    name = " ".join(ordered)
    return name.title() if name.isupper() else name


def parse_insider_filing(xml: str) -> tuple[str, str] | None:
    """(display name, role) for a director/officer reporting owner, else None. Ten-percent
    holders that are neither (usually funds) are skipped; addresses are never read."""
    name = _xml_field(xml, "rptOwnerName")
    if not name:
        return None
    is_director = _xml_field(xml, "isDirector") in ("1", "true")
    is_officer = _xml_field(xml, "isOfficer") in ("1", "true")
    if not (is_director or is_officer):
        return None
    roles: list[str] = []
    title = _xml_field(xml, "officerTitle") if is_officer else None
    if title:
        roles.append(title)
    elif is_officer:
        roles.append("Officer")
    # Titles like "President and Board Co-Chair" already state the board seat.
    if is_director and not (title and re.search(r"director|board", title, re.IGNORECASE)):
        roles.append("Director")
    return _display_name(name), ", ".join(roles)


class SecEdgarAdapter(ReconAdapter):
    """US SEC EDGAR, the government's public filing system, for companies that are SEC
    registrants: the registrant profile, links to key filings, and named directors/officers
    from statutory insider filings. Uses the official data.sec.gov JSON API and archive, within
    the SEC's fair-access limits (identified User-Agent, a few bounded requests per run)."""

    name = "SEC EDGAR"
    modes = frozenset({AccessMode.AUTHORIZED_PASSIVE})
    timeout_budget_multiplier = 6

    async def run(self, *, domain: str, organization_name: str, timeout: float) -> list[AdapterFinding]:
        company = await wikidata.fetch_company(organization_name, timeout=timeout)
        if company is None or company.matches_domain(domain) is False:
            return []
        ciks = company.strings(wikidata.SEC_CIK)
        if not ciks or not ciks[0].isdigit():
            return []  # Not an SEC registrant -- nothing to look up, not a failure.
        contact = get_settings().sec_contact_email.strip()
        if not contact:
            raise AdapterError("SEC EDGAR skipped: set SEC_CONTACT_EMAIL in .env (required by SEC fair-access policy)")
        cik = int(ciks[0])

        headers = {"User-Agent": f"EthicalHawkRecon/0.2 {contact}"}
        try:
            async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
                response = await client.get(_SUBMISSIONS_URL.format(cik=cik))
                if response.status_code != 200:
                    raise AdapterError(f"SEC EDGAR returned status {response.status_code}")
                data = response.json()

                findings = [*self._profile(data, cik), *self._key_filings(data, cik)]
                insider_urls = self._insider_filing_urls(data, cik)

                async def fetch(url: str):
                    try:
                        r = await client.get(url)
                    except httpx.HTTPError:
                        return url, None
                    return url, (r.text if r.status_code == 200 else None)

                fetched = await gather_limited((fetch(u) for u in insider_urls), limit=3)
        except httpx.HTTPError as exc:
            raise AdapterError(f"SEC EDGAR request failed: {exc}") from exc
        except ValueError as exc:
            raise AdapterError("SEC EDGAR returned an unparsable response") from exc

        people: dict[str, tuple[str, str, str]] = {}
        for url, xml in fetched:
            parsed = parse_insider_filing(xml) if xml else None
            if parsed and parsed[0].lower() not in people:
                people[parsed[0].lower()] = (parsed[0], parsed[1], url)
        for key, (name, role, url) in sorted(people.items()):
            findings.append(
                AdapterFinding(
                    category=ResultCategory.PEOPLE,
                    title=f"{name} — {role}",
                    summary=f"Role as filed: {role}. Named in a statutory SEC insider filing (Form 3/4).",
                    dedupe_key=f"person:sec:{cik}:{key}",
                    source_name="SEC EDGAR",
                    source_url=url,
                    confidence=0.95,
                    rationale="Official regulatory filing; reporting-owner name and relationship as filed.",
                )
            )
        return findings

    @staticmethod
    def _profile(data: dict, cik: int) -> list[AdapterFinding]:
        lines: list[str] = []
        if data.get("name"):
            lines.append(f"Registered name: {data['name']}")
        if data.get("sicDescription"):
            lines.append(f"Industry (SIC {data.get('sic')}): {data['sicDescription']}")
        if data.get("stateOfIncorporation"):
            lines.append(f"State of incorporation: {data['stateOfIncorporation']}")
        tickers = [
            f"{exchange}: {ticker}" if exchange else ticker
            for ticker, exchange in zip(data.get("tickers") or [], data.get("exchanges") or [], strict=False)
        ]
        if tickers:
            lines.append(f"Listed as: {', '.join(tickers)}")
        if data.get("category"):
            lines.append(f"Filer category: {data['category']}")
        fye = data.get("fiscalYearEnd") or ""
        if len(fye) == 4:
            lines.append(f"Fiscal year ends: {fye[:2]}/{fye[2:]} (MM/DD)")
        address = (data.get("addresses") or {}).get("business") or {}
        parts = [address.get("street1"), address.get("city"), address.get("stateOrCountryDescription"),
                 address.get("zipCode")]
        if any(parts):
            lines.append("Business address (corporate): " + ", ".join(p for p in parts if p))
        former = [f.get("name") for f in data.get("formerNames") or [] if f.get("name")]
        if former:
            lines.append(f"Former names: {', '.join(former)}")
        if not lines:
            return []
        return [
            AdapterFinding(
                category=ResultCategory.WEB_PRESENCE,
                title=f"SEC registrant profile: {data.get('name', cik)}",
                summary="\n".join(lines),
                dedupe_key=f"company-profile:sec:{cik}",
                source_name="SEC EDGAR",
                source_url=f"https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK={cik}",
                confidence=1.0,
                rationale="Registrant data from the SEC's official EDGAR filing system.",
            )
        ]

    @staticmethod
    def _key_filings(data: dict, cik: int) -> list[AdapterFinding]:
        recent = (data.get("filings") or {}).get("recent") or {}
        forms = recent.get("form") or []
        counts: dict[str, int] = {}
        findings: list[AdapterFinding] = []
        for i, form in enumerate(forms):
            if form not in _KEY_FORMS or counts.get(form, 0) >= _PER_FORM_LIMIT.get(form, 1):
                continue
            counts[form] = counts.get(form, 0) + 1
            accession = recent["accessionNumber"][i]
            filed = recent["filingDate"][i]
            url = _ARCHIVE_URL.format(cik=cik, accession=accession.replace("-", ""),
                                      document=recent["primaryDocument"][i])
            findings.append(
                AdapterFinding(
                    category=ResultCategory.DOCUMENTS,
                    title=f"{_KEY_FORMS[form]} — filed {filed}",
                    summary=f"SEC filing {accession}.",
                    dedupe_key=f"sec-filing:{accession}",
                    source_name="SEC EDGAR",
                    source_url=url,
                    confidence=1.0,
                    rationale="Organization-published regulatory filing in the SEC's public EDGAR archive.",
                )
            )
        return findings

    @staticmethod
    def _insider_filing_urls(data: dict, cik: int) -> list[str]:
        recent = (data.get("filings") or {}).get("recent") or {}
        urls: list[str] = []
        for i, form in enumerate(recent.get("form") or []):
            if form not in _INSIDER_FORMS:
                continue
            # primaryDocument points at the XSL-rendered view ('xslF345X05/form4.xml'); the raw
            # XML sits at the same name without that rendering-directory prefix.
            document = re.sub(r"^xsl[^/]+/", "", recent["primaryDocument"][i])
            urls.append(_ARCHIVE_URL.format(cik=cik, accession=recent["accessionNumber"][i].replace("-", ""),
                                            document=document))
            if len(urls) >= _MAX_INSIDER_FILINGS:
                break
        return urls
