from __future__ import annotations

from app.models import AccessMode, ResultCategory
from app.services.recon import wikidata
from app.services.recon.base import AdapterFinding, ReconAdapter


class WikidataProfileAdapter(ReconAdapter):
    """Organization background (founding, headquarters, industry, size, ownership, listing),
    subsidiaries, official social accounts, and publicly attributed founders/executives/board
    members from Wikidata's structured statements. Runs in both modes; the pipeline's per-mode
    category allowlist keeps the People findings out of Public Profile runs."""

    name = "Wikidata"
    modes = frozenset({AccessMode.PUBLIC_PROFILE, AccessMode.AUTHORIZED_PASSIVE})
    timeout_budget_multiplier = 4

    async def run(self, *, domain: str, organization_name: str, timeout: float) -> list[AdapterFinding]:
        company = await wikidata.fetch_company(organization_name, timeout=timeout)
        if company is None:
            return []
        return company_findings(company, domain)


def company_findings(company: wikidata.WikidataCompany, domain: str) -> list[AdapterFinding]:
    match = company.matches_domain(domain)
    if match is False:
        # The article matched by name lists a different official website -- likely a different
        # organization with a similar name. Still shown (the analyst may know better), but
        # clearly flagged and down-weighted rather than silently presented as fact.
        confidence = 0.4
        rationale = (
            f"Matched by organization name, but Wikidata's official website "
            f"({', '.join(sorted(company.website_hosts()))}) does not match {domain}; verify this is "
            f"the same organization."
        )
    elif match:
        confidence = 0.85
        rationale = f"Structured Wikidata statements; the item's official website matches {domain}."
    else:
        confidence = 0.7
        rationale = "Structured Wikidata statements matched by organization name (no official website listed)."

    def finding(category, title, summary, key, url=None, conf=None, why=None) -> AdapterFinding:
        return AdapterFinding(
            category=category,
            title=title,
            summary=summary,
            dedupe_key=key,
            source_name="Wikidata",
            source_url=url or company.url,
            confidence=conf if conf is not None else confidence,
            rationale=why or rationale,
        )

    findings: list[AdapterFinding] = []

    lines: list[str] = []
    founded = company.statements(wikidata.INCEPTION)
    if founded:
        value = founded[0].get("mainsnak", {}).get("datavalue", {}).get("value", {})
        precision = value.get("precision", 11) if isinstance(value, dict) else 11
        when = wikidata.format_time(f"{value.get('time')}|{precision}") if isinstance(value, dict) else None
        if when:
            lines.append(f"Founded: {when}")
    for label, prop in (
        ("Headquarters", wikidata.HEADQUARTERS),
        ("Country", wikidata.COUNTRY),
        ("Industry", wikidata.INDUSTRY),
        ("Legal form", wikidata.LEGAL_FORM),
        ("Parent organization", wikidata.PARENT_ORG),
        ("Owned by", wikidata.OWNED_BY),
    ):
        values = company.item_labels(prop, current_only=True)
        if values:
            lines.append(f"{label}: {', '.join(values[:6])}")
    for label, prop in (("Employees", wikidata.EMPLOYEES), ("Revenue", wikidata.REVENUE)):
        quantity = company.latest_quantity(prop)
        if quantity:
            amount, as_of = quantity
            lines.append(f"{label}: {amount}" + (f" (as of {as_of})" if as_of else ""))
    listings: list[str] = []
    for s in company.statements(wikidata.STOCK_EXCHANGE, current_only=True):
        exchange = company.labels.get(wikidata.item_id(s) or "", "")
        tickers = [
            q.get("datavalue", {}).get("value")
            for q in s.get("qualifiers", {}).get(wikidata.TICKER, [])
            if q.get("datavalue", {}).get("value")
        ]
        if exchange:
            listings.append(f"{exchange}: {', '.join(tickers)}" if tickers else exchange)
    if listings:
        lines.append(f"Stock listing: {'; '.join(listings)}")
    websites = company.strings(wikidata.OFFICIAL_WEBSITE)
    if websites:
        lines.append(f"Official website: {websites[0]}")
    for label, prop in (("SEC CIK", wikidata.SEC_CIK), ("LEI", wikidata.LEI)):
        values = company.strings(prop)
        if values:
            lines.append(f"{label}: {values[0]}")
    if lines:
        findings.append(
            finding(
                ResultCategory.WEB_PRESENCE,
                f"Company background: {company.label}",
                "\n".join(lines),
                f"company-profile:wikidata:{company.qid}",
            )
        )

    subsidiaries = company.item_labels(wikidata.SUBSIDIARY, current_only=True)
    if subsidiaries:
        shown = subsidiaries[:40]
        more = len(subsidiaries) - len(shown)
        findings.append(
            finding(
                ResultCategory.WEB_PRESENCE,
                f"Subsidiaries of {company.label} ({len(subsidiaries)})",
                ", ".join(shown) + (f", and {more} more" if more > 0 else ""),
                f"subsidiaries:wikidata:{company.qid}",
            )
        )

    for prop, (platform, url_template) in wikidata.SOCIAL_ACCOUNTS.items():
        for handle in company.strings(prop)[:3]:
            url = url_template.format(handle)
            findings.append(
                finding(
                    ResultCategory.WEB_PRESENCE,
                    f"Official {platform} account: {handle}",
                    f"Organization's {platform} presence as listed on Wikidata.",
                    f"social:{platform.lower()}:{handle.lower()}",
                    url=url,
                    why=f"{rationale} Official account identifier recorded on the organization's Wikidata item.",
                )
            )

    # A person often holds several of these at once (founder + CEO + board member) -- group
    # roles per person into one result instead of three near-duplicates.
    roles_by_person: dict[str, list[str]] = {}
    for prop, role in wikidata.PEOPLE_ROLES.items():
        for s in company.statements(prop, current_only=prop != "P112"):
            qid = wikidata.item_id(s)
            person = company.labels.get(qid or "")
            if not person:
                continue
            since = wikidata.statement_time(s, wikidata.START_TIME)
            entry = f"{role} (since {since})" if since else role
            roles = roles_by_person.setdefault(person, [])
            if role not in " ".join(roles):
                roles.append(entry)
    for person, roles in sorted(roles_by_person.items()):
        findings.append(
            finding(
                ResultCategory.PEOPLE,
                f"{person} — {', '.join(r.split(' (')[0] for r in roles)}",
                "Publicly attributed role(s): " + "; ".join(roles),
                f"person:wikidata:{company.qid}:{person.lower()}",
            )
        )
    return findings
