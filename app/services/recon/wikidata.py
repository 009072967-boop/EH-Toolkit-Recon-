"""Shared Wikidata lookup for the organization-background, social-account, people and SEC
adapters. Wikidata is the structured, community-curated knowledge base behind Wikipedia
infoboxes, served through official keyless APIs built for programmatic access -- it's where
founding date, headquarters, industry, executives and identifiers like an SEC CIK live in
machine-readable form, instead of being regex-guessed out of encyclopedia prose."""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

from app.services.recon.base import AdapterError

_UA = {"User-Agent": "EthicalHawkRecon/0.2 (+passive-research-tool; authorized-use-only)"}
_WIKIPEDIA_API = "https://en.wikipedia.org/w/api.php"
_WIKIDATA_API = "https://www.wikidata.org/w/api.php"

# Property IDs (https://www.wikidata.org/wiki/Property:Pxxx)
INCEPTION = "P571"
HEADQUARTERS = "P159"
COUNTRY = "P17"
INDUSTRY = "P452"
LEGAL_FORM = "P1454"
EMPLOYEES = "P1128"
REVENUE = "P2139"
PARENT_ORG = "P749"
OWNED_BY = "P127"
SUBSIDIARY = "P355"
STOCK_EXCHANGE = "P414"
TICKER = "P249"
OFFICIAL_WEBSITE = "P856"
SEC_CIK = "P5531"
LEI = "P1278"
POINT_IN_TIME = "P585"
START_TIME = "P580"
END_TIME = "P582"

PEOPLE_ROLES = {
    "P112": "Founder",
    "P169": "Chief Executive Officer",
    "P488": "Chairperson",
    "P1037": "Director/Manager",
    "P3320": "Board member",
}

SOCIAL_ACCOUNTS = {
    "P2002": ("X (Twitter)", "https://x.com/{}"),
    "P4264": ("LinkedIn", "https://www.linkedin.com/company/{}"),
    "P2013": ("Facebook", "https://www.facebook.com/{}"),
    "P2003": ("Instagram", "https://www.instagram.com/{}"),
    "P2397": ("YouTube", "https://www.youtube.com/channel/{}"),
    "P2037": ("GitHub", "https://github.com/{}"),
}

_ITEM_PROPERTIES = (
    [HEADQUARTERS, COUNTRY, INDUSTRY, LEGAL_FORM, PARENT_ORG, OWNED_BY, SUBSIDIARY, STOCK_EXCHANGE]
    + list(PEOPLE_ROLES)
)
_USD = "http://www.wikidata.org/entity/Q4917"


@dataclass
class WikidataCompany:
    qid: str
    label: str
    claims: dict
    labels: dict[str, str] = field(default_factory=dict)

    @property
    def url(self) -> str:
        return f"https://www.wikidata.org/wiki/{self.qid}"

    def statements(self, prop: str, *, current_only: bool = False) -> list[dict]:
        """Non-deprecated statements, preferred-rank first. `current_only` drops statements
        with an end-time qualifier (a former CEO, a sold subsidiary, a delisting)."""
        result = [s for s in self.claims.get(prop, []) if s.get("rank") != "deprecated"]
        if current_only:
            result = [s for s in result if END_TIME not in s.get("qualifiers", {})]
        return sorted(result, key=lambda s: s.get("rank") != "preferred")

    def item_labels(self, prop: str, *, current_only: bool = False) -> list[str]:
        out: list[str] = []
        for s in self.statements(prop, current_only=current_only):
            qid = item_id(s)
            if qid and self.labels.get(qid) and self.labels[qid] not in out:
                out.append(self.labels[qid])
        return out

    def strings(self, prop: str) -> list[str]:
        out: list[str] = []
        for s in self.statements(prop):
            value = s.get("mainsnak", {}).get("datavalue", {}).get("value")
            if isinstance(value, str) and value not in out:
                out.append(value)
        return out

    def latest_quantity(self, prop: str) -> tuple[str, str | None] | None:
        """(formatted amount, as-of date) for the preferred value, else the most recent one."""
        statements = self.statements(prop)
        if not statements:
            return None
        preferred = [s for s in statements if s.get("rank") == "preferred"]
        pool = preferred or statements
        best = max(pool, key=lambda s: _qualifier_time(s, POINT_IN_TIME) or "")
        value = best.get("mainsnak", {}).get("datavalue", {}).get("value")
        if not isinstance(value, dict) or "amount" not in value:
            return None
        return _format_amount(value), format_time(_qualifier_time(best, POINT_IN_TIME))

    def website_hosts(self) -> set[str]:
        return {_bare_host(url) for url in self.strings(OFFICIAL_WEBSITE) if _bare_host(url)}

    def matches_domain(self, domain: str) -> bool | None:
        """True/False if Wikidata lists an official website; None if it lists none to compare."""
        hosts = self.website_hosts()
        if not hosts:
            return None
        bare = _bare_host(f"https://{domain}")
        return any(h == bare or h.endswith(f".{bare}") or bare.endswith(f".{h}") for h in hosts)


def item_id(statement: dict) -> str | None:
    value = statement.get("mainsnak", {}).get("datavalue", {}).get("value")
    return value.get("id") if isinstance(value, dict) else None


def _qualifier_time(statement: dict, prop: str) -> str | None:
    for q in statement.get("qualifiers", {}).get(prop, []):
        value = q.get("datavalue", {}).get("value")
        if isinstance(value, dict) and value.get("time"):
            return f"{value['time']}|{value.get('precision', 11)}"
    return None


def format_time(raw: str | None) -> str | None:
    """Wikidata time '+2009-11-00T00:00:00Z' (+ '|precision') -> '2009-11'. Precision 9 = year,
    10 = month, 11 = day; zero-filled parts beyond the stated precision are dropped."""
    if not raw:
        return None
    time, _, precision = raw.partition("|")
    date = time.lstrip("+").split("T", 1)[0]
    precision_int = int(precision) if precision.isdigit() else 11
    if precision_int <= 9:
        return date[:4]
    if precision_int == 10:
        return date[:7]
    return date


def statement_time(statement: dict, prop: str) -> str | None:
    return format_time(_qualifier_time(statement, prop))


def _format_amount(value: dict) -> str:
    amount = float(value["amount"])
    text = f"{amount:,.0f}"
    if value.get("unit") == _USD:
        if amount >= 1e9:
            return f"${amount / 1e9:,.2f} billion"
        if amount >= 1e6:
            return f"${amount / 1e6:,.1f} million"
        return f"${text}"
    return text


def _bare_host(url: str) -> str:
    host = (urlparse(url).hostname or "").lower()
    return host[4:] if host.startswith("www.") else host


async def fetch_company(organization_name: str, *, timeout: float) -> WikidataCompany | None:
    """Resolves an organization name to its Wikidata item via the matching English Wikipedia
    article (the same title search confirmation used), then loads its statements and the
    labels of every item they reference. Returns None when there is no unambiguous article."""
    title = organization_name.strip()
    if not title:
        return None
    try:
        async with httpx.AsyncClient(timeout=timeout, headers=_UA, follow_redirects=True) as client:
            pages = await client.get(
                _WIKIPEDIA_API,
                params={
                    "action": "query",
                    "prop": "pageprops",
                    "ppprop": "wikibase_item|disambiguation",
                    "titles": title,
                    "redirects": "1",
                    "format": "json",
                },
            )
            pages.raise_for_status()
            page = next(iter(pages.json().get("query", {}).get("pages", {}).values()), {})
            props = page.get("pageprops", {})
            qid = props.get("wikibase_item")
            if not qid or "disambiguation" in props:
                return None

            entity_response = await client.get(
                _WIKIDATA_API,
                params={"action": "wbgetentities", "ids": qid, "props": "labels|claims", "languages": "en",
                        "format": "json"},
            )
            entity_response.raise_for_status()
            entity = entity_response.json().get("entities", {}).get(qid, {})
            company = WikidataCompany(
                qid=qid,
                label=entity.get("labels", {}).get("en", {}).get("value", title),
                claims=entity.get("claims", {}),
            )

            referenced: list[str] = []
            for prop in _ITEM_PROPERTIES:
                for s in company.statements(prop):
                    item = item_id(s)
                    if item and item not in referenced:
                        referenced.append(item)
            for start in range(0, min(len(referenced), 150), 50):
                batch = referenced[start : start + 50]
                labels_response = await client.get(
                    _WIKIDATA_API,
                    params={"action": "wbgetentities", "ids": "|".join(batch), "props": "labels",
                            "languages": "en", "format": "json"},
                )
                labels_response.raise_for_status()
                for label_qid, item in labels_response.json().get("entities", {}).items():
                    label = item.get("labels", {}).get("en", {}).get("value")
                    if label:
                        company.labels[label_qid] = label
            return company
    except (httpx.HTTPError, ValueError) as exc:
        raise AdapterError(f"Wikidata request failed: {exc}") from exc
