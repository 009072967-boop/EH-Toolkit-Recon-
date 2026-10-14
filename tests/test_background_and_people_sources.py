from app.models import AccessMode, Organization, ReconResult, ReconRun, ResultCategory, RunStatus, User
from app.security import hash_password
from app.services import pipeline
from app.services.recon import wikidata
from app.services.recon.base import AdapterFinding, ReconAdapter
from app.services.recon.leadership_adapter import _is_people_page, _published_executives, _structured_data_people
from app.services.recon.sec_edgar_adapter import SecEdgarAdapter, _display_name, parse_insider_filing
from app.services.recon.web_adapter import social_accounts
from app.services.recon.wikidata_adapter import company_findings


def _item(qid, **qualifiers):
    return {
        "rank": qualifiers.pop("rank", "normal"),
        "mainsnak": {"datavalue": {"value": {"id": qid}}},
        "qualifiers": {
            prop: [{"datavalue": {"value": {"time": time, "precision": 10}}}] for prop, time in qualifiers.items()
        },
    }


def _quantity(amount, as_of):
    return {"rank": "normal", "mainsnak": {"datavalue": {"value": {"amount": amount}}},
            "qualifiers": {"P585": [{"datavalue": {"value": {"time": as_of, "precision": 11}}}]}}


def _string(value):
    return {"rank": "normal", "mainsnak": {"datavalue": {"value": value}}}


def _company(website="https://www.example-widgets.com/"):
    return wikidata.WikidataCompany(
        qid="Q1",
        label="Example Widgets",
        claims={
            "P571": [{"rank": "normal", "mainsnak": {"datavalue": {"value": {"time": "+2009-11-00T00:00:00Z",
                                                                              "precision": 10}}}}],
            "P159": [_item("Q10")],
            "P452": [_item("Q11")],
            "P1128": [_quantity("+1000", "+2020-12-31T00:00:00Z"), _quantity("+2440", "+2021-12-31T00:00:00Z")],
            "P856": [_string(website)],
            "P355": [_item("Q12"), _item("Q13", P582="+2015-01-00T00:00:00Z")],
            "P2002": [_string("ExampleWidgets")],
            "P112": [_item("Q20")],
            "P169": [_item("Q20", P580="+2009-07-00T00:00:00Z"), _item("Q21", P582="+2008-01-00T00:00:00Z")],
            "P3320": [_item("Q22")],
        },
        labels={"Q10": "San Francisco", "Q11": "Software", "Q12": "Widget Labs", "Q13": "Sold Co",
                "Q20": "Jordan Reyes", "Q21": "Former Boss", "Q22": "Alex Morgan"},
    )


def test_wikidata_findings_cover_background_social_and_current_people():
    findings = company_findings(_company(), "example-widgets.com")
    by_key = {f.dedupe_key: f for f in findings}

    background = by_key["company-profile:wikidata:Q1"]
    assert "Founded: 2009-11" in background.summary
    assert "Headquarters: San Francisco" in background.summary
    assert "Employees: 2,440 (as of 2021-12-31)" in background.summary  # most recent, not first listed
    assert background.confidence == 0.85

    assert by_key["subsidiaries:wikidata:Q1"].summary == "Widget Labs"  # ended subsidiary dropped
    assert by_key["social:x (twitter):examplewidgets"].source_url == "https://x.com/ExampleWidgets"

    people = {f.title for f in findings if f.category == ResultCategory.PEOPLE}
    assert "Jordan Reyes — Founder, Chief Executive Officer" in people
    assert "Alex Morgan — Board member" in people
    assert not any("Former Boss" in title for title in people)  # role with an end date is not current


def test_wikidata_findings_flag_a_different_official_website():
    findings = company_findings(_company(website="https://unrelated.example"), "example-widgets.com")
    assert findings and all(f.confidence == 0.4 for f in findings)
    assert "does not match example-widgets.com" in findings[0].rationale


def test_wikidata_time_formatting_respects_precision():
    assert wikidata.format_time("+2009-11-00T00:00:00Z|10") == "2009-11"
    assert wikidata.format_time("+2009-00-00T00:00:00Z|9") == "2009"
    assert wikidata.format_time("+2021-12-31T00:00:00Z|11") == "2021-12-31"


def test_sec_insider_filing_parsing():
    officer = (
        "<reportingOwner><rptOwnerName>SEIFERT THOMAS J</rptOwnerName><isDirector>0</isDirector>"
        "<isOfficer>1</isOfficer><officerTitle>Chief Financial Officer</officerTitle></reportingOwner>"
    )
    co_chair = (
        "<rptOwnerName>Zatlyn Michelle</rptOwnerName><isDirector>1</isDirector><isOfficer>1</isOfficer>"
        "<officerTitle>President &amp; Board Co-Chair</officerTitle>"
    )
    fund = "<rptOwnerName>Big Fund LP</rptOwnerName><isDirector>0</isDirector><isOfficer>0</isOfficer>"

    assert parse_insider_filing(officer) == ("Thomas J Seifert", "Chief Financial Officer")
    assert parse_insider_filing(co_chair) == ("Michelle Zatlyn", "President & Board Co-Chair")
    assert parse_insider_filing(fund) is None
    assert _display_name("SMITH JOHN JR") == "John Smith Jr"


def test_sec_key_filings_and_insider_urls():
    data = {"filings": {"recent": {
        "form": ["4", "8-K", "10-K", "8-K", "10-K"],
        "accessionNumber": ["0001-26-000005", "0001-26-000004", "0001-26-000003", "0001-26-000002", "0001-25-1"],
        "filingDate": ["2026-05-01", "2026-04-01", "2026-02-26", "2026-01-15", "2025-02-20"],
        "primaryDocument": ["xslF345X05/form4.xml", "a.htm", "annual.htm", "b.htm", "old.htm"],
    }}}
    filings = SecEdgarAdapter._key_filings(data, 42)
    assert [f.title.split(" — ")[0] for f in filings] == ["Current report (8-K)", "Annual report (10-K)",
                                                         "Current report (8-K)"]
    assert filings[1].source_url == "https://www.sec.gov/Archives/edgar/data/42/000126000003/annual.htm"
    assert SecEdgarAdapter._insider_filing_urls(data, 42) == [
        "https://www.sec.gov/Archives/edgar/data/42/000126000005/form4.xml"
    ]


def test_leadership_extracts_broader_titles_and_rejects_ui_text():
    pairs = _published_executives(
        "<h2>Jordan Reyes — Chief Executive Officer</h2>"
        "<p>Vice President, Engineering: Sam Lee</p>"
        "<p>Priya Shah, General Counsel</p>"
        "<p>Learn More — Chief Revenue Officer</p>"
    )
    assert ("Jordan Reyes", "Chief Executive Officer") in pairs
    assert ("Sam Lee", "Vice President, Engineering") in pairs
    assert ("Priya Shah", "General Counsel") in pairs
    assert not any(name == "Learn More" for name, _ in pairs)


def test_leadership_card_layout_is_not_shifted_by_one():
    cards = "".join(
        f"<div><h3>{name}</h3><span>{title}</span></div>"
        for name, title in [("Kyle Hanslovan", "CEO & Cofounder"), ("Matthew Puljiz", "Chief Financial Officer"),
                            ("Liz Kokoska", "Chief Marketing Officer")]
    )
    pairs = _published_executives(cards, "Huntress")
    assert ("Kyle Hanslovan", "CEO & Cofounder") in pairs
    assert ("Matthew Puljiz", "Chief Financial Officer") in pairs
    assert not any(name == "Matthew Puljiz" and role == "CEO & Cofounder" for name, role in pairs)


def test_leadership_structured_data_skips_testimonial_authors():
    markup = """<script type="application/ld+json">{"@type": "Organization", "employee": [
        {"@type": "Person", "name": "Jordan Reyes", "jobTitle": "Chief Executive Officer", "email": "x@y.z"}],
        "review": {"@type": "Review", "author": {"@type": "Person", "name": "Happy Customer", "jobTitle": "CEO"}}
    }</script>"""
    assert _structured_data_people(markup) == [("Jordan Reyes", "Chief Executive Officer")]


def test_people_pages_are_limited_to_leadership_style_urls():
    assert _is_people_page("https://example.com/about/leadership/")
    assert _is_people_page("https://example.com/our-team")
    assert not _is_people_page("https://example.com/why-us/it-security-teams/mid-sized")
    assert not _is_people_page("https://example.com/platform/managed-edr")


def test_social_accounts_keep_official_profiles_only():
    markup = """
      <a href="https://www.linkedin.com/company/example-widgets/">LinkedIn</a>
      <a href="https://www.linkedin.com/in/some-employee">personal profile</a>
      <a href="https://twitter.com/intent/tweet?text=hi">share</a>
      <a href="https://x.com/ExampleWidgets">X</a>
      <script type="application/ld+json">{"sameAs": ["https://github.com/example-widgets"]}</script>
    """
    found = {(platform, handle) for platform, handle, _url in social_accounts(markup)}
    assert found == {("LinkedIn", "example-widgets"), ("X (Twitter)", "ExampleWidgets"), ("GitHub", "example-widgets")}


class _MixedAdapter(ReconAdapter):
    name = "Mixed Source"
    modes = frozenset({AccessMode.PUBLIC_PROFILE, AccessMode.AUTHORIZED_PASSIVE})

    async def run(self, *, domain, organization_name, timeout):
        def make(category, key):
            return AdapterFinding(category=category, title=key, summary=None, dedupe_key=key,
                                  source_name=self.name, source_url=None, confidence=1.0)
        return [make(ResultCategory.WEB_PRESENCE, "profile"), make(ResultCategory.PEOPLE, "person")]


async def test_public_profile_runs_never_store_people(db_session, monkeypatch):
    monkeypatch.setattr(pipeline, "ADAPTERS", [_MixedAdapter()])
    user = User(email="mode-filter@example.com", password_hash=hash_password("irrelevant-password-3"))
    org = Organization(name="Mode Filter Org", primary_domain="mode-filter.example")
    db_session.add_all([user, org])
    db_session.commit()
    run = ReconRun(organization_id=org.id, user_id=user.id, mode=AccessMode.PUBLIC_PROFILE, status=RunStatus.PENDING)
    db_session.add(run)
    db_session.commit()
    run_id = run.id

    await pipeline.execute_run(run_id)

    db_session.expire_all()
    stored = db_session.query(ReconResult).filter(ReconResult.run_id == run_id).all()
    assert [r.category for r in stored] == [ResultCategory.WEB_PRESENCE]


def test_blocked_site_is_reported_not_silently_empty():
    import pytest

    from app.services.recon.base import AdapterError, raise_if_blocked

    with pytest.raises(AdapterError, match="HTTP 403"):
        raise_if_blocked("example.com", [403, 403, 404])
    raise_if_blocked("example.com", [403, 200])  # some pages worked -- not a block
    raise_if_blocked("example.com", [404, 404])  # pages genuinely missing -- not a block
