"""Seeds local/demo data: a demo account and a demo organization with two mocked recon runs
(so the Changes view has something to show). Uses only fabricated, clearly-labeled mock data
against example.com -- an IANA-reserved documentation domain -- never a real arbitrary target,
per PROGRAM_REQUIREMENTS.md 11 ("demo environment uses only mock data or intentionally
controlled sources").

Run with:  python -m app.seed
"""

from __future__ import annotations

import os
import secrets
from datetime import datetime, timedelta, timezone

from app.database import SessionLocal, init_db
from app.models import (
    AccessMode,
    Organization,
    ReconResult,
    ReconRun,
    ResultCategory,
    ResultObservation,
    Role,
    RunStatus,
    User,
)
from app.security import hash_password

DEMO_EMAIL = "demo@ethicalhawk-recon.example"


def _mock_results(run_id: str, variant: int) -> list[ReconResult]:
    base = [
        ReconResult(
            run_id=run_id,
            category=ResultCategory.DOMAINS,
            title="example.com",
            summary="Confirmed primary domain.",
            dedupe_key="primary-domain:example.com",
            source_name="Demo/Mock Data",
            source_url="https://example.com/",
            confidence=1.0,
            rationale="Domain selected during organization confirmation.",
        ),
        ReconResult(
            run_id=run_id,
            category=ResultCategory.WEB_PRESENCE,
            title="Official website: example.com",
            summary="Example Demo Corp is a fictional company used for EthicalHawk Recon's own demo data.",
            dedupe_key="official-site:example.com",
            source_name="Demo/Mock Data",
            source_url="https://example.com/",
            confidence=1.0,
        ),
        ReconResult(
            run_id=run_id,
            category=ResultCategory.DNS_NETWORK,
            title="A records for example.com",
            summary="93.184.216.34",
            dedupe_key="dns:example.com:A",
            source_name="Demo/Mock Data",
            source_url=None,
            confidence=1.0,
        ),
        ReconResult(
            run_id=run_id,
            category=ResultCategory.PEOPLE,
            title="J. Rivera -- Founder",
            summary="Publicly attributed as founder in demo source text. (Fabricated for demo purposes.)",
            dedupe_key="person:J. Rivera:Founder",
            source_name="Demo/Mock Data",
            source_url=None,
            confidence=0.5,
        ),
        ReconResult(
            run_id=run_id,
            category=ResultCategory.DOCUMENTS,
            title="Press/News: example.com/press",
            summary="Publicly accessible press page on the confirmed domain. (Demo data.)",
            dedupe_key="public-page:example.com/press",
            source_name="Demo/Mock Data",
            source_url="https://example.com/press",
            confidence=0.9,
        ),
    ]
    if variant == 2:
        base.append(
            ReconResult(
                run_id=run_id,
                category=ResultCategory.DOMAINS,
                title="status.example.com",
                summary="Observed in demo certificate-transparency-style mock data.",
                dedupe_key="subdomain:status.example.com",
                source_name="Demo/Mock Data",
                source_url=None,
                confidence=0.75,
            )
        )
        base.extend(_mock_background_and_people(run_id))
    return base


def _mock(run_id, category, title, summary, key, source, confidence, rationale=None, url=None) -> ReconResult:
    return ReconResult(
        run_id=run_id,
        category=category,
        title=title,
        summary=summary,
        dedupe_key=key,
        source_name=source,
        source_url=url,
        confidence=confidence,
        rationale=rationale,
    )


def _mock_background_and_people(run_id: str) -> list[ReconResult]:
    """Fabricated results in the shape of the Wikidata, SEC EDGAR, leadership-page and social
    sources, so demos and README screenshots show every category without researching a real
    organization. The company, people, and identifiers below do not exist."""
    web, people, docs = ResultCategory.WEB_PRESENCE, ResultCategory.PEOPLE, ResultCategory.DOCUMENTS
    results = [
        _mock(
            run_id, web, "Company background: Example Demo Corp",
            "Founded: 2012-04\nHeadquarters: Springfield\nCountry: United States\n"
            "Industry: Software, Information security\nEmployees: 1,250 (as of 2025-12-31)\n"
            "Revenue: $310.0 million (as of 2025)\nStock listing: Example Exchange: EXDC",
            "company-profile:wikidata:demo", "Wikidata (mock)", 0.85,
            "Fabricated demo data in the shape of structured Wikidata statements.",
        ),
        _mock(
            run_id, web, "SEC registrant profile: Example Demo Corp, Inc.",
            "Registered name: Example Demo Corp, Inc.\nIndustry (SIC 7372): Services-Prepackaged Software\n"
            "State of incorporation: DE\nListed as: Example Exchange: EXDC\nFiscal year ends: 12/31 (MM/DD)",
            "company-profile:sec:demo", "SEC EDGAR (mock)", 1.0,
            "Fabricated demo data in the shape of an SEC EDGAR registrant profile.",
        ),
        _mock(
            run_id, web, "Official LinkedIn account: example-demo-corp",
            "LinkedIn account linked from the organization's own homepage. (Demo data.)",
            "social:linkedin:example-demo-corp", "Demo/Mock Data", 0.9,
        ),
        _mock(
            run_id, web, "Official GitHub account: example-demo-corp",
            "GitHub account linked from the organization's own homepage. (Demo data.)",
            "social:github:example-demo-corp", "Demo/Mock Data", 0.9,
        ),
        _mock(
            run_id, docs, "Annual report (10-K) — filed 2026-02-20",
            "SEC filing (fabricated demo accession number).",
            "sec-filing:demo-10k", "SEC EDGAR (mock)", 1.0,
            "Fabricated demo data in the shape of an SEC EDGAR filing link.",
        ),
        _mock(
            run_id, docs, "Published security contact for example.com", "security@example.com",
            "security-contact:example.com:security@example.com", "Demo/Mock Data", 1.0,
            "Organization-published Contact field in /.well-known/security.txt. (Demo data.)",
        ),
    ]
    for name, role, source, confidence in (
        ("Jordan Reyes", "Chief Executive Officer", "SEC EDGAR (mock)", 0.95),
        ("Priya Shah", "Chief Financial Officer", "SEC EDGAR (mock)", 0.95),
        ("Alex Morgan", "Chief Information Security Officer", "Official Leadership Pages (mock)", 0.85),
        ("Sam Lee", "Vice President, Engineering", "Official Leadership Pages (mock)", 0.7),
        ("Taylor Brooks", "Director", "SEC EDGAR (mock)", 0.95),
    ):
        results.append(
            _mock(
                run_id, people, f"{name} — {role}",
                f"Professional role: {role}. Fabricated person for demo purposes.",
                f"person:demo:{name.lower()}", source, confidence,
                "Fabricated demo data; name and title only, never personal contact details.",
            )
        )
    return results


def main() -> None:
    init_db()
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == DEMO_EMAIL).one_or_none()
        if user is None:
            password = os.environ.get("DEMO_PASSWORD") or secrets.token_urlsafe(12)
            user = User(email=DEMO_EMAIL, password_hash=hash_password(password), role=Role.ADMINISTRATOR)
            db.add(user)
            db.commit()
            print(f"Created demo user: {DEMO_EMAIL} / {password}")
        else:
            print(f"Demo user already exists: {DEMO_EMAIL}")

        org = db.query(Organization).filter(Organization.primary_domain == "example.com").one_or_none()
        if org is None:
            org = Organization(
                name="Example Demo Corp",
                primary_domain="example.com",
                description="Fictional demo organization used for EthicalHawk Recon's own screenshots and demos.",
                description_source="Demo/Mock Data",
            )
            db.add(org)
            db.commit()

        existing_runs = db.query(ReconRun).filter(ReconRun.organization_id == org.id).count()
        if existing_runs == 0:
            older = ReconRun(
                organization_id=org.id,
                user_id=user.id,
                mode=AccessMode.AUTHORIZED_PASSIVE,
                status=RunStatus.COMPLETED,
                started_at=datetime.now(timezone.utc) - timedelta(days=7),
                completed_at=datetime.now(timezone.utc) - timedelta(days=7),
            )
            older.created_at = datetime.now(timezone.utc) - timedelta(days=7)
            db.add(older)
            db.commit()
            for r in _mock_results(older.id, variant=1):
                db.add(r)
            db.commit()
            for r in older.results:
                db.add(
                    ResultObservation(
                        organization_id=org.id,
                        category=r.category,
                        dedupe_key=r.dedupe_key,
                        first_observed_at=older.created_at,
                        last_observed_at=older.created_at,
                        last_seen_run_id=older.id,
                    )
                )
            db.commit()

            newer = ReconRun(
                organization_id=org.id,
                user_id=user.id,
                mode=AccessMode.AUTHORIZED_PASSIVE,
                status=RunStatus.COMPLETED,
                started_at=datetime.now(timezone.utc),
                completed_at=datetime.now(timezone.utc),
            )
            db.add(newer)
            db.commit()
            for r in _mock_results(newer.id, variant=2):
                db.add(r)
            db.commit()
            print(f"Seeded demo organization '{org.name}' with 2 mock runs.")
        else:
            print(f"Demo organization '{org.name}' already has runs; skipping.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
