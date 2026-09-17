from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from app.audit import record_event
from app.config import get_settings
from app.database import SessionLocal
from app.models import ReconResult, ReconRun, ResultObservation, RunStatus
from app.services.recon.base import AdapterError, ReconAdapter
from app.services.recon.crtsh_adapter import CrtShAdapter
from app.services.recon.dns_adapter import DnsAdapter
from app.services.recon.documents_adapter import PublicDocumentsAdapter
from app.services.recon.domain_context_adapter import DomainContextAdapter
from app.services.recon.leadership_adapter import LeadershipAdapter
from app.services.recon.people_adapter import PeopleAdapter
from app.services.recon.rdap_adapter import RdapAdapter
from app.services.recon.tech_signals_adapter import TechSignalsAdapter
from app.services.recon.web_adapter import WebPresenceAdapter
from app.services.recon.wiki_adapter import WikipediaOverviewAdapter

logger = logging.getLogger("ethicalhawk.pipeline")
settings = get_settings()

ADAPTERS: list[ReconAdapter] = [
    DomainContextAdapter(),
    WebPresenceAdapter(),
    WikipediaOverviewAdapter(),
    TechSignalsAdapter(),
    DnsAdapter(),
    RdapAdapter(),
    CrtShAdapter(),
    PeopleAdapter(),
    LeadershipAdapter(),
    PublicDocumentsAdapter(),
]


async def execute_run(run_id: str) -> None:
    """Runs the full passive-recon pipeline for a confirmed run. Designed to be scheduled onto
    the bounded in-process worker (app.background) -- never called directly from a request."""
    db = SessionLocal()
    try:
        run = db.get(ReconRun, run_id)
        if run is None:
            return

        if settings.recon_kill_switch:
            run.status = RunStatus.FAILED
            run.error_message = "Recon is temporarily disabled by an administrator kill switch."
            db.commit()
            record_event(
                db,
                event_type="recon.kill_switch_blocked",
                description=f"Run {run_id} blocked by kill switch.",
                target_type="recon_run",
                target_id=run_id,
            )
            return

        organization = run.organization
        domain = organization.primary_domain
        run.status = RunStatus.RUNNING
        run.started_at = datetime.now(timezone.utc)
        db.commit()

        applicable = [a for a in ADAPTERS if run.mode in a.modes]
        semaphore = asyncio.Semaphore(settings.max_concurrent_adapters_per_job)

        async def run_one(adapter: ReconAdapter):
            async with semaphore:
                try:
                    findings = await asyncio.wait_for(
                        adapter.run(
                            domain=domain or "",
                            organization_name=organization.name,
                            timeout=settings.adapter_timeout_seconds,
                        ),
                        # Each adapter declares how many sequential request-timeout-sized
                        # stages it can chain (robots.txt, homepage discovery, candidate pages,
                        # a bounded second hop, ...) so a slow/hanging simple adapter is still
                        # cut off quickly instead of every adapter getting the same generous
                        # budget regardless of how much work it actually does.
                        timeout=settings.adapter_timeout_seconds * adapter.timeout_budget_multiplier + 4,
                    )
                    return adapter.name, findings, None
                except (AdapterError, TimeoutError, asyncio.TimeoutError) as exc:
                    return adapter.name, [], str(exc)
                except Exception as exc:  # noqa: BLE001 - a single source must never take the run down
                    logger.exception("Adapter %s failed unexpectedly", adapter.name)
                    return adapter.name, [], str(exc)

        if domain and applicable:
            results = await asyncio.gather(*(run_one(a) for a in applicable))
        else:
            results = []

        failed_sources: list[str] = []
        seen_keys: set[str] = set()
        for source_name, findings, error in results:
            if error:
                failed_sources.append(source_name)
                record_event(
                    db,
                    event_type="recon.source_failed",
                    description=f"{source_name} could not be completed for run {run_id}: {error}",
                    user_id=run.user_id,
                    target_type="recon_run",
                    target_id=run_id,
                )
                continue

            for finding in findings:
                if finding.dedupe_key in seen_keys:
                    continue
                seen_keys.add(finding.dedupe_key)

                db.add(
                    ReconResult(
                        run_id=run.id,
                        category=finding.category,
                        title=finding.title,
                        summary=finding.summary,
                        dedupe_key=finding.dedupe_key,
                        source_name=finding.source_name,
                        source_url=finding.source_url,
                        confidence=finding.confidence,
                        rationale=finding.rationale,
                    )
                )
                _upsert_observation(db, organization.id, finding.category, finding.dedupe_key, run.id)

        run.status = RunStatus.COMPLETED
        run.completed_at = datetime.now(timezone.utc)
        if failed_sources:
            run.error_message = "Incomplete source coverage: " + ", ".join(sorted(set(failed_sources)))
        db.commit()

        record_event(
            db,
            event_type="recon.run_completed",
            description=f"Run {run_id} completed for {organization.name} ({run.mode.value}).",
            user_id=run.user_id,
            target_type="recon_run",
            target_id=run_id,
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("Run %s failed", run_id)
        db.rollback()
        run = db.get(ReconRun, run_id)
        if run is not None:
            run.status = RunStatus.FAILED
            run.error_message = "An internal error occurred while running this recon job."
            run.completed_at = datetime.now(timezone.utc)
            db.commit()
            record_event(
                db,
                event_type="recon.run_failed",
                description=f"Run {run_id} failed: {exc}",
                target_type="recon_run",
                target_id=run_id,
            )
    finally:
        db.close()


def _upsert_observation(db, organization_id: str, category, dedupe_key: str, run_id: str) -> None:
    existing = (
        db.query(ResultObservation)
        .filter(
            ResultObservation.organization_id == organization_id,
            ResultObservation.category == category,
            ResultObservation.dedupe_key == dedupe_key,
        )
        .one_or_none()
    )
    now = datetime.now(timezone.utc)
    if existing:
        existing.last_observed_at = now
        existing.last_seen_run_id = run_id
    else:
        db.add(
            ResultObservation(
                organization_id=organization_id,
                category=category,
                dedupe_key=dedupe_key,
                first_observed_at=now,
                last_observed_at=now,
                last_seen_run_id=run_id,
            )
        )
