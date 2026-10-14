import re
from urllib.parse import quote, urlparse

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.audit import record_event
from app.background import enqueue_run
from app.database import get_db
from app.deps import (
    RateLimited,
    check_run_rate_limit,
    get_or_create_csrf_token,
    require_user,
    secrets_compare,
)
from app.models import (
    AccessMode,
    AuthorizationAcknowledgement,
    Organization,
    OrganizationMatch,
    ReconRun,
    RunStatus,
    User,
)
from app.schemas import SearchQuery
from app.services.matching import find_candidates

router = APIRouter(tags=["search"])
templates = Jinja2Templates(directory="templates")

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


def _redirect_with_flash(url: str, message: str, kind: str = "error") -> RedirectResponse:
    return RedirectResponse(f"{url}?flash={quote(message)}&flash_type={kind}", status_code=303)


def _normalize_domain(value: str) -> str | None:
    """Accept a public hostname or URL, but never an IP address, path, or malformed target."""
    candidate = value.strip().lower()
    if not candidate:
        return None
    if "://" in candidate:
        parsed = urlparse(candidate)
        candidate = parsed.hostname or ""
    else:
        candidate = candidate.split("/", 1)[0].split(":", 1)[0]
    candidate = candidate.rstrip(".")
    # Users often paste a website URL such as https://www.example.org/. Store the
    # registrable-looking hostname for CT, RDAP, and DNS context; those public
    # sources describe example.org rather than its conventional www host.
    if candidate.startswith("www."):
        candidate = candidate[4:]
    return candidate if _DOMAIN_RE.fullmatch(candidate) else None


@router.get("/")
def landing(
    request: Request,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    recent_runs = (
        db.query(ReconRun)
        .filter(ReconRun.user_id == user.id)
        .order_by(ReconRun.created_at.desc())
        .limit(8)
        .all()
    )
    csrf = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "landing.html",
        {
            "user": user,
            "recent_runs": recent_runs,
            "csrf_token": csrf,
            "flash": request.query_params.get("flash"),
            "flash_type": request.query_params.get("flash_type", "error"),
        },
    )
    response.set_cookie("csrf_token", csrf, samesite="lax", secure=False, httponly=False)
    return response


@router.post("/search")
async def submit_search(
    request: Request,
    query: str = Form(...),
    csrf_token: str = Form(...),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    if not secrets_compare(request.cookies.get("csrf_token", ""), csrf_token):
        return _redirect_with_flash("/", "Your form session expired. Please try again.")

    try:
        cleaned = SearchQuery(query=query)
    except ValidationError as exc:
        return _redirect_with_flash("/", exc.errors()[0]["msg"])

    candidates = await find_candidates(cleaned.query)

    for c in candidates:
        db.add(
            OrganizationMatch(
                query=cleaned.query,
                matched_name=c.name,
                matched_domain=c.domain,
                confidence=c.confidence,
                rationale=c.rationale,
                source=c.source,
                searched_by_user_id=user.id,
            )
        )
    db.commit()
    record_event(
        db,
        event_type="search.performed",
        description=f'Searched for "{cleaned.query}" ({len(candidates)} candidates).',
        user_id=user.id,
    )

    csrf = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "search_results.html",
        {"user": user, "query": cleaned.query, "candidates": candidates, "csrf_token": csrf},
    )
    response.set_cookie("csrf_token", csrf, samesite="lax", secure=False, httponly=False)
    return response


@router.post("/organizations/confirm")
def confirm_organization(
    request: Request,
    name: str = Form(...),
    domain: str = Form(""),
    csrf_token: str = Form(...),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    if not secrets_compare(request.cookies.get("csrf_token", ""), csrf_token):
        return _redirect_with_flash("/", "Your form session expired. Please try again.")

    name = name.strip()[:255]
    domain = _normalize_domain(domain[:255])
    if not name:
        return _redirect_with_flash("/", "Choose a valid organization to confirm.")
    if domain is None:
        return _redirect_with_flash(
            "/", "Enter the organization's public domain before starting a research run."
        )

    org = (
        db.query(Organization)
        .filter(Organization.name == name, Organization.primary_domain == domain)
        .one_or_none()
    )
    if org is None:
        org = Organization(name=name, primary_domain=domain)
        db.add(org)
        db.commit()

    (
        db.query(OrganizationMatch)
        .filter(
            OrganizationMatch.matched_name == name,
            OrganizationMatch.searched_by_user_id == user.id,
            OrganizationMatch.confirmed.is_(False),
        )
        .update({OrganizationMatch.confirmed: True})
    )
    db.commit()

    record_event(
        db,
        event_type="organization.confirmed",
        description=f"Confirmed target organization: {name} ({domain or 'no domain'}).",
        user_id=user.id,
        target_type="organization",
        target_id=org.id,
    )

    csrf = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request, "run_new.html", {"user": user, "organization": org, "csrf_token": csrf}
    )
    response.set_cookie("csrf_token", csrf, samesite="lax", secure=False, httponly=False)
    return response


@router.post("/runs")
async def create_run(
    request: Request,
    organization_id: str = Form(...),
    mode: str = Form(...),
    purpose: str = Form(""),
    csrf_token: str = Form(...),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    if not secrets_compare(request.cookies.get("csrf_token", ""), csrf_token):
        return _redirect_with_flash("/", "Your form session expired. Please try again.")

    org = db.get(Organization, organization_id)
    if org is None:
        return _redirect_with_flash("/", "That organization could not be found.")

    try:
        access_mode = AccessMode(mode)
    except ValueError:
        return _redirect_with_flash("/", "Choose a valid access mode.")

    try:
        check_run_rate_limit(db, user)
    except RateLimited as exc:
        return _redirect_with_flash("/", exc.message)

    acknowledgement_id = None
    if access_mode == AccessMode.AUTHORIZED_PASSIVE:
        purpose = purpose.strip()
        if len(purpose) < 10:
            return _redirect_with_flash(
                "/", "Describe your authorization/purpose (at least 10 characters) to use Authorized Passive Recon."
            )
        ack = AuthorizationAcknowledgement(user_id=user.id, organization_id=org.id, purpose=purpose[:2000])
        db.add(ack)
        db.commit()
        acknowledgement_id = ack.id
        record_event(
            db,
            event_type="authorization.acknowledged",
            description=f"Authorization acknowledged for {org.name}: {purpose[:200]}",
            user_id=user.id,
            target_type="organization",
            target_id=org.id,
        )

    run = ReconRun(
        organization_id=org.id,
        user_id=user.id,
        mode=access_mode,
        status=RunStatus.PENDING,
        acknowledgement_id=acknowledgement_id,
    )
    db.add(run)
    db.commit()
    record_event(
        db,
        event_type="run.created",
        description=f"Recon run created for {org.name} in {access_mode.value} mode.",
        user_id=user.id,
        target_type="recon_run",
        target_id=run.id,
    )

    await enqueue_run(run.id)
    return RedirectResponse(f"/runs/{run.id}", status_code=303)
