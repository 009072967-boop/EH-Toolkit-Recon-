from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.audit import record_event
from app.database import get_db
from app.deps import get_or_create_csrf_token, require_user, secrets_compare
from app.models import AnalystNote, ReconResult, ReconRun, ResultCategory, Role, RunStatus, User
from app.schemas import HideResultForm, NoteForm
from app.services.diff import diff_runs

router = APIRouter(tags=["runs"])
templates = Jinja2Templates(directory="templates")

# Dedupe-key prefixes of findings that describe the organization itself (encyclopedia summary,
# structured company profile, SEC registrant profile) -- surfaced as the Overview's summary.
BACKGROUND_KEY_PREFIXES = ("wiki-summary:", "company-profile:")

CATEGORY_LABELS = {
    ResultCategory.DOMAINS: "Domains & Subdomains",
    ResultCategory.WEB_PRESENCE: "Web Presence",
    ResultCategory.PEOPLE: "People & Organization",
    ResultCategory.DOCUMENTS: "Public Documents",
    ResultCategory.DNS_NETWORK: "DNS & Network Context",
}


def _redirect_with_flash(url: str, message: str, kind: str = "error") -> RedirectResponse:
    return RedirectResponse(f"{url}?flash={quote(message)}&flash_type={kind}", status_code=303)


def _get_owned_run(db: Session, run_id: str, user: User) -> ReconRun:
    run = db.get(ReconRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found.")
    if run.user_id != user.id and user.role != Role.ADMINISTRATOR:
        raise HTTPException(status_code=404, detail="Run not found.")
    return run


def _previous_completed_run(db: Session, run: ReconRun) -> ReconRun | None:
    return (
        db.query(ReconRun)
        .filter(
            ReconRun.organization_id == run.organization_id,
            ReconRun.status == RunStatus.COMPLETED,
            ReconRun.created_at < run.created_at,
        )
        .order_by(ReconRun.created_at.desc())
        .first()
    )


@router.get("/runs")
def list_runs(request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    runs = db.query(ReconRun).filter(ReconRun.user_id == user.id).order_by(ReconRun.created_at.desc()).all()
    return templates.TemplateResponse(request, "runs_list.html", {"user": user, "runs": runs})


@router.get("/runs/{run_id}")
def run_dashboard(run_id: str, request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    run = _get_owned_run(db, run_id, user)
    visible_results = [r for r in run.results if not r.hidden]

    counts = {cat.value: 0 for cat in ResultCategory}
    for r in visible_results:
        counts[r.category.value] += 1

    previous = _previous_completed_run(db, run)
    changes_preview = []
    if run.status == RunStatus.COMPLETED and previous:
        changes_preview = diff_runs(previous.results, run.results)[:5]

    failed_sources = []
    if run.error_message and run.error_message.startswith("Incomplete source coverage:"):
        failed_sources = [s.strip() for s in run.error_message.split(":", 1)[1].split(",")]

    csrf = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "user": user,
            "run": run,
            "organization": run.organization,
            "counts": counts,
            "category_labels": CATEGORY_LABELS,
            "background": [r for r in visible_results if r.dedupe_key.startswith(BACKGROUND_KEY_PREFIXES)],
            "recent_results": sorted(visible_results, key=lambda r: r.discovered_at, reverse=True)[:8],
            "changes_preview": changes_preview,
            "has_previous_run": previous is not None,
            "failed_sources": failed_sources,
            "csrf_token": csrf,
        },
    )
    response.set_cookie("csrf_token", csrf, samesite="lax", secure=False, httponly=False)
    return response


@router.get("/runs/{run_id}/status")
def run_status(run_id: str, request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    run = _get_owned_run(db, run_id, user)
    response = templates.TemplateResponse(request, "partials/run_status.html", {"run": run})
    # The badge polls while a run is pending/running, but only the badge is swapped in. Once the
    # run finishes, tell HTMX to reload the whole page so the result counts, background card and
    # recent results appear -- otherwise the page keeps showing "Collecting..." until a manual reload.
    if request.headers.get("HX-Request") and run.status in (RunStatus.COMPLETED, RunStatus.FAILED):
        response.headers["HX-Refresh"] = "true"
    return response


@router.get("/runs/{run_id}/category/{category}")
def category_view(
    category: str,
    run_id: str,
    request: Request,
    q: str = "",
    show_hidden: bool = False,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    run = _get_owned_run(db, run_id, user)
    try:
        cat_enum = ResultCategory(category)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Unknown category.") from exc

    results = [r for r in run.results if r.category == cat_enum]
    if not show_hidden:
        results = [r for r in results if not r.hidden]
    if q:
        needle = q.lower()
        results = [r for r in results if needle in r.title.lower() or (r.summary and needle in r.summary.lower())]
    results.sort(key=lambda r: (-r.confidence, r.title.lower()))

    csrf = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "category.html",
        {
            "user": user,
            "run": run,
            "organization": run.organization,
            "category": cat_enum,
            "category_label": CATEGORY_LABELS[cat_enum],
            "results": results,
            "q": q,
            "show_hidden": show_hidden,
            "csrf_token": csrf,
        },
    )
    response.set_cookie("csrf_token", csrf, samesite="lax", secure=False, httponly=False)
    return response


@router.get("/runs/{run_id}/changes")
def changes_view(
    run_id: str,
    request: Request,
    compare_to: str = "",
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    run = _get_owned_run(db, run_id, user)

    previous = None
    if compare_to:
        previous = _get_owned_run(db, compare_to, user)
        if previous.organization_id != run.organization_id:
            previous = None
    if previous is None:
        previous = _previous_completed_run(db, run)

    other_runs = (
        db.query(ReconRun)
        .filter(
            ReconRun.organization_id == run.organization_id,
            ReconRun.status == RunStatus.COMPLETED,
            ReconRun.id != run.id,
        )
        .order_by(ReconRun.created_at.desc())
        .all()
    )

    entries = diff_runs(previous.results, run.results) if previous else []

    csrf = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "changes.html",
        {
            "user": user,
            "run": run,
            "organization": run.organization,
            "previous": previous,
            "other_runs": other_runs,
            "entries": entries,
            "category_labels": CATEGORY_LABELS,
            "csrf_token": csrf,
        },
    )
    response.set_cookie("csrf_token", csrf, samesite="lax", secure=False, httponly=False)
    return response


@router.post("/runs/{run_id}/results/{result_id}/hide")
def hide_result(
    run_id: str,
    result_id: str,
    request: Request,
    reason: str = Form(...),
    csrf_token: str = Form(...),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    run = _get_owned_run(db, run_id, user)
    if not secrets_compare(request.cookies.get("csrf_token", ""), csrf_token):
        return _redirect_with_flash(f"/runs/{run_id}", "Your form session expired. Please try again.")

    result = db.get(ReconResult, result_id)
    if result is None or result.run_id != run.id:
        raise HTTPException(status_code=404, detail="Result not found.")

    try:
        form = HideResultForm(reason=reason)
    except ValidationError as exc:
        return _redirect_with_flash(f"/runs/{run_id}", exc.errors()[0]["msg"])

    result.hidden = True
    result.hidden_reason = form.reason
    db.commit()
    record_event(
        db,
        event_type="result.hidden",
        description=f"Result hidden: {result.title} ({form.reason})",
        user_id=user.id,
        target_type="recon_result",
        target_id=result.id,
    )
    return RedirectResponse(f"/runs/{run_id}/category/{result.category.value}", status_code=303)


@router.post("/runs/{run_id}/notes")
def add_run_note(
    run_id: str,
    request: Request,
    body: str = Form(...),
    csrf_token: str = Form(...),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    run = _get_owned_run(db, run_id, user)
    if not secrets_compare(request.cookies.get("csrf_token", ""), csrf_token):
        return _redirect_with_flash(f"/runs/{run_id}", "Your form session expired. Please try again.")

    try:
        form = NoteForm(body=body)
    except ValidationError as exc:
        return _redirect_with_flash(f"/runs/{run_id}", exc.errors()[0]["msg"])

    db.add(AnalystNote(user_id=user.id, run_id=run.id, body=form.body))
    db.commit()
    return RedirectResponse(f"/runs/{run_id}", status_code=303)


@router.post("/results/{result_id}/notes")
def add_result_note(
    result_id: str,
    request: Request,
    body: str = Form(...),
    csrf_token: str = Form(...),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    result = db.get(ReconResult, result_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Result not found.")
    run = _get_owned_run(db, result.run_id, user)
    if not secrets_compare(request.cookies.get("csrf_token", ""), csrf_token):
        return _redirect_with_flash(f"/runs/{run.id}/category/{result.category.value}", "Your form session expired.")

    try:
        form = NoteForm(body=body)
    except ValidationError as exc:
        return _redirect_with_flash(f"/runs/{run.id}/category/{result.category.value}", exc.errors()[0]["msg"])

    db.add(AnalystNote(user_id=user.id, result_id=result.id, body=form.body))
    db.commit()
    return RedirectResponse(f"/runs/{run.id}/category/{result.category.value}", status_code=303)
