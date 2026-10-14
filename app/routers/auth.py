from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.audit import record_event
from app.database import get_db
from app.deps import get_current_user, get_or_create_csrf_token, secrets_compare
from app.models import PasswordResetToken, Role, User
from app.schemas import LoginForm, NewPasswordForm, RegisterForm
from app.security import (
    create_session_token,
    generate_reset_token,
    hash_password,
    hash_reset_token,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["auth"])
templates = Jinja2Templates(directory="templates")


def _redirect_with_flash(url: str, message: str, kind: str = "error") -> RedirectResponse:
    return RedirectResponse(f"{url}?flash={quote(message)}&flash_type={kind}", status_code=303)


@router.get("/register")
def register_form(request: Request, user: User | None = Depends(get_current_user)):
    if user:
        return RedirectResponse("/", status_code=303)
    csrf = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request, "auth/register.html", {"csrf_token": csrf, "flash": request.query_params.get("flash")}
    )
    response.set_cookie("csrf_token", csrf, samesite="lax", secure=False, httponly=False)
    return response


@router.post("/register")
def register_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    if not secrets_compare(request.cookies.get("csrf_token", ""), csrf_token):
        return _redirect_with_flash("/auth/register", "Your form session expired. Please try again.")

    if password != confirm_password:
        return _redirect_with_flash("/auth/register", "Passwords do not match.")

    try:
        form = RegisterForm(email=email, password=password)
    except ValidationError as exc:
        return _redirect_with_flash("/auth/register", exc.errors()[0]["msg"])

    existing = db.query(User).filter(User.email == form.email.lower()).one_or_none()
    if existing:
        return _redirect_with_flash("/auth/register", "An account with that email already exists.")

    is_first_user = db.query(User).count() == 0
    user = User(
        email=form.email.lower(),
        password_hash=hash_password(form.password),
        role=Role.ADMINISTRATOR if is_first_user else Role.MEMBER,
    )
    db.add(user)
    db.commit()
    record_event(db, event_type="auth.register", description="User registered.", user_id=user.id)

    token = create_session_token(user.id)
    response = RedirectResponse("/", status_code=303)
    response.set_cookie("eh_session", token, httponly=True, samesite="lax", secure=False)
    return response


@router.get("/login")
def login_form(request: Request, user: User | None = Depends(get_current_user)):
    if user:
        return RedirectResponse("/", status_code=303)
    csrf = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request, "auth/login.html", {"csrf_token": csrf, "flash": request.query_params.get("flash")}
    )
    response.set_cookie("csrf_token", csrf, samesite="lax", secure=False, httponly=False)
    return response


@router.post("/login")
def login_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    if not secrets_compare(request.cookies.get("csrf_token", ""), csrf_token):
        return _redirect_with_flash("/auth/login", "Your form session expired. Please try again.")

    try:
        form = LoginForm(email=email, password=password)
    except ValidationError:
        return _redirect_with_flash("/auth/login", "Enter a valid email and password.")

    user = db.query(User).filter(User.email == form.email.lower()).one_or_none()
    if not user or not verify_password(form.password, user.password_hash) or not user.is_active:
        record_event(db, event_type="auth.login_failed", description=f"Failed login for {form.email.lower()}.")
        return _redirect_with_flash("/auth/login", "Incorrect email or password.")

    record_event(db, event_type="auth.login", description="User logged in.", user_id=user.id)
    token = create_session_token(user.id)
    response = RedirectResponse("/", status_code=303)
    response.set_cookie("eh_session", token, httponly=True, samesite="lax", secure=False)
    return response


@router.post("/logout")
def logout(request: Request, user: User | None = Depends(get_current_user), db: Session = Depends(get_db)):
    if user:
        record_event(db, event_type="auth.logout", description="User logged out.", user_id=user.id)
    response = RedirectResponse("/auth/login", status_code=303)
    response.delete_cookie("eh_session")
    return response


@router.get("/reset")
def reset_request_form(request: Request):
    csrf = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request, "auth/reset_request.html", {"csrf_token": csrf, "flash": request.query_params.get("flash")}
    )
    response.set_cookie("csrf_token", csrf, samesite="lax", secure=False, httponly=False)
    return response


@router.post("/reset")
def reset_request_submit(
    request: Request, email: str = Form(...), csrf_token: str = Form(...), db: Session = Depends(get_db)
):
    if not secrets_compare(request.cookies.get("csrf_token", ""), csrf_token):
        return _redirect_with_flash("/auth/reset", "Your form session expired. Please try again.")

    user = db.query(User).filter(User.email == email.strip().lower()).one_or_none()
    reset_link = None
    if user:
        raw, hashed = generate_reset_token()
        db.add(
            PasswordResetToken(
                user_id=user.id,
                token_hash=hashed,
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            )
        )
        db.commit()
        record_event(db, event_type="auth.reset_requested", description="Password reset requested.", user_id=user.id)
        reset_link = f"/auth/reset/confirm/{raw}"

    # This is a local/demo build with no outbound email service configured, so the reset link
    # is shown directly rather than emailed. A production deployment must email it instead of
    # ever displaying it in-app.
    csrf = get_or_create_csrf_token(request)
    return templates.TemplateResponse(
        request,
        "auth/reset_request.html",
        {"csrf_token": csrf, "reset_link": reset_link, "submitted": True},
    )


@router.get("/reset/confirm/{token}")
def reset_confirm_form(request: Request, token: str):
    csrf = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "auth/reset_confirm.html",
        {"csrf_token": csrf, "token": token, "flash": request.query_params.get("flash")},
    )
    response.set_cookie("csrf_token", csrf, samesite="lax", secure=False, httponly=False)
    return response


@router.post("/reset/confirm/{token}")
def reset_confirm_submit(
    request: Request,
    token: str,
    password: str = Form(...),
    confirm_password: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    if not secrets_compare(request.cookies.get("csrf_token", ""), csrf_token):
        return _redirect_with_flash(f"/auth/reset/confirm/{token}", "Your form session expired. Please try again.")

    if password != confirm_password:
        return _redirect_with_flash(f"/auth/reset/confirm/{token}", "Passwords do not match.")

    try:
        NewPasswordForm(password=password)
    except ValidationError as exc:
        return _redirect_with_flash(f"/auth/reset/confirm/{token}", exc.errors()[0]["msg"])

    token_hash = hash_reset_token(token)
    record = (
        db.query(PasswordResetToken)
        .filter(PasswordResetToken.token_hash == token_hash, PasswordResetToken.used_at.is_(None))
        .one_or_none()
    )
    # SQLite drops tzinfo on read, so a stored UTC expiry comes back naive; comparing it to an
    # aware "now" raised TypeError and 500'd every reset attempt. It was written as UTC, so mark it so.
    expires_at = record.expires_at if record else None
    if expires_at is not None and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if not record or expires_at < datetime.now(timezone.utc):
        return _redirect_with_flash("/auth/reset", "That reset link is invalid or has expired.")

    user = db.get(User, record.user_id)
    user.password_hash = hash_password(password)
    record.used_at = datetime.now(timezone.utc)
    db.commit()
    record_event(db, event_type="auth.reset_completed", description="Password reset completed.", user_id=user.id)

    return _redirect_with_flash("/auth/login", "Password updated. Please sign in.", kind="success")
