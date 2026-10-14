from app.models import AccessMode, Organization, ReconRun, RunStatus, User


def _register(client, email):
    client.get("/auth/register")
    client.post(
        "/auth/register",
        data={
            "email": email,
            "password": "correct-horse-battery",
            "confirm_password": "correct-horse-battery",
            "csrf_token": client.cookies.get("csrf_token"),
        },
        follow_redirects=False,
    )


def _run(db_session, email, status):
    user = db_session.query(User).filter(User.email == email).one()
    org = Organization(name=f"Status Org {status.value}", primary_domain=f"status-{status.value}.example")
    db_session.add(org)
    db_session.commit()
    run = ReconRun(organization_id=org.id, user_id=user.id, mode=AccessMode.PUBLIC_PROFILE, status=status)
    db_session.add(run)
    db_session.commit()
    return run.id


def test_status_poll_reloads_the_page_once_the_run_finishes(client, db_session):
    _register(client, "status-poll@example.com")
    running = _run(db_session, "status-poll@example.com", RunStatus.RUNNING)
    finished = _run(db_session, "status-poll@example.com", RunStatus.COMPLETED)

    still_running = client.get(f"/runs/{running}/status", headers={"HX-Request": "true"})
    assert still_running.status_code == 200
    assert "HX-Refresh" not in still_running.headers

    done = client.get(f"/runs/{finished}/status", headers={"HX-Request": "true"})
    assert done.headers.get("HX-Refresh") == "true"

    # A plain (non-HTMX) request never gets the refresh instruction.
    assert "HX-Refresh" not in client.get(f"/runs/{finished}/status").headers
