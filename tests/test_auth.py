def _get_csrf(client, url="/auth/register"):
    response = client.get(url)
    assert response.status_code == 200
    return client.cookies.get("csrf_token")


def test_register_creates_session_and_redirects(client):
    csrf = _get_csrf(client)
    response = client.post(
        "/auth/register",
        data={
            "email": "newuser@example.com",
            "password": "correct-horse-battery",
            "confirm_password": "correct-horse-battery",
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/"
    assert client.cookies.get("eh_session") is not None


def test_register_rejects_mismatched_csrf(client):
    _get_csrf(client)
    response = client.post(
        "/auth/register",
        data={
            "email": "another@example.com",
            "password": "correct-horse-battery",
            "confirm_password": "correct-horse-battery",
            "csrf_token": "not-the-real-token",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "flash" in response.headers["location"]
    assert client.cookies.get("eh_session") is None


def test_register_rejects_weak_password(client):
    csrf = _get_csrf(client)
    response = client.post(
        "/auth/register",
        data={"email": "weak@example.com", "password": "short", "confirm_password": "short", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert client.cookies.get("eh_session") is None


def test_login_with_wrong_password_fails(client):
    csrf = _get_csrf(client)
    client.post(
        "/auth/register",
        data={
            "email": "loginuser@example.com",
            "password": "correct-horse-battery",
            "confirm_password": "correct-horse-battery",
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )
    client.cookies.delete("eh_session")

    csrf2 = _get_csrf(client, "/auth/login")
    response = client.post(
        "/auth/login",
        data={"email": "loginuser@example.com", "password": "wrong-password", "csrf_token": csrf2},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert client.cookies.get("eh_session") is None


def test_unauthenticated_landing_redirects_to_login(client):
    client.cookies.clear()
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/auth/login"


def test_password_reset_flow_sets_new_password(client, db_session):
    import re

    from app.models import User
    from app.security import verify_password

    csrf = _get_csrf(client)
    client.post(
        "/auth/register",
        data={"email": "resetme@example.com", "password": "correct-horse-battery",
              "confirm_password": "correct-horse-battery", "csrf_token": csrf},
        follow_redirects=False,
    )
    csrf = _get_csrf(client, "/auth/reset")
    page = client.post("/auth/reset", data={"email": "resetme@example.com", "csrf_token": csrf})
    link = re.search(r"/auth/reset/confirm/[\w-]+", page.text).group(0)

    response = client.post(
        link,
        data={"password": "brand-new-password-1", "confirm_password": "brand-new-password-1", "csrf_token": csrf},
        follow_redirects=False,
    )

    # Regression: SQLite returns the stored expiry without tzinfo, which used to raise a TypeError (HTTP 500).
    assert response.status_code == 303
    assert "Password+updated" in response.headers["location"] or "Password%20updated" in response.headers["location"]
    user = db_session.query(User).filter(User.email == "resetme@example.com").one()
    assert verify_password("brand-new-password-1", user.password_hash)
