from app.routers.search import _normalize_domain


def test_normalize_domain_accepts_url_and_removes_www_prefix():
    assert _normalize_domain("https://www.example.org/path") == "example.org"


def test_normalize_domain_rejects_invalid_values():
    assert _normalize_domain("127.0.0.1") is None
    assert _normalize_domain("not a domain") is None
