from app.services.recon.documents_adapter import (
    _customer_phone_numbers,
    _organization_inboxes_from_page,
    _security_txt_findings,
)


def test_security_txt_returns_published_organization_contact_only():
    findings = _security_txt_findings(
        "example.org",
        "/.well-known/security.txt",
        "https://example.org/.well-known/security.txt",
        "# Contact details\nContact: mailto:security@example.org\nContact: mailto:jane@example.org\n",
    )

    assert len(findings) == 1
    assert findings[0].summary == "security@example.org"
    assert findings[0].source_name == "Official security.txt"


def test_security_txt_returns_published_security_contact_url():
    findings = _security_txt_findings(
        "example.org",
        "/security.txt",
        "https://example.org/security.txt",
        "Contact: https://example.org/security/report\n",
    )

    assert len(findings) == 1
    assert findings[0].summary == "https://example.org/security/report"


def test_official_page_returns_generic_inbox_but_not_personal_email():
    findings = _organization_inboxes_from_page(
        "example.org",
        "https://example.org/contact",
        'Contact <a href="mailto:support@example.org">support</a> or jane@example.org.',
    )

    assert len(findings) == 1
    assert findings[0].summary == "support@example.org"


def test_contact_page_returns_published_customer_phone_number():
    findings = _customer_phone_numbers(
        "example.org",
        "https://example.org/contact",
        '<a href="tel:+1-555-010-1234">Call us</a>',
    )

    assert len(findings) == 1
    assert findings[0].summary == "+1-555-010-1234"
