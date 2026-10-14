from app.services.recon.leadership_adapter import _published_executives


def test_published_executives_extracts_name_title_pairs():
    pairs = _published_executives(
        "<h2>Jordan Reyes — Chief Executive Officer</h2><p>Chief Technology Officer: Alex Morgan</p>"
    )

    assert ("Jordan Reyes", "Chief Executive Officer") in pairs
    assert ("Alex Morgan", "Chief Technology Officer") in pairs
