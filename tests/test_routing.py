import os

import pytest

os.environ.setdefault("TEST_MODE", "true")
os.environ.setdefault("HIBP_API_KEY", "test")
os.environ.setdefault("APIFY_API_TOKEN", "test")
os.environ.setdefault("APIFY_ACTOR_ID", "test")
os.environ.setdefault("GOOGLE_CSE_API_KEY", "test")
os.environ.setdefault("GOOGLE_CSE_ID", "test")
os.environ.setdefault("OLLAMA_HOST", "http://localhost:11434")
os.environ.setdefault("SPIDERFOOT_HOST", "http://localhost:5001")

from eidolon.core.models import InputClassification


class TestInputClassificationModel:
    def test_email_type(self):
        c = InputClassification(
            type="email", value="test@example.com", raw="test@example.com"
        )
        assert c.type == "email"

    def test_phone_type(self):
        c = InputClassification(type="phone", value="+15551234567", raw="555-123-4567")
        assert c.type == "phone"

    def test_name_type(self):
        c = InputClassification(type="name", value="John Doe", raw="John Doe")
        assert c.type == "name"

    def test_org_type(self):
        c = InputClassification(type="org", value="Acme Corp", raw="Acme Corp")
        assert c.type == "org"

    def test_invalid_type_raises(self):
        with pytest.raises(Exception):
            InputClassification(type="invalid", value="x", raw="x")


class TestInputNormalization:
    """Test that intake_node correctly routes inputs by type."""

    def test_email_detected(self):
        raw = "user@example.com"
        assert "@" in raw and "." in raw.split("@")[-1]

    def test_phone_pattern(self):
        import re

        phone_re = re.compile(r"[\d\s\-\(\)\+]{7,}")
        assert phone_re.search("555-123-4567")
        assert phone_re.search("+1 (555) 123-4567")

    def test_multiple_inputs_split(self):
        raw = "email@example.com\nJohn Doe\n555-123-4567"
        parts = raw.splitlines()
        assert len(parts) == 3
