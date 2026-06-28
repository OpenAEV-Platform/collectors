"""Tests for the shared URL helpers (credential redaction)."""

import pytest
from src.services.utils.url import redact_userinfo


class TestRedactUserinfo:
    """Test cases for redact_userinfo."""

    def test_strips_user_and_password(self):
        """A ``user:pass@`` URL is rebuilt without its credentials."""
        sanitized = redact_userinfo("https://user:secret@es.example.com:9200")

        assert sanitized == "https://es.example.com:9200"  # noqa: S101
        assert "user" not in sanitized  # noqa: S101
        assert "secret" not in sanitized  # noqa: S101
        assert "@" not in sanitized  # noqa: S101

    def test_strips_username_only(self):
        """Userinfo with only a username is removed."""
        assert (  # noqa: S101
            redact_userinfo("https://user@es.example.com:9200")
            == "https://es.example.com:9200"
        )

    def test_preserves_url_without_userinfo(self):
        """A URL without credentials is returned unchanged."""
        assert (  # noqa: S101
            redact_userinfo("https://es.example.com:9200")
            == "https://es.example.com:9200"
        )

    def test_preserves_path(self):
        """The path is preserved while credentials are removed."""
        assert (  # noqa: S101
            redact_userinfo("https://user:secret@es.example.com:9200/es")
            == "https://es.example.com:9200/es"
        )

    def test_drops_query_and_fragment(self):
        """Query strings and fragments (possible secret carriers) are dropped."""
        sanitized = redact_userinfo(
            "https://user:secret@es.example.com:9200/p?api_key=abc#frag"
        )

        assert sanitized == "https://es.example.com:9200/p"  # noqa: S101
        assert "api_key" not in sanitized  # noqa: S101
        assert "secret" not in sanitized  # noqa: S101

    def test_handles_no_port(self):
        """A URL without an explicit port keeps the host only."""
        assert (  # noqa: S101
            redact_userinfo("https://user:secret@es.example.com")
            == "https://es.example.com"
        )

    def test_handles_ipv6_host(self):
        """An IPv6 literal stays bracketed after redaction."""
        assert (  # noqa: S101
            redact_userinfo("https://user:secret@[2001:db8::1]:9200")
            == "https://[2001:db8::1]:9200"
        )

    @pytest.mark.parametrize("value", ["", None])
    def test_returns_falsy_unchanged(self, value):
        """Falsy input is returned unchanged."""
        assert redact_userinfo(value) == value  # noqa: S101

    def test_strips_userinfo_from_schemeless_string(self):
        """A schemeless ``user:pass@host`` string still has userinfo removed."""
        sanitized = redact_userinfo("user:secret@es.example.com:9200")

        assert "secret" not in sanitized  # noqa: S101
        assert "user" not in sanitized  # noqa: S101
