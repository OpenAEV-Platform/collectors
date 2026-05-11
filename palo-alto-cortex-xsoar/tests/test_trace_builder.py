"""Tests for TraceBuilder and _build_web_base_url."""

from unittest.mock import patch

import pytest
from src.models.incident import Alert
from src.services.utils.trace_builder import TraceBuilder, _build_web_base_url

# ---------------------------------------------------------------------------
# _build_web_base_url
# ---------------------------------------------------------------------------


class TestBuildWebBaseUrl:
    def test_strips_api_soar_prefix(self):
        """api-soar- prefix is removed from the API URL."""
        result = _build_web_base_url(
            "https://api-soar-filigran.crtx.fa.paloaltonetworks.com"
        )
        assert result == "https://filigran.crtx.fa.paloaltonetworks.com"

    def test_different_tenant(self):
        result = _build_web_base_url(
            "https://api-soar-acme.crtx.us.paloaltonetworks.com"
        )
        assert result == "https://acme.crtx.us.paloaltonetworks.com"

    def test_trailing_slash(self):
        result = _build_web_base_url(
            "https://api-soar-filigran.crtx.fa.paloaltonetworks.com/"
        )
        assert result == "https://filigran.crtx.fa.paloaltonetworks.com"

    def test_no_prefix_unchanged(self):
        """API URL without api-soar- prefix is kept as-is."""
        result = _build_web_base_url("https://custom-host.example.com")
        assert result == "https://custom-host.example.com"

    def test_no_prefix_strips_trailing_slash(self):
        result = _build_web_base_url("https://custom-host.example.com/")
        assert result == "https://custom-host.example.com"


# ---------------------------------------------------------------------------
# TraceBuilder.create_alert_trace
# ---------------------------------------------------------------------------


class TestCreateAlertTrace:
    @pytest.fixture
    def sample_alert(self):
        return Alert(
            alert_id="166",
            case_id=42,
            detection_timestamp=1714200000000,
            action_pretty="Detected (Reported)",
        )

    def test_link_format_with_standard_api_url(self, sample_alert):
        """The exact example from the requirement."""
        trace = TraceBuilder.create_alert_trace(
            alert=sample_alert,
            api_url="https://api-soar-filigran.crtx.fa.paloaltonetworks.com",
        )
        assert (
            trace["alert_link"]
            == "https://filigran.crtx.fa.paloaltonetworks.com/issue-view/166"
        )

    def test_link_uses_alert_id(self):
        """The link must use alert_id, not case_id."""
        alert = Alert(
            alert_id="999",
            case_id=1,
            detection_timestamp=1714200000000,
        )
        trace = TraceBuilder.create_alert_trace(
            alert=alert,
            api_url="https://api-soar-tenant.crtx.eu.paloaltonetworks.com",
        )
        assert trace["alert_link"].endswith("/issue-view/999")

    def test_link_when_case_id_is_none(self):
        alert = Alert(
            alert_id="500",
            case_id=None,
            detection_timestamp=1714200000000,
        )
        trace = TraceBuilder.create_alert_trace(
            alert=alert,
            api_url="https://api-soar-filigran.crtx.fa.paloaltonetworks.com",
        )
        assert trace["alert_link"].endswith("/issue-view/500")

    def test_alert_name(self, sample_alert):
        trace = TraceBuilder.create_alert_trace(
            alert=sample_alert,
            api_url="https://api-soar-filigran.crtx.fa.paloaltonetworks.com",
        )
        assert trace["alert_name"] == "PaloAltoCortexXSOAR Alert 166"

    def test_additional_data(self, sample_alert):
        trace = TraceBuilder.create_alert_trace(
            alert=sample_alert,
            api_url="https://api-soar-filigran.crtx.fa.paloaltonetworks.com",
        )
        assert trace["additional_data"]["alert_id"] == "166"
        assert trace["additional_data"]["case_id"] == 42
        assert trace["additional_data"]["data_source"] == "palo_alto_cortex_xsoar"

    def test_empty_api_url(self, sample_alert):
        trace = TraceBuilder.create_alert_trace(alert=sample_alert, api_url="")
        assert trace["alert_link"] == ""

    def test_empty_alert_id(self):
        alert = Alert(
            alert_id="",
            case_id=1,
            detection_timestamp=1714200000000,
        )
        trace = TraceBuilder.create_alert_trace(alert=alert, api_url="https://test.com")
        assert trace["alert_link"] == ""

    def test_create_alert_trace_exception(self, sample_alert):
        with patch(
            "src.services.utils.trace_builder._build_web_base_url"
        ) as mock_build:
            mock_build.side_effect = Exception("error")
            trace = TraceBuilder.create_alert_trace(
                alert=sample_alert, api_url="https://test.com"
            )
            assert trace["alert_link"] == ""

    def test_fallback_api_url_link(self):
        alert = Alert(
            alert_id="77",
            case_id=10,
            detection_timestamp=1714200000000,
        )
        trace = TraceBuilder.create_alert_trace(
            alert=alert,
            api_url="https://custom-host.example.com",
        )
        assert trace["alert_link"] == "https://custom-host.example.com/issue-view/77"
