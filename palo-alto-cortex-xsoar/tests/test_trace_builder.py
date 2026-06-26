"""Tests for TraceBuilder and _extract_incident_url."""

from unittest.mock import patch

import pytest
from src.services.ioc_extractor import IncidentResult, IndicatorResults
from src.services.utils.trace_builder import TraceBuilder, _extract_incident_url

# ---------------------------------------------------------------------------
# _extract_incident_url
# ---------------------------------------------------------------------------


def _make_incident(incident_id="test-id", urls=None):
    return IncidentResult(
        id=incident_id,
        action=["Detected (Reported)"],
        indicators=IndicatorResults(url=urls or []),
    )


class TestExtractIncidentUrl:
    def test_finds_paloalto_url(self):
        incident = _make_incident(
            urls=[
                "https://other.example.com/page",
                "https://filigran.crtx.fa.paloaltonetworks.com/issue-view/166",
                "https://another.site.com",
            ]
        )
        result = _extract_incident_url(incident)
        assert result == "https://filigran.crtx.fa.paloaltonetworks.com/issue-view/166"

    def test_returns_first_match(self):
        incident = _make_incident(
            urls=[
                "https://tenant1.crtx.fa.paloaltonetworks.com/issue-view/1",
                "https://tenant2.crtx.fa.paloaltonetworks.com/issue-view/2",
            ]
        )
        result = _extract_incident_url(incident)
        assert result == "https://tenant1.crtx.fa.paloaltonetworks.com/issue-view/1"

    def test_no_paloalto_url(self):
        incident = _make_incident(urls=["https://other.com/page"])
        result = _extract_incident_url(incident)
        assert result == ""

    def test_empty_urls(self):
        incident = _make_incident(urls=[])
        result = _extract_incident_url(incident)
        assert result == ""


# ---------------------------------------------------------------------------
# TraceBuilder.create_incident_trace
# ---------------------------------------------------------------------------


class TestCreateIncidentTrace:
    @pytest.fixture
    def sample_incident(self):
        return _make_incident(
            incident_id="166",
            urls=["https://filigran.crtx.fa.paloaltonetworks.com/issue-view/166"],
        )

    def test_link_from_indicators_url(self, sample_incident):
        """The link is extracted from incident.indicators.url."""
        trace = TraceBuilder.create_incident_trace(
            incident=sample_incident,
            api_url="https://api-soar-filigran.crtx.fa.paloaltonetworks.com",
        )
        assert (
            trace["alert_link"]
            == "https://filigran.crtx.fa.paloaltonetworks.com/issue-view/166"
        )

    def test_link_uses_indicator_url_not_api_url(self):
        """The link comes from indicators, not from api_url transformation."""
        incident = _make_incident(
            incident_id="999",
            urls=["https://acme.crtx.fa.paloaltonetworks.com/issue-view/999"],
        )
        trace = TraceBuilder.create_incident_trace(
            incident=incident,
            api_url="https://completely-different.example.com",
        )
        assert (
            trace["alert_link"]
            == "https://acme.crtx.fa.paloaltonetworks.com/issue-view/999"
        )

    def test_incident_name(self, sample_incident):
        trace = TraceBuilder.create_incident_trace(
            incident=sample_incident,
            api_url="https://api-soar-filigran.crtx.fa.paloaltonetworks.com",
        )
        assert trace["alert_name"] == "PaloAltoCortexXSOAR Incident 166"

    def test_additional_data(self, sample_incident):
        trace = TraceBuilder.create_incident_trace(
            incident=sample_incident,
            api_url="https://api-soar-filigran.crtx.fa.paloaltonetworks.com",
        )
        assert trace["additional_data"]["incident_id"] == "166"
        assert trace["additional_data"]["data_source"] == "palo_alto_cortex_xsoar"

    def test_no_matching_url_returns_empty_link(self):
        incident = _make_incident(
            incident_id="500",
            urls=["https://other.example.com/page"],
        )
        trace = TraceBuilder.create_incident_trace(
            incident=incident,
            api_url="https://api-soar-filigran.crtx.fa.paloaltonetworks.com",
        )
        assert trace["alert_link"] == ""

    def test_empty_urls_returns_empty_link(self):
        incident = _make_incident(incident_id="500", urls=[])
        trace = TraceBuilder.create_incident_trace(
            incident=incident,
            api_url="https://test.com",
        )
        assert trace["alert_link"] == ""

    def test_create_incident_trace_exception(self, sample_incident):
        with patch(
            "src.services.utils.trace_builder._extract_incident_url"
        ) as mock_extract:
            mock_extract.side_effect = Exception("error")
            trace = TraceBuilder.create_incident_trace(
                incident=sample_incident, api_url="https://test.com"
            )
            assert trace["alert_link"] == ""
