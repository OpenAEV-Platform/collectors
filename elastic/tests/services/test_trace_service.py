"""Tests for the Elastic Security trace service."""

from unittest.mock import Mock

import pytest
from src.collector.models import ExpectationResult
from src.services.exception import ElasticValidationError
from src.services.trace_service import ElasticTraceService
from tests.services.fixtures.factories import create_test_config


def _make_expectation(sig_type: str = "source_ipv4_address", value: str = "1.2.3.4"):
    """Build a mock expectation with a single signature."""
    signature = Mock()
    signature.type.value = sig_type
    signature.value = value
    expectation = Mock()
    expectation.inject_expectation_signatures = [signature]
    return expectation


def _make_result(matching_data: dict) -> ExpectationResult:
    """Build a valid ExpectationResult with a matched alert."""
    return ExpectationResult(
        expectation_id="exp-1",
        is_valid=True,
        expectation=_make_expectation(),
        matched_alerts=[matching_data],
    )


class TestElasticTraceService:
    """Test cases for ElasticTraceService."""

    def test_init_without_config_raises(self):
        """Initialization without a config raises a validation error."""
        with pytest.raises(ElasticValidationError):
            ElasticTraceService(config=None)

    def test_create_traces_from_results_success(self):
        """A valid result produces a single trace with a source-IP alert name."""
        service = ElasticTraceService(config=create_test_config())
        result = _make_result({"source_ipv4_address": {"data": "1.2.3.4"}})

        traces = service.create_traces_from_results([result], "elastic--collector")

        assert len(traces) == 1  # noqa: S101
        trace = traces[0]
        assert trace.inject_expectation_trace_expectation == "exp-1"  # noqa: S101
        assert (
            trace.inject_expectation_trace_source_id == "elastic--collector"
        )  # noqa: S101
        assert "Source IP" in trace.inject_expectation_trace_alert_name  # noqa: S101
        assert trace.inject_expectation_trace_alert_link.startswith(
            "http"
        )  # noqa: S101

    def test_create_traces_target_ip_alert_name(self):
        """A target-IP match yields a target-IP alert name."""
        service = ElasticTraceService(config=create_test_config())
        result = _make_result({"target_ipv4_address": {"data": "10.0.0.1"}})

        traces = service.create_traces_from_results([result], "elastic--collector")

        assert (
            "Target IP" in traces[0].inject_expectation_trace_alert_name
        )  # noqa: S101

    def test_create_traces_generic_alert_name(self):
        """A non-IP match yields the generic alert name."""
        service = ElasticTraceService(config=create_test_config())
        result = _make_result({"parent_process_name": {"data": "x.exe"}})

        traces = service.create_traces_from_results([result], "elastic--collector")

        name = traces[0].inject_expectation_trace_alert_name
        assert name == "Elastic Security Detection Alert"  # noqa: S101

    def test_create_traces_empty_collector_id_raises(self):
        """An empty collector_id raises a validation error."""
        service = ElasticTraceService(config=create_test_config())
        with pytest.raises(ElasticValidationError):
            service.create_traces_from_results([], "")

    def test_create_traces_non_list_raises(self):
        """A non-list results argument raises a validation error."""
        service = ElasticTraceService(config=create_test_config())
        with pytest.raises(ElasticValidationError):
            service.create_traces_from_results("nope", "elastic--collector")

    def test_create_traces_no_valid_results(self):
        """Invalid results (no matches) produce no traces."""
        service = ElasticTraceService(config=create_test_config())
        invalid = ExpectationResult(
            expectation_id="exp-2", is_valid=False, matched_alerts=None
        )
        assert service.create_traces_from_results([invalid], "c") == []  # noqa: S101

    def test_create_traces_kibana_url_used(self):
        """When kibana_url is configured it is used for the trace link."""
        config = create_test_config()
        config.elastic.kibana_url = "https://kibana.example.com:5601"
        service = ElasticTraceService(config=config)
        result = _make_result({"source_ipv4_address": {"data": "1.2.3.4"}})

        traces = service.create_traces_from_results([result], "elastic--collector")

        assert traces[0].inject_expectation_trace_alert_link.startswith(  # noqa: S101
            "https://kibana.example.com:5601"
        )

    def test_derive_kibana_base_url_uses_configured_url(self):
        """A configured kibana_url is used verbatim (trailing slash trimmed)."""
        config = create_test_config()
        config.elastic.kibana_url = "https://kibana.example.com:5601/"
        service = ElasticTraceService(config=config)

        assert (  # noqa: S101
            service._derive_kibana_base_url() == "https://kibana.example.com:5601"
        )

    def test_derive_kibana_base_url_rewrites_9200_to_5601(self):
        """Without kibana_url, the Elasticsearch :9200 port becomes Kibana :5601."""
        config = create_test_config()
        config.elastic.kibana_url = None
        config.elastic.base_url = "https://es.example.com:9200"
        service = ElasticTraceService(config=config)

        assert (  # noqa: S101
            service._derive_kibana_base_url() == "https://es.example.com:5601"
        )

    def test_derive_kibana_base_url_rewrites_non_default_port(self):
        """Any explicit port (not only 9200) is rewritten to Kibana :5601."""
        config = create_test_config()
        config.elastic.kibana_url = None
        config.elastic.base_url = "https://es.example.com:443"
        service = ElasticTraceService(config=config)

        assert (  # noqa: S101
            service._derive_kibana_base_url() == "https://es.example.com:5601"
        )

    def test_derive_kibana_base_url_without_port_falls_back(self):
        """With no explicit port the Elasticsearch URL is returned unchanged.

        The heuristic must not silently invent a :5601 port when base_url has
        none (e.g. a host behind a reverse proxy); the operator is expected to
        set ELASTIC_KIBANA_URL instead.
        """
        config = create_test_config()
        config.elastic.kibana_url = None
        config.elastic.base_url = "https://es.example.com"
        service = ElasticTraceService(config=config)

        assert (  # noqa: S101
            service._derive_kibana_base_url() == "https://es.example.com"
        )

    def test_create_traces_heuristic_link_uses_5601(self):
        """End to end, a :9200 base_url without kibana_url yields a :5601 link."""
        config = create_test_config()
        config.elastic.kibana_url = None
        config.elastic.base_url = "https://es.example.com:9200"
        service = ElasticTraceService(config=config)
        result = _make_result({"source_ipv4_address": {"data": "1.2.3.4"}})

        traces = service.create_traces_from_results([result], "elastic--collector")

        assert traces[0].inject_expectation_trace_alert_link.startswith(  # noqa: S101
            "https://es.example.com:5601/app/security/alerts"
        )

    def test_get_service_info(self):
        """The service exposes detection-only metadata."""
        service = ElasticTraceService(config=create_test_config())
        info = service.get_service_info()
        assert info["creates_detection_traces"] is True  # noqa: S101
        assert info["creates_prevention_traces"] is False  # noqa: S101
