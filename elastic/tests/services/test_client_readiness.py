"""Client-readiness tests: signature vocabulary, transient-outage pending,
SIEM-only drilldown fallback. See docs/CLIENT_READINESS_SPEC.md (DoD-1/2/3)."""

from unittest.mock import Mock

from src.services import signature_compat
from src.services.exception import (
    ElasticAPIError,
    ElasticAuthenticationError,
    ElasticNetworkError,
    ElasticNoMatchingAlertsError,
    ElasticUngradableError,
)
from src.services.expectation_service import ElasticExpectationService
from tests.services.fixtures.factories import (
    MockObjectsFactory,
    create_test_config,
)


def _sig(sig_type: str, value: str) -> Mock:
    s = Mock()
    s.type.value = sig_type
    s.value = value
    return s


class TestSignatureCompatShim:
    """DoD-1a: the fail-soft enum shim never lets a signature type abort parsing."""

    def test_install_is_idempotent(self):
        assert signature_compat.install() is True  # noqa: S101
        assert signature_compat.install() is True  # noqa: S101

    def test_alias_maps_to_canonical(self):
        from pyoaev.signatures.types import SignatureTypes

        signature_compat.install()
        assert SignatureTypes("source_ipv4").value == "source_ipv4_address"  # noqa: S101
        assert SignatureTypes("start_time").value == "start_date"  # noqa: S101
        assert SignatureTypes("target_ipv6").value == "target_ipv6_address"  # noqa: S101

    def test_unknown_type_is_tolerated_not_raised(self):
        from pyoaev.signatures.types import SignatureTypes

        signature_compat.install()
        # Would raise ValueError on the stock enum; the shim passes it through.
        assert SignatureTypes("some_future_type").value == "some_future_type"  # noqa: S101


class TestSignatureNormalization:
    """DoD-1b: agentless/NetExec vocabulary is normalized onto canonical types."""

    def test_extract_normalizes_source_ipv4_alias(self):
        service = ElasticExpectationService(config=create_test_config())
        expectation = MockObjectsFactory.create_mock_expectation()
        expectation.inject_expectation_signatures = [_sig("source_ipv4", "10.0.0.1")]

        search, _matching = service._extract_signatures(expectation)

        types = [s["type"] for s in search]
        assert "source_ipv4_address" in types  # noqa: S101
        assert "source_ipv4" not in types  # noqa: S101

    def test_extract_normalizes_start_time_alias(self):
        service = ElasticExpectationService(config=create_test_config())
        expectation = MockObjectsFactory.create_mock_expectation()
        expectation.inject_expectation_signatures = [
            _sig("source_ipv4", "10.0.0.1"),
            _sig("start_time", "2026-01-01T00:00:00Z"),
        ]

        search, matching = service._extract_signatures(expectation)

        # start_time -> start_date is a search (window) signature, excluded from matching.
        assert any(s["type"] == "start_date" for s in search)  # noqa: S101
        assert all(s["type"] != "start_date" for s in matching)  # noqa: S101

    def test_only_unknown_signatures_leave_pending(self):
        """An expectation with no usable signature is skipped (pending), not graded."""
        service = ElasticExpectationService(config=create_test_config())
        helper = MockObjectsFactory.create_mock_detection_helper()
        expectation = MockObjectsFactory.create_mock_expectation(
            expectation_type="detection"
        )
        expectation.inject_expectation_signatures = [_sig("file_hash", "abc123")]
        # process_expectation dispatches on DetectionExpectation; drive the core
        # directly to assert the ungradable path raises rather than grading.
        import pytest

        with pytest.raises(ElasticUngradableError):
            service._handle_expectation(_as_detection(expectation), helper, "detection")


class TestTransientOutagePending:
    """DoD-2: transient outages leave the expectation pending, never 'Not Detected'."""

    def _service_and_exp(self):
        service = ElasticExpectationService(config=create_test_config())
        exp = MockObjectsFactory.create_mock_expectation(expectation_type="detection")
        return service, exp

    def test_api_error_leaves_pending(self):
        service, exp = self._service_and_exp()
        service.process_expectation = Mock(side_effect=ElasticAPIError("SIEM down"))
        results = service.handle_batch_expectations(
            [exp], MockObjectsFactory.create_mock_detection_helper()
        )
        assert results == []  # noqa: S101  omitted -> pending, re-served next cycle

    def test_network_error_leaves_pending(self):
        service, exp = self._service_and_exp()
        service.process_expectation = Mock(side_effect=ElasticNetworkError("reset"))
        results = service.handle_batch_expectations(
            [exp], MockObjectsFactory.create_mock_detection_helper()
        )
        assert results == []  # noqa: S101

    def test_auth_error_leaves_pending(self):
        service, exp = self._service_and_exp()
        service.process_expectation = Mock(side_effect=ElasticAuthenticationError("401"))
        results = service.handle_batch_expectations(
            [exp], MockObjectsFactory.create_mock_detection_helper()
        )
        assert results == []  # noqa: S101

    def test_no_match_still_graded_not_detected(self):
        """Regression guard: a successful query with no match is NOT skipped."""
        service, exp = self._service_and_exp()
        service.process_expectation = Mock(
            side_effect=ElasticNoMatchingAlertsError()
        )
        results = service.handle_batch_expectations(
            [exp], MockObjectsFactory.create_mock_detection_helper()
        )
        assert len(results) == 1  # noqa: S101
        assert results[0].is_valid is False  # noqa: S101  -> "Not Detected"

    def test_mixed_outage_and_success(self):
        service = ElasticExpectationService(config=create_test_config())
        good = MockObjectsFactory.create_mock_expectation(expectation_type="detection")
        bad = MockObjectsFactory.create_mock_expectation(expectation_type="detection")
        from src.collector.models import ExpectationResult

        def _dispatch(expectation, _helper):
            if expectation is bad:
                raise ElasticNetworkError("blip")
            return ExpectationResult(
                expectation_id=str(expectation.inject_expectation_id),
                is_valid=True,
                expectation=expectation,
            )

        service.process_expectation = Mock(side_effect=_dispatch)
        results = service.handle_batch_expectations(
            [bad, good], MockObjectsFactory.create_mock_detection_helper()
        )
        assert len(results) == 1  # noqa: S101  only the good one; bad left pending
        assert results[0].is_valid is True  # noqa: S101


class TestSiemOnlyDrilldownFallback:
    """DoD-3b: with no events index, implant expectations degrade to IP+time."""

    def _service(self, events_index):
        config = create_test_config()
        config.elastic.events_index = events_index
        return ElasticExpectationService(config=config)

    def test_endpoint_alert_rejected_when_drilldown_enabled(self):
        service = self._service("logs-endpoint.events.process-*")
        assert service.drilldown_enabled is True  # noqa: S101
        helper = MockObjectsFactory.create_mock_detection_helper(match_result=True)
        signatures = [{"type": "source_ipv4_address", "value": "192.0.2.10"}]
        data_item = {
            "source_ipv4_address": {"type": "simple", "data": ["192.0.2.10"]},
            "_endpoint_context": True,
        }
        assert not service._match_with_detection_helper(  # noqa: S101
            signatures, data_item, helper, expectation_expects_parent=True
        )

    def test_endpoint_alert_ip_fallback_when_no_events_index(self):
        service = self._service("")
        assert service.drilldown_enabled is False  # noqa: S101
        helper = MockObjectsFactory.create_mock_detection_helper(match_result=True)
        signatures = [{"type": "source_ipv4_address", "value": "192.0.2.10"}]
        data_item = {
            "source_ipv4_address": {"type": "simple", "data": ["192.0.2.10"]},
            "_endpoint_context": True,
        }
        assert service._match_with_detection_helper(  # noqa: S101
            signatures, data_item, helper, expectation_expects_parent=True
        )


def _as_detection(mock_exp):
    """Wrap a mock expectation so isinstance(DetectionExpectation) is not required
    by _handle_expectation (which takes the expectation directly)."""
    return mock_exp


class TestSecurityHardening:
    """SEC-1/2/3/5/6: hardening guards."""

    def test_lucene_values_escapes_metachars(self):
        from src.services.client_api import NO_MATCH_TOKEN, _lucene_values

        out = _lucene_values(['a"b', "c\\d"])
        assert '\\"' in out  # noqa: S101  quote escaped
        assert "\\\\" in out  # noqa: S101  backslash escaped
        assert _lucene_values([]) == NO_MATCH_TOKEN  # noqa: S101

    def test_verify_ssl_false_disables_verification(self):
        # Security control: verify=False is honored (a loud WARNING is also
        # emitted at init - verified manually; caplog is neutralized by conftest).
        config = create_test_config()
        config.elastic.verify_ssl = False
        config.elastic.ca_cert = None
        from src.services.client_api import ElasticClientAPI

        client = ElasticClientAPI(config=config)
        assert client.session.verify is False  # noqa: S101

    def test_ca_cert_overrides_verify(self):
        config = create_test_config()
        config.elastic.verify_ssl = False
        config.elastic.ca_cert = "/etc/ssl/my-ca.pem"
        from src.services.client_api import ElasticClientAPI

        client = ElasticClientAPI(config=config)
        assert client.session.verify == "/etc/ssl/my-ca.pem"  # noqa: S101

    def test_drilldown_cap_and_cache(self):
        from unittest.mock import patch

        from src.services.client_api import MAX_DRILLDOWN_ALERTS, ElasticClientAPI
        from src.services.models import ElasticAlert

        client = ElasticClientAPI(config=create_test_config())
        client.events_index = "logs-endpoint.events.process-*"
        alerts = [
            ElasticAlert(time="t", host_name=f"h{i}", pid=1000 + i)
            for i in range(MAX_DRILLDOWN_ALERTS + 5)
        ]
        with patch.object(
            client, "_fetch_source_event_marker", return_value=None
        ) as spy:
            client._enrich_alerts_with_source_events(alerts)
        assert spy.call_count == MAX_DRILLDOWN_ALERTS  # noqa: S101  fan-out capped

    def test_entity_id_marker_cached_and_reset(self):
        from unittest.mock import patch

        from src.services.client_api import ElasticClientAPI
        from src.services.models import ElasticAlert

        client = ElasticClientAPI(config=create_test_config())
        client.events_index = "logs-endpoint.events.process-*"
        # entity_id is reuse-safe -> cached across identical seeds within a cycle.
        same = [
            ElasticAlert(time="t", host_name="h", pid=42, process_entity_id="e1")
            for _ in range(3)
        ]
        with patch.object(
            client, "_fetch_source_event_marker", return_value="m"
        ) as spy:
            client._enrich_alerts_with_source_events(same)
            assert spy.call_count == 1  # noqa: S101  cached across identical seeds
            client.reset_marker_cache()
            client._enrich_alerts_with_source_events(same)
            assert spy.call_count == 2  # noqa: S101  re-drilled after reset

    def test_pid_only_seed_is_not_cached(self):
        """A pid can be reused within a cycle, so a pid-only seed must NOT be
        cached (avoids stale mis-attribution); each alert re-resolves."""
        from unittest.mock import patch

        from src.services.client_api import ElasticClientAPI
        from src.services.models import ElasticAlert

        client = ElasticClientAPI(config=create_test_config())
        client.events_index = "logs-endpoint.events.process-*"
        same = [ElasticAlert(time="t", host_name="h", pid=42) for _ in range(3)]
        with patch.object(
            client, "_fetch_source_event_marker", return_value="m"
        ) as spy:
            client._enrich_alerts_with_source_events(same)
            assert spy.call_count == 3  # noqa: S101  not cached: one drill per alert


class TestTraceLinkSafety:
    """SEC-5: an untrusted kibana.alert.url must not inject a rogue link."""

    def _trace(self, matching_data, config=None):
        from src.collector.models import ExpectationResult
        from src.services.trace_service import ElasticTraceService

        service = ElasticTraceService(config=config or create_test_config())
        result = ExpectationResult(
            expectation_id="e1", is_valid=True, expectation=None,
            matched_alerts=[matching_data],
        )
        return service.create_traces_from_results([result], "c")[0]

    def test_javascript_alert_url_rejected_falls_back(self):
        trace = self._trace(
            {
                "source_ipv4_address": {"data": "192.0.2.10"},
                "_alert_id": "abc-uuid",
                "_alert_url": "javascript:alert(document.cookie)",
            }
        )
        link = trace.inject_expectation_trace_alert_link
        assert "javascript:" not in link  # noqa: S101
        assert "/app/security/alerts" in link  # noqa: S101  collector-built fallback

    def test_https_alert_url_accepted_when_host_matches_elastic(self):
        # kibana_url unset: the alert host equals the Elastic host (co-located
        # Kibana), so the canonical link is trusted verbatim.
        config = create_test_config()
        config.elastic.kibana_url = None
        trace = self._trace(
            {
                "source_ipv4_address": {"data": "192.0.2.10"},
                "_alert_id": "abc-uuid",
                "_alert_url": "https://test-elastic.example.com:5601/app/security/alerts/redirect/abc",
            },
            config=config,
        )
        assert trace.inject_expectation_trace_alert_link.startswith(  # noqa: S101
            "https://test-elastic.example.com:5601/app/security/alerts/redirect/"
        )

    def test_rogue_host_falls_back_when_kibana_unset(self):
        # kibana_url unset and the alert host is not the Elastic host: it cannot
        # be verified as the real Kibana, so fall back to a collector-built link.
        config = create_test_config()
        config.elastic.kibana_url = None
        trace = self._trace(
            {
                "source_ipv4_address": {"data": "192.0.2.10"},
                "_alert_id": "abc-uuid",
                "_alert_url": "https://evil.example.com/phish?x=1",
            },
            config=config,
        )
        link = trace.inject_expectation_trace_alert_link
        assert "evil.example.com" not in link  # noqa: S101  rogue host neutralised
        assert "/app/security/alerts" in link  # noqa: S101  collector-built fallback

    def test_userinfo_stripped_from_alert_url(self):
        # Credentials embedded in the alert URL are never propagated into the link.
        config = create_test_config()
        config.elastic.kibana_url = None
        trace = self._trace(
            {
                "source_ipv4_address": {"data": "192.0.2.10"},
                "_alert_id": "abc-uuid",
                "_alert_url": "https://user:s3cr3t@test-elastic.example.com:5601/app/security/alerts/redirect/abc",
            },
            config=config,
        )
        link = trace.inject_expectation_trace_alert_link
        assert "s3cr3t" not in link  # noqa: S101  credentials stripped
        assert "@" not in link  # noqa: S101
        assert link.startswith(  # noqa: S101
            "https://test-elastic.example.com:5601/"
        )

    def test_rogue_host_with_userinfo_rebased_when_kibana_set(self):
        # kibana_url set: host/scheme are replaced (rogue host neutralised) and
        # only the path is kept.
        config = create_test_config()
        config.elastic.kibana_url = "https://kibana.internal:5601"
        trace = self._trace(
            {
                "source_ipv4_address": {"data": "192.0.2.10"},
                "_alert_id": "abc-uuid",
                "_alert_url": "https://user:s3cr3t@evil.example.com/app/security/alerts/redirect/abc",
            },
            config=config,
        )
        link = trace.inject_expectation_trace_alert_link
        assert link.startswith("https://kibana.internal:5601/")  # noqa: S101
        assert "evil.example.com" not in link  # noqa: S101
        assert "s3cr3t" not in link  # noqa: S101


class TestEventsIndexDrilldownAuthz:
    """BLOCKER (product/staff §3): a 401/403/404 on the events index must surface
    (leaving the expectation pending), never silently recover no marker and
    downgrade an implant inject to a false 'Not Detected'. Transient errors still
    return [] so the outer retry loop re-drills."""

    def _client(self):
        from src.services.client_api import ElasticClientAPI

        client = ElasticClientAPI(config=create_test_config())
        client.events_index = "logs-endpoint.events.process-*"
        return client

    def test_events_index_403_raises_auth_error(self):
        import pytest
        from unittest.mock import Mock, patch

        client = self._client()
        with patch.object(client.session, "post", return_value=Mock(status_code=403)):
            with pytest.raises(ElasticAuthenticationError):
                client._fetch_process_events(
                    {"term": {"process.pid": 1}}, "host-1", 900
                )

    def test_events_index_401_raises_auth_error(self):
        import pytest
        from unittest.mock import Mock, patch

        client = self._client()
        with patch.object(client.session, "post", return_value=Mock(status_code=401)):
            with pytest.raises(ElasticAuthenticationError):
                client._fetch_process_events(
                    {"term": {"process.pid": 1}}, "host-1", 900
                )

    def test_events_index_404_raises_api_error(self):
        import pytest
        from unittest.mock import Mock, patch

        client = self._client()
        with patch.object(client.session, "post", return_value=Mock(status_code=404)):
            with pytest.raises(ElasticAPIError):
                client._fetch_process_events(
                    {"term": {"process.pid": 1}}, "host-1", 900
                )

    def test_events_index_transient_500_returns_empty(self):
        from unittest.mock import Mock, patch

        client = self._client()
        with patch.object(client.session, "post", return_value=Mock(status_code=500)):
            assert (  # noqa: S101  transient -> swallowed, retry loop re-drills
                client._fetch_process_events({"term": {"process.pid": 1}}, "host-1", 900)
                == []
            )

    def test_enrich_propagates_events_index_403(self):
        """A 403 during enrichment propagates out of the alert fetch so the whole
        expectation is left pending rather than graded on markerless alerts."""
        import pytest
        from unittest.mock import Mock, patch

        from src.services.models import ElasticAlert

        client = self._client()
        alert = ElasticAlert(time="t", host_name="host-1", pid=99)
        with patch.object(client.session, "post", return_value=Mock(status_code=403)):
            with pytest.raises(ElasticAuthenticationError):
                client._enrich_alerts_with_source_events([alert])
