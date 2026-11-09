"""Endpoint alerts whose host has no process telemetry in the events index.

A SIEM fed by the Windows Security channel (System integration) keeps its
process events in ``logs-system.security-*``. With an events index that does
not cover the host, the implant marker can never be recovered, so its endpoint
alerts must fall back to IP + time instead of being rejected.
"""

import re
from pathlib import Path
from unittest.mock import Mock, patch

from src.services.client_api import DEFAULT_QUERY_TEMPLATE, ElasticClientAPI
from src.services.converter import Converter
from src.services.expectation_service import ElasticExpectationService
from src.services.models import ElasticAlert, ElasticResponse
from tests.services.fixtures.factories import (
    MockObjectsFactory,
    create_test_config,
)

MARKER = (
    "oaev-implant-12345678-1234-1234-1234-123456789abc"
    "-agent-87654321-4321-4321-4321-cba987654321"
)
ELASTIC_DIR = Path(__file__).resolve().parents[2]

# Shaped like a real alert: a custom query rule on Windows Security event 4689
# (process exit) shipped by the System integration. No entity_id, no parent.
WINDOWS_SECURITY_HIT = {
    "_id": "alert-0001",
    "_source": {
        "@timestamp": "2026-11-09T09:00:31.153Z",
        "kibana.alert.rule.name": "Certutil or Bitsadmin execution",
        "kibana.alert.uuid": "alert-0001",
        "host": {"name": "win-ws01", "ip": ["192.0.2.58", "fe80::1"]},
        "process": {
            "executable": "C:\\Windows\\System32\\certutil.exe",
            "name": "certutil.exe",
            "pid": 33132,
        },
        "event": {"action": "exited-process", "code": "4689"},
    },
}


def _response(hits: list) -> Mock:
    response = Mock()
    response.status_code = 200
    response.json.return_value = {"hits": {"hits": hits}}
    return response


def _client() -> ElasticClientAPI:
    client = ElasticClientAPI(config=create_test_config())
    client.events_index = "logs-endpoint.events.process-*"
    return client


class TestHostProcessTelemetryProbe:
    """The drilldown records whether the host's process events are indexed."""

    def test_no_marker_and_no_telemetry_is_flagged(self):
        client = _client()
        alert = ElasticAlert(time="2026-11-09T09:00:31Z", host_name="h", pid=42)
        with (
            patch.object(client, "_fetch_source_event_marker", return_value=None),
            patch.object(client, "_events_search", return_value=[]) as search,
        ):
            client._enrich_alerts_with_source_events([alert])
        assert alert.host_has_process_telemetry is False  # noqa: S101
        body = search.call_args.args[0]
        filters = body["query"]["bool"]["filter"]
        assert {"term": {"event.type": "start"}} in filters  # noqa: S101
        assert {"term": {"host.name": "h"}} in filters  # noqa: S101

    def test_no_marker_with_telemetry_is_flagged_true(self):
        client = _client()
        alert = ElasticAlert(time="t", host_name="h", pid=42)
        with (
            patch.object(client, "_fetch_source_event_marker", return_value=None),
            patch.object(client, "_events_search", return_value=[{"_id": "e"}]),
        ):
            client._enrich_alerts_with_source_events([alert])
        assert alert.host_has_process_telemetry is True  # noqa: S101

    def test_recovered_marker_skips_the_probe(self):
        client = _client()
        alert = ElasticAlert(time="t", host_name="h", pid=42)
        with (
            patch.object(client, "_fetch_source_event_marker", return_value=MARKER),
            patch.object(client, "_host_has_process_telemetry") as probe,
        ):
            client._enrich_alerts_with_source_events([alert])
        probe.assert_not_called()
        assert alert.host_has_process_telemetry is None  # noqa: S101

    def test_probe_is_cached_per_host_and_reset(self):
        client = _client()
        alerts = [ElasticAlert(time="t", host_name="h", pid=40 + i) for i in range(3)]
        with (
            patch.object(client, "_fetch_source_event_marker", return_value=None),
            patch.object(client, "_events_search", return_value=[]) as search,
        ):
            client._enrich_alerts_with_source_events(alerts)
            assert search.call_count == 1  # noqa: S101  one probe for the host
            client.reset_marker_cache()
            client._enrich_alerts_with_source_events(alerts[:1])
            assert search.call_count == 2  # noqa: S101  re-probed after reset

    def test_no_probe_without_events_index(self):
        client = _client()
        client.events_index = None
        alert = ElasticAlert(time="t", host_name="h", pid=42)
        with patch.object(client, "_events_search") as search:
            client._enrich_alerts_with_source_events([alert])
        search.assert_not_called()
        assert alert.host_has_process_telemetry is None  # noqa: S101


class TestMissingSeedFallsBackToHostMarker:
    """A seed missing from the events index still tries the host fallback."""

    @patch("requests.Session.post")
    def test_missing_seed_uses_unique_host_implant(self, mock_post):
        client = _client()
        implant = {"_source": {"process": {"name": f"{MARKER}.exe"}}}
        mock_post.side_effect = [_response([]), _response([implant])]

        marker = client._fetch_source_event_marker(
            "h", 4242, None, "2026-11-09T09:00:31Z"
        )

        assert marker == MARKER  # noqa: S101
        fallback_body = mock_post.call_args_list[1].kwargs["json"]
        assert "oaev-implant-*" in str(fallback_body)  # noqa: S101


class TestConverterMarkerRecoverable:
    """The converter exposes whether a missing marker is meaningful."""

    def test_flag_follows_probe(self):
        converter = Converter()
        base = {"time": "t", "host_name": "h", "pid": 1, "host_ips": ["10.0.0.5"]}
        blind = converter.convert_data_to_oaev_data(
            [ElasticAlert(**base, host_has_process_telemetry=False)]
        )[0]
        seen = converter.convert_data_to_oaev_data(
            [ElasticAlert(**base, host_has_process_telemetry=True)]
        )[0]
        unknown = converter.convert_data_to_oaev_data([ElasticAlert(**base)])[0]
        assert blind["_marker_recoverable"] is False  # noqa: S101
        assert seen["_marker_recoverable"] is True  # noqa: S101
        assert unknown["_marker_recoverable"] is True  # noqa: S101


class TestWindowsSecurityAlertMatching:
    """End to end: a Windows Security alert is credited on IP + time."""

    def _match(self, telemetry_hits: list) -> bool:
        service = ElasticExpectationService(config=create_test_config())
        assert service.drilldown_enabled is True  # noqa: S101  default index
        alert = ElasticResponse.from_raw_response(
            {"hits": {"hits": [WINDOWS_SECURITY_HIT]}}
        ).results[0]
        with patch.object(
            service.client_api, "_events_search", return_value=telemetry_hits
        ):
            service.client_api._enrich_alerts_with_source_events([alert])
        oaev_data = service.converter.convert_data_to_oaev_data([alert])
        signatures = [
            {"type": "parent_process_name", "value": MARKER},
            {"type": "source_ipv4_address", "value": "192.0.2.58"},
        ]
        helper = MockObjectsFactory.create_mock_detection_helper(match_result=True)
        return service._any_match(oaev_data, signatures, helper)

    def test_host_without_process_telemetry_matches_on_ip(self):
        assert self._match([]) is True  # noqa: S101

    def test_host_with_process_telemetry_but_no_marker_is_rejected(self):
        # The host's process creations are indexed and none leads to this
        # inject's implant: the alert is unrelated, never credited on IP.
        assert (
            self._match([{"_source": {"process": {"name": "x"}}}]) is False
        )  # noqa: S101

    def test_default_events_index_covers_windows_security(self):
        assert "logs-system.security-*" in (  # noqa: S101
            create_test_config().elastic.events_index or ""
        )


class TestEventsIndexStartupCheck:
    """check_connectivity reports an events index without process creations."""

    def _client_with(self, events_response: Mock) -> ElasticClientAPI:
        client = _client()
        alerts_count = Mock(status_code=200)
        alerts_count.json.return_value = {"count": 3}
        client.session = Mock()
        client.session.get.return_value = alerts_count
        client.session.post.return_value = events_response
        return client

    def test_empty_events_index_warns_but_stays_connected(self):
        empty = Mock(status_code=200)
        empty.json.return_value = {"count": 0}
        client = self._client_with(empty)
        with patch.object(client.logger, "warning") as warning:
            assert client.check_connectivity() is True  # noqa: S101
        assert "No process-creation event" in warning.call_args.args[0]  # noqa: S101
        url = client.session.post.call_args.args[0]
        assert url.endswith("/logs-endpoint.events.process-*/_count")  # noqa: S101

    def test_events_index_error_warns(self):
        client = self._client_with(Mock(status_code=403))
        with patch.object(client.logger, "warning") as warning:
            assert client.check_connectivity() is True  # noqa: S101
        assert "answered 403" in warning.call_args.args[0]  # noqa: S101

    def test_populated_events_index_does_not_warn(self):
        populated = Mock(status_code=200)
        populated.json.return_value = {"count": 12}
        client = self._client_with(populated)
        with patch.object(client.logger, "warning") as warning:
            assert client.check_connectivity() is True  # noqa: S101
        warning.assert_not_called()

    def test_no_events_index_skips_the_check(self):
        client = self._client_with(Mock())
        client.events_index = None
        assert client.check_connectivity() is True  # noqa: S101
        client.session.post.assert_not_called()


class TestDocumentedDefaultQuery:
    """The samples and the README show the exact built-in query."""

    def test_samples_and_readme_show_the_default_query(self):
        default = " ".join(DEFAULT_QUERY_TEMPLATE.split())
        env = (ELASTIC_DIR / "src" / ".env.sample").read_text()
        yml = (ELASTIC_DIR / "src" / "config.yml.sample").read_text()
        readme = (ELASTIC_DIR / "README.md").read_text()
        assert f"# ELASTIC_QUERY_TEMPLATE={default}\n" in env  # noqa: S101
        assert f"# query_template: '{default}'\n" in yml  # noqa: S101
        block = re.search(r"Built-in default query.*?```\n(.*?)```", readme, re.S)
        assert block is not None  # noqa: S101
        assert " ".join(block.group(1).split()) == default  # noqa: S101
