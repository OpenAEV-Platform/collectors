import sys
import types
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import MagicMock, patch

from pydantic import BaseModel


def _install_pyoaev_stub():
    if "pyoaev.daemons" in sys.modules:
        return

    pyoaev = types.ModuleType("pyoaev")
    pyoaev.__path__ = []
    configuration = types.ModuleType("pyoaev.configuration")
    daemons = types.ModuleType("pyoaev.daemons")
    helpers = types.ModuleType("pyoaev.helpers")

    class Configuration:
        def get(self, key):
            return None

    class ConfigLoaderCollector(BaseModel):
        pass

    class ConfigLoaderOAEV(BaseModel):
        pass

    class SettingsLoader(BaseModel):
        pass

    class CollectorDaemon:
        pass

    class OpenAEVDetectionHelper:
        def __init__(self, *args, **kwargs):
            return None

    configuration.Configuration = Configuration
    configuration.ConfigLoaderCollector = ConfigLoaderCollector
    configuration.ConfigLoaderOAEV = ConfigLoaderOAEV
    configuration.SettingsLoader = SettingsLoader
    daemons.CollectorDaemon = CollectorDaemon
    helpers.OpenAEVDetectionHelper = OpenAEVDetectionHelper

    sys.modules["pyoaev"] = pyoaev
    sys.modules["pyoaev.configuration"] = configuration
    sys.modules["pyoaev.daemons"] = daemons
    sys.modules["pyoaev.helpers"] = helpers


with patch.dict(sys.modules):
    _install_pyoaev_stub()
    from tanium_threat_response import api_handler
    from tanium_threat_response.openaev_tanium_threat_response import (
        OpenAEVTaniumThreatResponse,
    )


class _Logger:
    def __init__(self):
        self.errors = []

    def info(self, message):
        return None

    def debug(self, message):
        return None

    def error(self, message):
        self.errors.append(message)


class _Config:
    def __init__(self, values):
        self.values = values

    def get(self, key):
        return self.values.get(key)


def _collector(query_result):
    collector = OpenAEVTaniumThreatResponse.__new__(OpenAEVTaniumThreatResponse)
    collector.logger = _Logger()
    collector.scanning_delta = 45
    collector._configuration = _Config(
        {"collector_id": "col-1", "tanium_url_console": "https://tanium.example"}
    )
    collector.tanium_api_handler = SimpleNamespace(
        _query=lambda *args, **kwargs: query_result
    )
    updates = []
    traces = []

    def update(expectation_id, data):
        updates.append((expectation_id, data))

    def bulk_create(payload):
        traces.append(payload)

    collector.api = SimpleNamespace(
        inject_expectation=SimpleNamespace(
            detection_expectations_for_source=lambda *args, **kwargs: [
                {
                    "inject_expectation_id": "exp-1",
                    "inject_expectation_inject": "inj-1",
                    "inject_expectation_type": "DETECTION",
                    "inject_expectation_created_at": "2020-01-01T00:00:00Z",
                    "inject_expectation_results": [],
                }
            ],
            update=update,
        ),
        inject_expectation_trace=SimpleNamespace(bulk_create=bulk_create),
    )
    return collector, updates, traces


class NoneResponseTest(TestCase):
    def test_missing_alerts_still_fails_expired_expectation(self):
        collector, updates, traces = _collector(None)

        collector._process_message()

        self.assertEqual(
            updates,
            [
                (
                    "exp-1",
                    {
                        "collector_id": "col-1",
                        "result": "Not Detected",
                        "is_success": False,
                    },
                )
            ],
        )
        self.assertEqual(traces, [{"expectation_traces": []}])

    def test_missing_intel_keeps_alert_guid(self):
        collector, _, _ = _collector(None)

        name = collector._extract_alert_name(
            {"guid": "alert-guid"},
            {"intel_id": "42"},
        )

        self.assertEqual(name, "alert-guid")

    def test_intel_type_is_used_when_present(self):
        collector, _, _ = _collector({"type": "Suspicious Process"})

        name = collector._extract_alert_name(
            {"guid": "alert-guid"},
            {"intel_id": "42"},
        )

        self.assertEqual(name, "Suspicious Process")

    def test_query_without_data_returns_none(self):
        logger = _Logger()
        handler = api_handler.TaniumApiHandler(
            logger, "https://tanium.example", "token"
        )
        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {"data": None}
        response.text = '{"data": null}'

        def fake_get(*args, **kwargs):
            return response

        original = api_handler.requests.get
        api_handler.requests.get = fake_get
        try:
            result = handler._query("get", "/plugin/products/threat-response/api/v1/alerts")
        finally:
            api_handler.requests.get = original

        self.assertIsNone(result)
        self.assertTrue(logger.errors)
