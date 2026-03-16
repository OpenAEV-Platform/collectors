import asyncio
import json
import sys
import types
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock


def _install_dependency_stubs() -> None:
    """Install lightweight stubs for optional runtime deps used by the collector module."""

    def ensure_module(name: str) -> types.ModuleType:
        module = sys.modules.get(name)
        if module is None:
            module = types.ModuleType(name)
            sys.modules[name] = module
        return module

    ensure_module("azure")
    ensure_module("azure.identity")
    azure_identity_aio = ensure_module("azure.identity.aio")

    class ClientSecretCredential:  # pragma: no cover - import-time fallback only
        def __init__(self, *args, **kwargs):
            pass

    azure_identity_aio.ClientSecretCredential = ClientSecretCredential

    msgraph_module = ensure_module("msgraph")

    class GraphServiceClient:  # pragma: no cover - import-time fallback only
        def __init__(self, *args, **kwargs):
            pass

    msgraph_module.GraphServiceClient = GraphServiceClient

    ensure_module("msgraph.generated")
    ensure_module("msgraph.generated.security")
    ensure_module(
        "msgraph.generated.security.microsoft_graph_security_run_hunting_query"
    )
    request_body_module = ensure_module(
        "msgraph.generated.security.microsoft_graph_security_run_hunting_query."
        "run_hunting_query_post_request_body"
    )

    class RunHuntingQueryPostRequestBody:
        def __init__(self, query: str, timespan: str):
            self.query = query
            self.timespan = timespan

    request_body_module.RunHuntingQueryPostRequestBody = RunHuntingQueryPostRequestBody

    ensure_module("pyoaev")
    configuration_module = ensure_module("pyoaev.configuration")
    daemons_module = ensure_module("pyoaev.daemons")
    helpers_module = ensure_module("pyoaev.helpers")

    class Configuration:  # pragma: no cover - import-time fallback only
        pass

    class CollectorDaemon:  # pragma: no cover - import-time fallback only
        def __init__(self, *args, **kwargs):
            pass

    class OpenAEVDetectionHelper:  # pragma: no cover - import-time fallback only
        def __init__(self, *args, **kwargs):
            pass

    configuration_module.Configuration = Configuration
    daemons_module.CollectorDaemon = CollectorDaemon
    helpers_module.OpenAEVDetectionHelper = OpenAEVDetectionHelper


try:
    from microsoft_defender.openaev_microsoft_defender import (
        TH_API_QUERY,
        OpenAEVMicrosoftDefender,
    )
except ModuleNotFoundError:
    _install_dependency_stubs()
    from microsoft_defender.openaev_microsoft_defender import (
        TH_API_QUERY,
        OpenAEVMicrosoftDefender,
    )


def test_process_alerts_updates_detection_and_creates_trace():
    collector = OpenAEVMicrosoftDefender.__new__(OpenAEVMicrosoftDefender)
    collector.logger = MagicMock()
    collector.scanning_delta = 45
    collector.microsoft_defender_alert_details_url = (
        "https://security.microsoft.com/alerts/"
    )
    collector._configuration = MagicMock()
    collector._configuration.get.return_value = "collector-id"

    expectation = {
        "inject_expectation_id": "exp-1",
        "inject_expectation_asset": "host-1",
        "inject_expectation_created_at": datetime.now(timezone.utc).isoformat(),
        "inject_expectation_inject": "inject-1",
        "inject_expectation_type": "DETECTION",
        "inject_expectation_signatures": [
            {"type": "process_name", "value": "powershell.exe"}
        ],
    }

    collector.api = MagicMock()
    collector.api.inject_expectation.expectations_assets_for_source.return_value = [
        expectation
    ]
    collector._match_alert = MagicMock(return_value="DETECTED")

    evidence_payload = {
        "EntityType": "Process",
        "FirstActivityTimestamp": "2026-03-09T21:07:37.3225955Z",
        "LastActivityTimestamp": "2026-03-09T21:07:56.8069713Z",
        "Title": "PowerSploit post-exploitation tool",
        "Identifier": "powershell.exe",
        "LastRemediationState": "Blocked",
        "DetectionStatus": "Blocked",
        "ParentProcessImageFileName": "oaev-implant-2cbb7baa-326f-4755-9e10-506f84daa8e3-agent-7d6e652c-4365-479f-af5d-fffb1d7b3292.exe",
        "CommandLine": '"powershell" -ExecutionPolicy Bypass',
    }

    alert_result = SimpleNamespace(
        additional_data={
            "AlertId": "da639086874138071342_-1566804818",
            "DeviceName": "castelblack.north.sevenkingdoms.local",
            "evidence": [json.dumps(evidence_payload)],
        }
    )

    post_mock = AsyncMock(return_value=SimpleNamespace(results=[alert_result]))
    graph_client = SimpleNamespace(
        security=SimpleNamespace(
            microsoft_graph_security_run_hunting_query=SimpleNamespace(post=post_mock)
        )
    )

    asyncio.run(collector._process_alerts(graph_client))

    collector.api.inject_expectation.update.assert_called_once()
    update_args = collector.api.inject_expectation.update.call_args.args
    assert update_args[0] == "exp-1"
    assert update_args[1]["result"] == "Detected"
    assert update_args[1]["is_success"] is True
    assert update_args[1]["metadata"]["alertId"] == "da639086874138071342_-1566804818"

    collector.api.inject_expectation_trace.create.assert_called_once()
    trace_payload = collector.api.inject_expectation_trace.create.call_args.kwargs[
        "data"
    ]
    assert (
        trace_payload["inject_expectation_trace_alert_name"]
        == "PowerSploit post-exploitation tool"
    )
    assert (
        trace_payload["inject_expectation_trace_alert_link"]
        == "https://security.microsoft.com/alerts/da639086874138071342_-1566804818"
    )

    post_mock.assert_awaited_once()
    request_body = post_mock.await_args.kwargs["body"]
    assert request_body.query == TH_API_QUERY
    assert request_body.timespan
