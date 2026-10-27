"""The daemon: registered as the scenarios collector, it runs the collection at each period."""

import pytest

from scenarios.configuration.config_loader import ConfigLoader
from scenarios.openaev_scenarios import OpenAEVScenarios
from scenarios.platform import PlatformSink
from scenarios.run import DryRunSink

TENANT = "2b0f1c4e-6a7d-4e8f-9a1b-3c5d7e9f0a2b"


def _daemon(monkeypatch: pytest.MonkeyPatch, **extra: str) -> OpenAEVScenarios:
    monkeypatch.chdir("/")
    for name, value in {
        "OPENAEV_URL": "http://openaev:8080",
        "OPENAEV_TOKEN": "openaev-token",
        "COLLECTOR_ID": "scenarios--0b5c1a6e-4f0e-4b8e-9d2a-1c3e5f7a9b0d",
        "COLLECTOR_NAME": "OpenAEV Scenarios",
        **extra,
    }.items():
        monkeypatch.setenv(name, value)
    return OpenAEVScenarios(configuration=ConfigLoader().to_daemon_config())


def test_the_daemon_runs_the_collection_dry(monkeypatch: pytest.MonkeyPatch) -> None:
    daemon = _daemon(monkeypatch)
    runs: list[str] = []
    monkeypatch.setattr(daemon._collect, "run", lambda: runs.append("run"))

    daemon._process_message()

    assert runs == ["run"]
    assert daemon.collector_type == "openaev_scenarios"
    assert isinstance(daemon._collect.sink, DryRunSink)


@pytest.mark.parametrize(
    ("tenant", "path"),
    [
        ({}, "/api/catalog/sync"),
        ({"OPENAEV_TENANT_ID": TENANT}, f"/api/tenants/{TENANT}/catalog/sync"),
    ],
)
def test_out_of_dry_run_the_daemon_sends_to_the_platform_s_catalogue(
    monkeypatch: pytest.MonkeyPatch, tenant: dict[str, str], path: str
) -> None:
    daemon = _daemon(monkeypatch, SCENARIOS_DRY_RUN="false", **tenant)

    sink = daemon._collect.sink
    assert isinstance(sink, PlatformSink)
    assert sink._url == f"http://openaev:8080{path}"
