"""The daemon: registered as the scenarios collector, it runs the collection at each period."""

import pytest

from scenarios.configuration.config_loader import ConfigLoader
from scenarios.openaev_scenarios import OpenAEVScenarios
from scenarios.run import DryRunSink


def test_the_daemon_runs_the_collection_dry(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir("/")
    for name, value in {
        "OPENAEV_URL": "http://openaev:8080",
        "OPENAEV_TOKEN": "openaev-token",
        "COLLECTOR_ID": "scenarios--0b5c1a6e-4f0e-4b8e-9d2a-1c3e5f7a9b0d",
        "COLLECTOR_NAME": "OpenAEV Scenarios",
    }.items():
        monkeypatch.setenv(name, value)
    daemon = OpenAEVScenarios(configuration=ConfigLoader().to_daemon_config())
    runs: list[str] = []
    monkeypatch.setattr(daemon._collect, "run", lambda: runs.append("run"))

    daemon._process_message()

    assert runs == ["run"]
    assert daemon.collector_type == "openaev_scenarios"
    assert isinstance(daemon._collect.sink, DryRunSink)
