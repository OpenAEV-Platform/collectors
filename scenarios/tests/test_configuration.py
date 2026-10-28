"""The settings of the collector, from the environment, as the other collectors read theirs."""

from typing import Any

import pytest
from pydantic import ValidationError

from scenarios.configuration.config_loader import ConfigLoader

BASE = {
    "OPENAEV_URL": "http://openaev:8080",
    "OPENAEV_TOKEN": "openaev-token",
    "COLLECTOR_ID": "scenarios--0b5c1a6e-4f0e-4b8e-9d2a-1c3e5f7a9b0d",
    "COLLECTOR_NAME": "OpenAEV Scenarios",
}


def _config(monkeypatch: pytest.MonkeyPatch, **extra: str) -> Any:
    monkeypatch.chdir("/")  # no config.yml nor .env around
    for name, value in {**BASE, **extra}.items():
        monkeypatch.setenv(name, value)
    return ConfigLoader().to_daemon_config()


def test_the_defaults_follow_edge_of_the_repository_every_hour(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(monkeypatch)

    assert config.get("scenarios_repository") == "OpenAEV-Platform/scenarios"
    assert config.get("scenarios_channel") == "edge"
    assert config.get("scenarios_github_api_url") == "https://api.github.com"
    assert config.get("scenarios_github_token") is None
    assert config.get("collector_period") == 3600
    assert config.get("scenarios_dry_run") is True


def test_the_source_is_set_from_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(
        monkeypatch,
        SCENARIOS_REPOSITORY="someone/catalogue",
        SCENARIOS_CHANNEL="stable",
        SCENARIOS_GITHUB_TOKEN="github-token",
    )

    assert config.get("scenarios_repository") == "someone/catalogue"
    assert config.get("scenarios_channel") == "stable"
    assert config.get("scenarios_github_token") == "github-token"


def test_the_token_is_never_shown_with_the_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir("/")
    for name, value in {**BASE, "SCENARIOS_GITHUB_TOKEN": "github-token"}.items():
        monkeypatch.setenv(name, value)

    assert "github-token" not in repr(ConfigLoader().scenarios)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("SCENARIOS_CHANNEL", "nightly"),
        ("SCENARIOS_REPOSITORY", "no-owner"),
        ("SCENARIOS_REPOSITORY", "owner/.."),
        ("SCENARIOS_GITHUB_API_URL", "http://api.github.com"),
    ],
)
def test_a_setting_out_of_its_values_is_refused(
    monkeypatch: pytest.MonkeyPatch, name: str, value: str
) -> None:
    with pytest.raises(ValidationError):
        _config(monkeypatch, **{name: value})


@pytest.mark.parametrize(("given", "dry"), [("false", False), ("true", True)])
def test_the_dry_run_is_set_from_the_environment(
    monkeypatch: pytest.MonkeyPatch, given: str, dry: bool
) -> None:
    assert _config(monkeypatch, SCENARIOS_DRY_RUN=given).get("scenarios_dry_run") is dry


@pytest.mark.parametrize("given", ["", "maybe", "sometimes"])
def test_a_dry_run_neither_true_nor_false_is_refused(
    monkeypatch: pytest.MonkeyPatch, given: str
) -> None:
    with pytest.raises(ValidationError):
        _config(monkeypatch, SCENARIOS_DRY_RUN=given)
