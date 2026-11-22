"""Tests of the configuration, the asset payload and a full collector run."""

from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from github_collector import openaev_github
from github_collector.configuration.collector_config_override import (
    CollectorConfigOverride,
)
from github_collector.configuration.config_loader import ConfigLoader
from github_collector.inventory import repository_asset
from github_collector.openaev_github import OpenAEVGitHub, build_asset, tag_color
from tests.fixtures import REPOSITORIES, FakeClient

REQUIRED = {"github_token": "t", "github_organizations": "acme"}


def test_defaults():
    config = CollectorConfigOverride(**REQUIRED)
    assert config.id == "openaev_github"
    assert config.period.total_seconds() == 6 * 3600
    assert config.github_api_url == "https://api.github.com"
    assert config.github_include_archived is True
    assert config.github_include_forks is False
    assert config.github_collect_workflows is True
    assert config.github_collect_packages is True
    assert config.github_end_date_removed is True


@pytest.mark.parametrize(
    ("values", "message"),
    [
        ({"github_organizations": "acme"}, "github_token is required"),
        ({"github_token": "t"}, "at least one owner"),
        ({**REQUIRED, "github_api_url": "github.example.com"}, "http"),
        ({**REQUIRED, "github_package_types": "npm,pypi"}, "unknown GitHub package"),
    ],
)
def test_invalid_configuration_is_refused(values, message):
    with pytest.raises(ValidationError, match=message):
        CollectorConfigOverride(**values)


def test_enterprise_url_loses_its_trailing_slash():
    config = CollectorConfigOverride(
        **REQUIRED, github_api_url="https://github.example.com/api/v3/"
    )
    assert config.github_api_url == "https://github.example.com/api/v3"


def test_environment_variables_reach_the_daemon_configuration(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    for name, value in {
        "OPENAEV_URL": "http://openaev:8080",
        "OPENAEV_TOKEN": "token",
        "COLLECTOR_ID": "c1",
        "COLLECTOR_GITHUB_TOKEN": "ghp",
        "COLLECTOR_GITHUB_USERS": "octocat",
        "COLLECTOR_GITHUB_INCLUDE_FORKS": "true",
    }.items():
        monkeypatch.setenv(name, value)
    configuration = ConfigLoader().to_daemon_config()
    assert configuration.get("github_token") == "ghp"
    assert configuration.get("github_users") == "octocat"
    # pyoaev's Configuration returns booleans as 0 / 1.
    assert bool(configuration.get("github_include_forks")) is True
    assert bool(configuration.get("github_collect_workflows")) is True


def test_build_asset_payload():
    asset = repository_asset(REPOSITORIES[0], "github.com")
    payload = build_asset(asset, ["t1"])
    assert payload["asset_category"] == "SOURCE_CODE"
    assert payload["asset_subcategory"] == "CODE_REPOSITORY"
    assert payload["asset_external_reference"] == "github:repository:R_api"
    assert payload["asset_url"] == "https://github.com/acme/api"
    assert payload["asset_internet_facing"] is True
    assert payload["asset_tags"] == ["t1"]
    # No platform or architecture: OpenAEV keeps its Unknown default for this category.
    assert "endpoint_platform" not in payload
    assert "endpoint_arch" not in payload
    assert payload["asset_metadata"]["github_node_id"] == "R_api"


def test_tag_colors_come_from_the_prefix():
    assert tag_color("source:github") == "#24292f"
    assert tag_color("unknown:x") == "#6b7280"


def _daemon(values, known=None, overviews=None):
    configuration = MagicMock()
    configuration.get.side_effect = values.get

    def fake_init(self, *args, **kwargs):
        self._configuration = configuration
        self.logger = MagicMock()
        self.api = MagicMock()

    with patch.object(openaev_github.CollectorDaemon, "__init__", fake_init):
        daemon = OpenAEVGitHub(configuration=configuration)
    daemon.client = FakeClient()
    daemon.api.tag.upsert.side_effect = lambda data: {
        "tag_id": f"id-{data['tag_name']}"
    }
    daemon.api.http_post.return_value = {"content": known or [], "last": True}
    daemon.api.http_get.side_effect = lambda path: (overviews or {}).get(path, {})
    return daemon


BASE = {
    "github_token": "t",
    "github_organizations": "acme",
    "github_include_archived": True,
    "github_include_forks": False,
    "github_collect_workflows": True,
    "github_collect_packages": True,
    "github_package_types": "npm",
    "github_end_date_removed": True,
}


def test_a_run_upserts_repositories_workflows_and_packages():
    daemon = _daemon(BASE)
    daemon._process_message()
    payloads = [c.args[0] for c in daemon.api.endpoint.upsert.call_args_list]
    assert sorted(p["asset_external_reference"] for p in payloads) == [
        "github:package:77",
        "github:repository:R_api",
        "github:repository:R_legacy",
        "github:workflow:W_ci",
    ]
    assert {p["asset_category"] for p in payloads} == {"SOURCE_CODE"}
    api = next(p for p in payloads if p["asset_name"] == "acme/api")
    assert "id-source:github" in api["asset_tags"]
    tag_calls = [c.args[0]["tag_name"] for c in daemon.api.tag.upsert.call_args_list]
    assert tag_calls.count("source:github") == 1


def test_a_repository_gone_from_github_is_end_dated_not_deleted():
    known = [
        {
            "asset_id": "a1",
            "asset_name": "acme/removed",
            "asset_external_reference": "github:repository:R_removed",
        },
        {
            "asset_id": "a2",
            "asset_name": "acme/api",
            "asset_external_reference": "github:repository:R_api",
        },
    ]
    overviews = {"/assets/a1": {"asset_metadata": {"github_state": "active"}}}
    daemon = _daemon(BASE, known=known, overviews=overviews)
    daemon._process_message()
    payloads = [c.args[0] for c in daemon.api.endpoint.upsert.call_args_list]
    [ended] = [
        p
        for p in payloads
        if p["asset_external_reference"] == "github:repository:R_removed"
    ]
    assert ended["asset_metadata"]["github_state"] == "deleted"
    assert "github_end_date" in ended["asset_metadata"]
    assert ended["asset_tags"] == ["id-github-state:deleted"]
    # Nothing is ever deleted.
    assert not daemon.api.endpoint.delete.called
    assert not daemon.api.http_delete.called
    search = daemon.api.http_post.call_args.kwargs["post_data"]
    filters = search["filterGroup"]["filters"]
    assert {
        "key": "asset_category",
        "mode": "or",
        "operator": "eq",
        "values": ["SOURCE_CODE"],
    } in filters


def test_an_already_end_dated_asset_is_left_alone():
    known = [
        {
            "asset_id": "a1",
            "asset_name": "acme/removed",
            "asset_external_reference": "github:repository:R_removed",
        }
    ]
    overviews = {"/assets/a1": {"asset_metadata": {"github_state": "deleted"}}}
    daemon = _daemon(BASE, known=known, overviews=overviews)
    daemon._process_message()
    refs = [
        c.args[0]["asset_external_reference"]
        for c in daemon.api.endpoint.upsert.call_args_list
    ]
    assert "github:repository:R_removed" not in refs


def test_an_owner_whose_listing_failed_is_never_end_dated():
    known = [
        {
            "asset_id": "a1",
            "asset_name": "acme/api",
            "asset_external_reference": "github:repository:R_api",
        }
    ]
    daemon = _daemon(BASE, known=known)
    daemon.client = FakeClient(fail_owner="acme")
    daemon._process_message()
    assert not daemon.api.endpoint.upsert.called
    assert not daemon.api.http_post.called


def test_end_dating_can_be_turned_off():
    daemon = _daemon({**BASE, "github_end_date_removed": False})
    daemon._process_message()
    assert not daemon.api.http_post.called
