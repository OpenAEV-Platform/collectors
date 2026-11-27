"""Tests of the configuration, the asset payload and a full collector run."""

from unittest.mock import MagicMock, patch

import pytest
from github_collector import openaev_github
from github_collector.client import GitHubApiError
from github_collector.configuration.collector_config_override import (
    CollectorConfigOverride,
)
from github_collector.configuration.config_loader import ConfigLoader
from github_collector.inventory import repository_asset
from github_collector.openaev_github import OpenAEVGitHub, build_asset, tag_color
from pydantic import ValidationError
from tests.fixtures import REPOSITORIES, FakeClient, workflow

REQUIRED = {"github_token": "t", "github_organizations": "acme"}


def test_defaults():
    config = CollectorConfigOverride(**REQUIRED)
    assert config.id == "openaev_github"
    assert config.period.total_seconds() == 6 * 3600
    assert config.github_api_url == "https://api.github.com"
    assert config.github_include_archived is True
    assert config.github_include_forks is False
    assert config.github_collect_workflows is True
    assert config.github_collect_dynamic_workflows is False
    assert config.github_collect_packages is True
    assert config.github_end_date_removed is True
    assert config.github_removed_action == "end_date"


@pytest.mark.parametrize(
    ("values", "message"),
    [
        ({"github_organizations": "acme"}, "github_token is required"),
        ({"github_token": "t"}, "at least one owner"),
        ({**REQUIRED, "github_api_url": "github.example.com"}, "http"),
        ({**REQUIRED, "github_package_types": "npm,pypi"}, "unknown GitHub package"),
        ({**REQUIRED, "github_removed_action": "purge"}, "github_removed_action"),
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
        "COLLECTOR_GITHUB_COLLECT_DYNAMIC_WORKFLOWS": "true",
    }.items():
        monkeypatch.setenv(name, value)
    configuration = ConfigLoader().to_daemon_config()
    assert configuration.get("github_token") == "ghp"
    assert configuration.get("github_users") == "octocat"
    # pyoaev's Configuration returns booleans as 0 / 1.
    assert bool(configuration.get("github_include_forks")) is True
    assert bool(configuration.get("github_collect_workflows")) is True
    assert bool(configuration.get("github_collect_dynamic_workflows")) is True


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
    known = [
        {
            "asset_id": "a1",
            "asset_name": "acme/removed",
            "asset_external_reference": "github:repository:R_removed",
        }
    ]
    overviews = {"/assets/a1": {"asset_metadata": {"github_state": "active"}}}
    daemon = _daemon(
        {**BASE, "github_end_date_removed": False}, known=known, overviews=overviews
    )
    daemon._process_message()
    assert "github:repository:R_removed" not in _upserted(daemon)
    assert not daemon.api.http_put.called


def _upserted(daemon):
    return [
        c.args[0]["asset_external_reference"]
        for c in daemon.api.endpoint.upsert.call_args_list
    ]


def _end_dated(daemon):
    return [
        c.args[0]
        for c in daemon.api.endpoint.upsert.call_args_list
        if c.args[0].get("asset_metadata", {}).get("github_state") == "deleted"
    ]


def _workflow(node_id, name="Deploy"):
    return {
        "asset_id": f"id-{node_id}",
        "asset_name": f"acme/api: {name}",
        "asset_external_reference": f"github:workflow:{node_id}",
    }


def _overview(repository="github:repository:R_api", **extra):
    return {
        "asset_metadata": {
            "github_kind": "workflow",
            "github_owner": "acme",
            "github_state": "active",
            "github_repository_external_reference": repository,
        },
        **extra,
    }


class ForbiddenWorkflows(FakeClient):
    """The workflows listing of every repository answers 403 (no actions: read)."""

    def repository_workflows(self, full_name):
        raise GitHubApiError("Resource not accessible by integration", 403)


def test_a_workflow_listing_refused_never_end_dates_its_workflows():
    # (a) Active repository, workflows listing 403 in this run: no workflow end-dated.
    known = [_workflow("W_ci", "CI"), _workflow("W_deploy")]
    overviews = {
        "/assets/id-W_ci": _overview(),
        "/assets/id-W_deploy": _overview(),
    }
    daemon = _daemon(BASE, known=known, overviews=overviews)
    daemon.client = ForbiddenWorkflows()
    daemon._process_message()
    assert _end_dated(daemon) == []
    assert "github:repository:R_api" in _upserted(daemon)


def test_a_workflow_seen_again_loses_the_deleted_tag():
    # (b) End-dated in an earlier run, returned again: the tag goes, every other tag stays.
    known = [
        {
            "asset_id": "id-W_ci",
            "asset_name": "acme/api: CI",
            "asset_external_reference": "github:workflow:W_ci",
            "asset_tags": ["id-source:github", "id-github-state:deleted"],
        }
    ]
    overviews = {
        "/assets/id-W_ci": _overview(
            asset_name="acme/api: CI",
            asset_external_reference="github:workflow:W_ci",
            asset_category="SOURCE_CODE",
            asset_subcategory="CI_CD_PIPELINE",
            asset_url="https://github.com/acme/api/blob/main/.github/workflows/ci.yml",
            asset_tags=["id-source:github", "id-github-state:deleted"],
            asset_agents=[],
            asset_markings=["m1"],
        )
    }
    daemon = _daemon(BASE, known=known, overviews=overviews)
    daemon._process_message()
    [upsert] = [
        c.args[0]
        for c in daemon.api.endpoint.upsert.call_args_list
        if c.args[0]["asset_external_reference"] == "github:workflow:W_ci"
    ]
    assert upsert["asset_metadata"]["github_state"] == "active"
    assert "github_end_date" not in upsert["asset_metadata"]
    [put] = daemon.api.http_put.call_args_list
    assert put.args[0] == "/endpoints/id-W_ci"
    body = put.kwargs["post_data"]
    assert body["asset_tags"] == ["id-source:github"]
    assert body["asset_name"] == "acme/api: CI"
    assert body["asset_external_reference"] == "github:workflow:W_ci"
    assert body["asset_subcategory"] == "CI_CD_PIPELINE"
    # Output-only fields are never sent back.
    assert "asset_agents" not in body and "asset_markings" not in body
    assert _end_dated(daemon) == []


def test_a_workflow_really_removed_is_end_dated_and_keeps_its_tags():
    # (c) Workflow gone from a repository whose listing completed: end-dated, the upsert
    # only adds the deleted tag (OpenAEV merges tags on upsert, so the others stay).
    known = [_workflow("W_gone", "Old")]
    overviews = {"/assets/id-W_gone": _overview()}
    daemon = _daemon(BASE, known=known, overviews=overviews)
    daemon._process_message()
    [ended] = _end_dated(daemon)
    assert ended["asset_external_reference"] == "github:workflow:W_gone"
    assert ended["asset_tags"] == ["id-github-state:deleted"]
    assert "github_end_date" in ended["asset_metadata"]
    assert not daemon.api.http_put.called


def test_a_workflow_whose_file_was_deleted_is_end_dated():
    # GitHub still lists W_stale (state active) but its file left the default branch.
    known = [_workflow("W_stale", "CI")]
    overviews = {"/assets/id-W_stale": _overview()}
    daemon = _daemon(BASE, known=known, overviews=overviews)
    daemon.client = FakeClient(
        workflows={
            "acme/api": [
                workflow("W_ci", "CI", ".github/workflows/ci.yml"),
                workflow("W_stale", "CI", ".github/workflows/old-ci.yml"),
            ]
        }
    )
    daemon._process_message()
    # Its only upsert is the end-dating one: it is never upserted as an active asset.
    assert _upserted(daemon).count("github:workflow:W_stale") == 1
    [ended] = _end_dated(daemon)
    assert ended["asset_external_reference"] == "github:workflow:W_stale"
    ci = next(
        c.args[0]
        for c in daemon.api.endpoint.upsert.call_args_list
        if c.args[0]["asset_external_reference"] == "github:workflow:W_ci"
    )
    assert ci["asset_name"] == "acme/api: CI"
    assert ci["asset_internet_facing"] is True


def test_a_workflow_of_a_repository_gone_is_end_dated():
    known = [_workflow("W_x")]
    overviews = {"/assets/id-W_x": _overview(repository="github:repository:R_gone")}
    daemon = _daemon(BASE, known=known, overviews=overviews)
    daemon.client = ForbiddenWorkflows()
    daemon._process_message()
    assert [e["asset_external_reference"] for e in _end_dated(daemon)] == [
        "github:workflow:W_x"
    ]


def test_a_complete_run_end_dates_nothing():
    # (d) Every repository, workflow and package listed: zero assets end-dated, even with
    # the stored references carrying stray whitespace.
    known = [
        {
            "asset_id": "r1",
            "asset_name": "acme/api",
            "asset_external_reference": "github:repository:R_api ",
        },
        {
            "asset_id": "r2",
            "asset_name": "acme/legacy",
            "asset_external_reference": "github:repository:R_legacy",
        },
        _workflow("W_ci", "CI"),
        {
            "asset_id": "p1",
            "asset_name": "acme/api-sdk (npm)",
            "asset_external_reference": "github:package:77",
        },
    ]
    overviews = {
        path: _overview()
        for path in ("/assets/r1", "/assets/r2", "/assets/id-W_ci", "/assets/p1")
    }
    daemon = _daemon(BASE, known=known, overviews=overviews)
    daemon._process_message()
    assert _end_dated(daemon) == []


def test_packages_of_an_unreadable_type_are_never_end_dated():
    known = [
        {
            "asset_id": "p1",
            "asset_name": "acme/api-sdk (npm)",
            "asset_external_reference": "github:package:77",
        }
    ]
    overviews = {
        "/assets/p1": {
            "asset_metadata": {
                "github_owner": "acme",
                "github_package_type": "npm",
                "github_state": "active",
            }
        }
    }
    daemon = _daemon(BASE, known=known, overviews=overviews)
    daemon.client = FakeClient(packages_status=403)
    daemon._process_message()
    assert _end_dated(daemon) == []


class LegacyPackage(FakeClient):
    """An npm package published from the archived acme/legacy repository."""

    def owner_packages(self, owner, package_type, is_org):
        return iter(
            [
                {
                    "id": 88,
                    "name": "legacy-sdk",
                    "package_type": "npm",
                    "visibility": "private",
                    "repository": {"full_name": "acme/legacy", "node_id": "R_legacy"},
                }
            ]
        )


def _legacy_known():
    known = [
        {
            "asset_id": "r-legacy",
            "asset_name": "acme/legacy",
            "asset_external_reference": "github:repository:R_legacy",
        },
        {
            "asset_id": "w-legacy",
            "asset_name": "acme/legacy: CI",
            "asset_external_reference": "github:workflow:W_legacy",
        },
        {
            "asset_id": "p-legacy",
            "asset_name": "acme/legacy-sdk (npm)",
            "asset_external_reference": "github:package:88",
        },
    ]
    overviews = {
        "/assets/r-legacy": {
            "asset_metadata": {"github_owner": "acme", "github_state": "archived"},
            "asset_tags": ["id-source:github"],
        },
        "/assets/w-legacy": _overview(repository="github:repository:R_legacy"),
        "/assets/p-legacy": {
            "asset_metadata": {
                "github_owner": "acme",
                "github_package_type": "npm",
                "github_state": "active",
                "github_repository_external_reference": "github:repository:R_legacy",
            }
        },
    }
    return known, overviews


def _deleted(daemon):
    return [c.args[0] for c in daemon.api.http_delete.call_args_list]


def test_delete_removes_an_archived_repository_and_its_workflows_and_packages():
    # Archived repositories not collected, action delete: the repository, its workflow and
    # its package leave OpenAEV, whatever their tags; the active repository stays.
    known, overviews = _legacy_known()
    daemon = _daemon(
        {**BASE, "github_include_archived": False, "github_removed_action": "delete"},
        known=known,
        overviews=overviews,
    )
    daemon.client = LegacyPackage()
    daemon._process_message()
    assert sorted(_deleted(daemon)) == [
        "/assets/p-legacy",
        "/assets/r-legacy",
        "/assets/w-legacy",
    ]
    assert "github:package:88" not in _upserted(daemon)
    assert "github:repository:R_api" in _upserted(daemon)
    assert _end_dated(daemon) == []


def test_delete_never_keys_on_the_deleted_tag():
    # A live workflow wrongly tagged github-state:deleted by an older run is never deleted:
    # only this run's listings decide.
    known = [
        {
            "asset_id": "id-W_ci",
            "asset_name": "acme/api: CI",
            "asset_external_reference": "github:workflow:W_ci",
            "asset_tags": ["id-source:github", "id-github-state:deleted"],
        }
    ]
    overviews = {
        "/assets/id-W_ci": _overview(
            asset_tags=["id-source:github", "id-github-state:deleted"],
            github_state="deleted",
        )
    }
    daemon = _daemon(
        {**BASE, "github_removed_action": "delete"}, known=known, overviews=overviews
    )
    daemon._process_message()
    assert _deleted(daemon) == []


def test_delete_leaves_an_incomplete_listing_alone():
    known, overviews = _legacy_known()
    daemon = _daemon(
        {**BASE, "github_include_archived": False, "github_removed_action": "delete"},
        known=known,
        overviews=overviews,
    )
    daemon.client = FakeClient(fail_owner="acme")
    daemon._process_message()
    assert _deleted(daemon) == []


def test_end_date_applies_to_an_archived_repository_dropped_by_the_settings():
    known, overviews = _legacy_known()
    daemon = _daemon(
        {**BASE, "github_include_archived": False}, known=known, overviews=overviews
    )
    daemon.client = LegacyPackage()
    daemon._process_message()
    assert sorted(e["asset_external_reference"] for e in _end_dated(daemon)) == [
        "github:package:88",
        "github:repository:R_legacy",
        "github:workflow:W_legacy",
    ]
    assert _deleted(daemon) == []


def test_tag_only_adds_the_deleted_tag():
    known, overviews = _legacy_known()
    daemon = _daemon(
        {**BASE, "github_include_archived": False, "github_removed_action": "tag"},
        known=known,
        overviews=overviews,
    )
    daemon.client = LegacyPackage()
    daemon._process_message()
    tagged = [
        c.args[0]
        for c in daemon.api.endpoint.upsert.call_args_list
        if c.args[0]["asset_external_reference"] == "github:repository:R_legacy"
    ]
    assert [t["asset_tags"] for t in tagged] == [["id-github-state:deleted"]]
    assert "github_end_date" not in tagged[0]["asset_metadata"]
    assert _end_dated(daemon) == []
    assert _deleted(daemon) == []
