"""Tests of the inventory: repositories, workflows and packages to source-code assets."""

from unittest.mock import MagicMock

from github_collector.inventory import (
    Inventory,
    InventorySettings,
    package_asset,
    parse_list,
    repository_asset,
)
from tests.fixtures import PACKAGES, REPOSITORIES, FakeClient


def _collect(client=None, **settings):
    values = {"organizations": ["acme"], "package_types": ["npm"]}
    values.update(settings)
    return Inventory(
        client or FakeClient(), InventorySettings(**values), MagicMock()
    ).collect()


def test_parse_list():
    assert parse_list(" a, ,b ") == ["a", "b"]
    assert parse_list(None) == []


def test_repository_maps_to_a_code_repository_keyed_on_its_node_id():
    asset = repository_asset(REPOSITORIES[0], "github.com")
    assert asset.subcategory == "CODE_REPOSITORY"
    assert asset.external_reference == "github:repository:R_api"
    assert asset.name == "acme/api"
    assert asset.url == "https://github.com/acme/api"
    assert asset.internet_facing is True
    assert asset.metadata["github_default_branch"] == "main"
    assert asset.metadata["github_pushed_at"] == "2026-11-20T10:00:00Z"
    assert asset.metadata["github_state"] == "active"
    assert "topic:security" in asset.tags
    assert "language:python" in asset.tags
    assert "visibility:public" in asset.tags


def test_archived_private_repository_is_flagged_and_not_internet_facing():
    asset = repository_asset(REPOSITORIES[1], "github.com")
    assert asset.internet_facing is False
    assert asset.metadata["github_archived"] is True
    assert asset.metadata["github_state"] == "archived"
    assert "github-state:archived" in asset.tags


def test_forks_are_skipped_by_default_and_archived_kept():
    result = _collect()
    names = {a.name for a in result.assets if a.kind == "repository"}
    assert names == {"acme/api", "acme/legacy"}
    assert result.complete_owners == {"acme"}


def test_flags_include_forks_and_drop_archived():
    result = _collect(include_forks=True, include_archived=False)
    names = {a.name for a in result.assets if a.kind == "repository"}
    assert names == {"acme/api", "acme/forked"}


def test_workflows_are_linked_to_their_repository():
    result = _collect()
    [workflow] = [a for a in result.assets if a.kind == "workflow"]
    assert workflow.subcategory == "CI_CD_PIPELINE"
    assert workflow.external_reference == "github:workflow:W_ci"
    assert workflow.metadata["github_repository_external_reference"] == (
        "github:repository:R_api"
    )
    assert workflow.name == "acme/api: CI"


def test_workflows_toggle_off():
    result = _collect(collect_workflows=False)
    assert not [a for a in result.assets if a.kind == "workflow"]


def test_packages_are_software_packages():
    asset = package_asset(PACKAGES["npm"][0], "acme", "github.com")
    assert asset.subcategory == "SOFTWARE_PACKAGE"
    assert asset.external_reference == "github:package:77"
    assert (
        asset.metadata["github_repository_external_reference"]
        == "github:repository:R_api"
    )
    assert asset.name == "acme/api-sdk (npm)"


def test_unreadable_packages_do_not_stop_the_owner():
    result = _collect(client=FakeClient(packages_status=403))
    assert not [a for a in result.assets if a.kind == "package"]
    assert result.complete_owners == {"acme"}


def test_a_failing_owner_is_skipped_and_never_complete():
    result = _collect(
        client=FakeClient(fail_owner="acme"), users=["someone"], collect_packages=False
    )
    assert result.assets == []
    assert result.complete_owners == {"someone"}
