"""Tests of the inventory: repositories, workflows and packages to source-code assets."""

from unittest.mock import MagicMock

from github_collector.inventory import (
    Inventory,
    InventorySettings,
    package_asset,
    parse_list,
    repository_asset,
)
from tests.fixtures import PACKAGES, REPOSITORIES, FakeClient, repo, workflow


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


def _connectors_workflows():
    return {
        "acme/api": [
            workflow(
                "W_old", "Tests Connectors", ".github/workflows/tests-connectors.yml"
            ),
            workflow("W_new", "Tests Connectors", ".github/workflows/ci-tests.yml"),
            workflow("W_lint", "Lint", ".github/workflows/lint.yml"),
            workflow("W_claude", "Claude", "dynamic/agents/claude"),
            workflow("W_codeql", "CodeQL", "dynamic/github-code-scanning/codeql"),
        ]
    }


def _workflows_of(result):
    return {a.external_reference: a for a in result.assets if a.kind == "workflow"}


def test_workflows_sharing_a_name_get_their_file_in_the_name():
    files = {
        "acme/api": [
            ".github/workflows/tests-connectors.yml",
            ".github/workflows/ci-tests.yml",
            ".github/workflows/lint.yml",
        ]
    }
    client = FakeClient(workflows=_connectors_workflows(), workflow_files=files)
    workflows = _workflows_of(_collect(client=client))
    old = workflows["github:workflow:W_old"].name
    new = workflows["github:workflow:W_new"].name
    assert old != new
    assert old == "acme/api: Tests Connectors (tests-connectors.yml)"
    assert new == "acme/api: Tests Connectors (ci-tests.yml)"
    # A unique name stays as it was, so existing assets keep their name.
    assert workflows["github:workflow:W_lint"].name == "acme/api: Lint"


def test_a_workflow_whose_file_left_the_default_branch_is_not_emitted():
    files = {
        "acme/api": [".github/workflows/ci-tests.yml", ".github/workflows/lint.yml"]
    }
    client = FakeClient(workflows=_connectors_workflows(), workflow_files=files)
    result = _collect(client=client)
    workflows = _workflows_of(result)
    assert set(workflows) == {"github:workflow:W_new", "github:workflow:W_lint"}
    # Once the stale one is gone, the remaining name is unique again.
    assert workflows["github:workflow:W_new"].name == "acme/api: Tests Connectors"
    # The listing still completed: an asset registered for the stale workflow is removable.
    assert "github:repository:R_api" in result.complete_workflow_repositories
    assert result.removable(
        "workflow",
        "acme",
        {"github_repository_external_reference": "github:repository:R_api"},
    )
    # One contents read per repository, on its default branch.
    contents = [c for c in client.calls if c[0] == "contents"]
    assert contents == [("contents", "acme/api", ".github/workflows", "main")]


def test_a_repository_without_workflow_directory_emits_no_file_workflow():
    client = FakeClient(workflows=_connectors_workflows(), workflow_files={})
    result = _collect(client=client)
    assert _workflows_of(result) == {}
    assert "github:repository:R_api" in result.complete_workflow_repositories


def test_unreadable_workflow_files_keep_every_listed_workflow():
    client = FakeClient(workflows=_connectors_workflows(), contents_status=403)
    result = _collect(client=client)
    assert set(_workflows_of(result)) == {
        "github:workflow:W_old",
        "github:workflow:W_new",
        "github:workflow:W_lint",
    }
    assert "github:repository:R_api" in result.complete_workflow_repositories


def test_dynamic_workflows_are_skipped_by_default_and_collected_on_demand():
    files = {"acme/api": [".github/workflows/lint.yml"]}
    client = FakeClient(workflows=_connectors_workflows(), workflow_files=files)
    assert set(_workflows_of(_collect(client=client))) == {"github:workflow:W_lint"}
    client = FakeClient(workflows=_connectors_workflows(), workflow_files=files)
    workflows = _workflows_of(_collect(client=client, collect_dynamic_workflows=True))
    assert set(workflows) == {
        "github:workflow:W_lint",
        "github:workflow:W_claude",
        "github:workflow:W_codeql",
    }
    assert workflows["github:workflow:W_claude"].name == "acme/api: Claude"


def test_dynamic_workflows_alone_need_no_contents_read():
    client = FakeClient(
        workflows={"acme/api": [workflow("W_d", "Claude", "dynamic/agents/claude")]},
        contents_status=500,
    )
    assert _workflows_of(_collect(client=client)) == {}
    assert not [c for c in client.calls if c[0] == "contents"]


def test_a_workflow_takes_the_exposure_and_visibility_of_its_repository():
    repositories = [
        repo("api", "R_api"),
        repo("internal", "R_internal", visibility="internal", private=True),
        repo("secret", "R_secret", visibility="private", private=True),
    ]
    ci = ".github/workflows/ci.yml"
    workflows = {
        "acme/api": [workflow("W_pub", "CI", ci)],
        "acme/internal": [workflow("W_int", "CI", ci)],
        "acme/secret": [workflow("W_priv", "CI", ci)],
    }
    files = {name: [ci] for name in workflows}
    client = FakeClient(
        repositories=repositories, workflows=workflows, workflow_files=files
    )
    found = _workflows_of(_collect(client=client))
    public = found["github:workflow:W_pub"]
    assert public.internet_facing is True
    assert "visibility:public" in public.tags
    assert public.metadata["github_visibility"] == "public"
    internal = found["github:workflow:W_int"]
    assert internal.internet_facing is False
    assert "visibility:internal" in internal.tags
    private = found["github:workflow:W_priv"]
    assert private.internet_facing is False
    assert "visibility:private" in private.tags


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


def test_complete_listings_are_recorded_per_repository_and_package_type():
    result = _collect()
    assert result.listed_repositories == {
        "github:repository:R_api",
        "github:repository:R_legacy",
    }
    # acme/legacy answers 404 on its workflows: its listing is not complete.
    assert result.complete_workflow_repositories == {"github:repository:R_api"}
    assert result.complete_package_types == {("acme", "npm")}


def test_removable_needs_the_listing_that_would_have_returned_the_asset():
    result = _collect()
    api = {"github_repository_external_reference": "github:repository:R_api"}
    legacy = {"github_repository_external_reference": "github:repository:R_legacy"}
    gone = {"github_repository_external_reference": "github:repository:R_gone"}
    assert result.removable("repository", "ACME", {})
    assert result.removable("workflow", "acme", api)
    assert not result.removable("workflow", "acme", legacy)
    assert result.removable("workflow", "acme", gone)
    assert not result.removable("workflow", "acme", {})
    assert result.removable("package", "acme", {"github_package_type": "npm"})
    assert not result.removable("package", "acme", {"github_package_type": "maven"})
    assert not result.removable("repository", "other", {})


def test_a_failing_owner_is_skipped_and_never_complete():
    result = _collect(
        client=FakeClient(fail_owner="acme"), users=["someone"], collect_packages=False
    )
    assert result.assets == []
    assert result.complete_owners == {"someone"}
