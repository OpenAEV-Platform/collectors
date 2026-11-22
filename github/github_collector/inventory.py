"""Turn the GitHub inventory of the configured owners into OpenAEV source-code assets.

Every asset is keyed on a stable GitHub identifier carried in ``asset_external_reference``:

- a repository on its GraphQL node id: ``github:repository:<node_id>``;
- a GitHub Actions workflow on its node id: ``github:workflow:<node_id>``;
- a GitHub Packages package on its id: ``github:package:<id>``.

The names can change (a repository renamed or transferred keeps its node id), so the upsert
never creates a second asset for the same object.
"""

import logging
from dataclasses import dataclass, field
from typing import Any

from github_collector.client import GitHubApiError, GitHubClient

CATEGORY = "SOURCE_CODE"
SUBCATEGORY_REPOSITORY = "CODE_REPOSITORY"
SUBCATEGORY_PIPELINE = "CI_CD_PIPELINE"
SUBCATEGORY_PACKAGE = "SOFTWARE_PACKAGE"

REFERENCE_PREFIX = "github:"
KIND_REPOSITORY = "repository"
KIND_WORKFLOW = "workflow"
KIND_PACKAGE = "package"

DEFAULT_PACKAGE_TYPES = ("npm", "maven", "rubygems", "nuget", "container")
ALLOWED_PACKAGE_TYPES = {"npm", "maven", "rubygems", "docker", "nuget", "container"}


def parse_list(value: str | None) -> list[str]:
    """Split a comma-separated setting, dropping blanks."""
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def reference(kind: str, identifier: Any) -> str:
    """Return the external reference of a GitHub object."""
    return f"{REFERENCE_PREFIX}{kind}:{identifier}"


@dataclass
class GitHubAsset:
    """One source-code asset, ready to be sent to OpenAEV."""

    kind: str
    name: str
    external_reference: str
    subcategory: str
    owner: str
    url: str | None = None
    description: str | None = None
    internet_facing: bool | None = None
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class InventorySettings:
    """What to collect."""

    organizations: list[str] = field(default_factory=list)
    users: list[str] = field(default_factory=list)
    include_archived: bool = True
    include_forks: bool = False
    collect_workflows: bool = True
    collect_packages: bool = True
    package_types: list[str] = field(
        default_factory=lambda: list(DEFAULT_PACKAGE_TYPES)
    )
    host: str = "github.com"


@dataclass
class InventoryResult:
    """The assets found and the owners whose listing completed without error.

    Only a complete owner may have its missing assets end-dated: a listing cut by an API
    error must never be read as "every repository was deleted".
    """

    assets: list[GitHubAsset] = field(default_factory=list)
    complete_owners: set[str] = field(default_factory=set)


def repository_asset(repo: dict[str, Any], host: str) -> GitHubAsset:
    """Map a repository of the REST API to an asset."""
    owner = (repo.get("owner") or {}).get("login") or repo["full_name"].split("/")[0]
    visibility = repo.get("visibility") or (
        "private" if repo.get("private") else "public"
    )
    archived = bool(repo.get("archived"))
    tags = [f"github-owner:{owner.lower()}", f"visibility:{visibility}"]
    if repo.get("language"):
        tags.append(f"language:{repo['language'].lower()}")
    tags.extend(f"topic:{topic.lower()}" for topic in repo.get("topics") or [])
    if archived:
        tags.append("github-state:archived")
    if repo.get("fork"):
        tags.append("github-fork")
    return GitHubAsset(
        kind=KIND_REPOSITORY,
        name=repo["full_name"],
        external_reference=reference(KIND_REPOSITORY, repo["node_id"]),
        subcategory=SUBCATEGORY_REPOSITORY,
        owner=owner,
        url=repo.get("html_url"),
        description=repo.get("description"),
        # A public repository is readable from the Internet; a private or internal one is not.
        internet_facing=visibility == "public",
        tags=tags,
        metadata={
            "provider": "github",
            "github_host": host,
            "github_kind": KIND_REPOSITORY,
            "github_owner": owner,
            "github_name": repo.get("name"),
            "github_full_name": repo["full_name"],
            "github_node_id": repo["node_id"],
            "github_id": repo.get("id"),
            "github_visibility": visibility,
            "github_default_branch": repo.get("default_branch"),
            "github_archived": archived,
            "github_fork": bool(repo.get("fork")),
            "github_pushed_at": repo.get("pushed_at"),
            "github_language": repo.get("language"),
            "github_topics": repo.get("topics") or [],
            "github_state": "archived" if archived else "active",
        },
    )


def workflow_asset(
    workflow: dict[str, Any], repository: GitHubAsset, host: str
) -> GitHubAsset:
    """Map a GitHub Actions workflow to an asset linked to its repository."""
    full_name = repository.metadata["github_full_name"]
    return GitHubAsset(
        kind=KIND_WORKFLOW,
        name=f"{full_name}: {workflow.get('name') or workflow.get('path')}",
        external_reference=reference(KIND_WORKFLOW, workflow["node_id"]),
        subcategory=SUBCATEGORY_PIPELINE,
        owner=repository.owner,
        url=workflow.get("html_url"),
        description=f"GitHub Actions workflow {workflow.get('path')} of {full_name}",
        tags=[
            f"github-owner:{repository.owner.lower()}",
            f"github-repo:{full_name.lower()}",
        ],
        metadata={
            "provider": "github",
            "github_host": host,
            "github_kind": KIND_WORKFLOW,
            "github_owner": repository.owner,
            "github_node_id": workflow["node_id"],
            "github_id": workflow.get("id"),
            "github_path": workflow.get("path"),
            "github_workflow_state": workflow.get("state"),
            "github_repository": full_name,
            "github_repository_external_reference": repository.external_reference,
            "github_updated_at": workflow.get("updated_at"),
            "github_state": "active",
        },
    )


def package_asset(package: dict[str, Any], owner: str, host: str) -> GitHubAsset:
    """Map a GitHub Packages package to an asset."""
    package_type = package.get("package_type") or "unknown"
    repo = package.get("repository") or {}
    metadata: dict[str, Any] = {
        "provider": "github",
        "github_host": host,
        "github_kind": KIND_PACKAGE,
        "github_owner": owner,
        "github_id": package["id"],
        "github_package_type": package_type,
        "github_visibility": package.get("visibility"),
        "github_version_count": package.get("version_count"),
        "github_updated_at": package.get("updated_at"),
        "github_state": "active",
    }
    tags = [f"github-owner:{owner.lower()}", f"package-type:{package_type}"]
    if repo.get("full_name"):
        metadata["github_repository"] = repo["full_name"]
        if repo.get("node_id"):
            metadata["github_repository_external_reference"] = reference(
                KIND_REPOSITORY, repo["node_id"]
            )
        tags.append(f"github-repo:{repo['full_name'].lower()}")
    return GitHubAsset(
        kind=KIND_PACKAGE,
        name=f"{owner}/{package['name']} ({package_type})",
        external_reference=reference(KIND_PACKAGE, package["id"]),
        subcategory=SUBCATEGORY_PACKAGE,
        owner=owner,
        url=package.get("html_url"),
        internet_facing=package.get("visibility") == "public",
        tags=tags,
        metadata=metadata,
    )


class Inventory:
    """Read the configured owners on GitHub and build their assets."""

    def __init__(
        self,
        client: GitHubClient,
        settings: InventorySettings,
        logger: logging.Logger | Any,
    ) -> None:
        """Keep the client, the settings and the logger."""
        self.client = client
        self.settings = settings
        self.logger = logger

    def _keep(self, repo: dict[str, Any]) -> bool:
        if repo.get("archived") and not self.settings.include_archived:
            return False
        if repo.get("fork") and not self.settings.include_forks:
            return False
        return True

    def _owner_assets(self, owner: str, is_org: bool) -> list[GitHubAsset]:
        """List every asset of one owner; raise GitHubApiError when the listing fails."""
        host = self.settings.host
        repositories = (
            self.client.organization_repositories(owner)
            if is_org
            else self.client.user_repositories(owner)
        )
        assets: list[GitHubAsset] = []
        for repo in repositories:
            if not self._keep(repo):
                continue
            repository = repository_asset(repo, host)
            assets.append(repository)
            if self.settings.collect_workflows:
                assets.extend(self._workflows(repository))
        if self.settings.collect_packages:
            assets.extend(self._packages(owner, is_org))
        return assets

    def _workflows(self, repository: GitHubAsset) -> list[GitHubAsset]:
        full_name = repository.metadata["github_full_name"]
        try:
            return [
                workflow_asset(workflow, repository, self.settings.host)
                for workflow in self.client.repository_workflows(full_name)
            ]
        except GitHubApiError as err:
            # Actions disabled, or no "actions: read" permission: the repository itself stays.
            if err.status_code in (403, 404):
                self.logger.info(f"No readable workflows for {full_name}: {err}")
                return []
            raise

    def _packages(self, owner: str, is_org: bool) -> list[GitHubAsset]:
        assets: list[GitHubAsset] = []
        for package_type in self.settings.package_types:
            try:
                for package in self.client.owner_packages(owner, package_type, is_org):
                    assets.append(package_asset(package, owner, self.settings.host))
            except GitHubApiError as err:
                # Packages need a token with read:packages: without it the rest still runs.
                if err.status_code in (401, 403, 404):
                    self.logger.info(
                        f"Packages of type {package_type} of {owner} not readable with "
                        f"this token: {err}"
                    )
                    return assets
                raise
        return assets

    def collect(self) -> InventoryResult:
        """Collect every configured owner; an owner that fails is logged and skipped."""
        result = InventoryResult()
        owners = [(org, True) for org in self.settings.organizations] + [
            (user, False) for user in self.settings.users
        ]
        for owner, is_org in owners:
            try:
                assets = self._owner_assets(owner, is_org)
            except GitHubApiError as err:
                self.logger.error(f"Failed to list the repositories of {owner}: {err}")
                continue
            self.logger.info(f"{owner}: {len(assets)} source-code assets")
            result.assets.extend(assets)
            result.complete_owners.add(owner.lower())
        return result
