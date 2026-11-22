"""OpenAEV collector registering GitHub repositories, workflows and packages as assets."""

import os
from datetime import UTC, datetime
from typing import Any

from github_collector.client import GITHUB_COM_API_URL, GitHubClient
from github_collector.configuration.config_loader import ConfigLoader
from github_collector.inventory import (
    CATEGORY,
    REFERENCE_PREFIX,
    GitHubAsset,
    Inventory,
    InventorySettings,
    parse_list,
)
from pyoaev.apis.inputs.search import Filter, FilterGroup, SearchPaginationInput
from pyoaev.configuration import Configuration
from pyoaev.daemons import CollectorDaemon

SOURCE_TAG = "source:github"
DELETED_TAG = "github-state:deleted"
TAG_COLORS = {
    "source": "#24292f",
    "github-owner": "#8b5cf6",
    "github-repo": "#6366f1",
    "visibility": "#3b82f6",
    "language": "#10b981",
    "topic": "#f59e0b",
    "github-state": "#ef4444",
    "github-fork": "#6b7280",
    "package-type": "#0ea5e9",
}
DEFAULT_TAG_COLOR = "#6b7280"
SEARCH_PAGE_SIZE = 200

ENV_KEYS = [
    "GITHUB_TOKEN",
    "GITHUB_API_URL",
    "GITHUB_ORGANIZATIONS",
    "GITHUB_USERS",
]


def tag_color(name: str) -> str:
    """Return the color of a tag, read from its prefix."""
    return TAG_COLORS.get(name.split(":", 1)[0], DEFAULT_TAG_COLOR)


def build_asset(asset: GitHubAsset, tag_ids: list[str]) -> dict[str, Any]:
    """Build the OpenAEV asset payload of a GitHub object.

    OpenAEV registers every asset category through the agentless endpoint upsert; platform and
    architecture are left out so the platform keeps its Unknown default.
    """
    payload: dict[str, Any] = {
        "asset_name": asset.name,
        "asset_external_reference": asset.external_reference,
        "asset_category": CATEGORY,
        "asset_subcategory": asset.subcategory,
        "asset_metadata": {
            k: v for k, v in asset.metadata.items() if v not in (None, [], "")
        },
    }
    if asset.url:
        payload["asset_url"] = asset.url
    if asset.description:
        payload["asset_description"] = asset.description
    if asset.internet_facing is not None:
        payload["asset_internet_facing"] = asset.internet_facing
    if tag_ids:
        payload["asset_tags"] = tag_ids
    return payload


def owner_of(asset_name: str) -> str:
    """Return the GitHub owner of an asset this collector named ``owner/...``."""
    return asset_name.split("/", 1)[0].lower()


class OpenAEVGitHub(CollectorDaemon):  # type: ignore[misc]
    """Collector daemon: one GitHub inventory pass per period."""

    def __init__(
        self,
        configuration: Configuration,
    ) -> None:
        """Read the settings; the GitHub client is created at the first run."""
        super().__init__(
            configuration=configuration,
            callback=self._process_message,
            collector_type="openaev_github",
        )
        get = self._configuration.get
        self.token = get("github_token")
        self.api_url = get("github_api_url") or GITHUB_COM_API_URL
        self.end_date_removed = bool(get("github_end_date_removed"))
        self.settings = InventorySettings(
            organizations=parse_list(get("github_organizations")),
            users=parse_list(get("github_users")),
            include_archived=bool(get("github_include_archived")),
            include_forks=bool(get("github_include_forks")),
            collect_workflows=bool(get("github_collect_workflows")),
            collect_packages=bool(get("github_collect_packages")),
            package_types=parse_list(get("github_package_types")),
            host=self._host(self.api_url),
        )
        self.client: GitHubClient | None = None
        self._tag_cache: dict[str, str | None] = {}

    @staticmethod
    def _host(api_url: str) -> str:
        if api_url.rstrip("/") == GITHUB_COM_API_URL:
            return "github.com"
        return api_url.split("://", 1)[-1].split("/", 1)[0]

    def _get_client(self) -> GitHubClient:
        # One client for the life of the daemon, so its ETag cache spans the runs.
        if self.client is None:
            self.client = GitHubClient(
                token=self.token, api_url=self.api_url, logger=self.logger
            )
        return self.client

    def _tag_id(self, name: str) -> str | None:
        """Upsert an OpenAEV tag once per run and return its id."""
        if name not in self._tag_cache:
            try:
                result = self.api.tag.upsert(
                    {"tag_name": name, "tag_color": tag_color(name)}
                )
                self._tag_cache[name] = result.get("tag_id")
            except Exception as err:
                self.logger.warning(f"Failed to upsert tag {name}: {err}")
                self._tag_cache[name] = None
        return self._tag_cache[name]

    def _tag_ids(self, names: list[str]) -> list[str]:
        return [tag_id for name in names if (tag_id := self._tag_id(name))]

    def _known_assets(self) -> list[dict[str, Any]]:
        """Return the source-code assets this collector registered earlier."""
        filters = FilterGroup(
            "and",
            [
                Filter("asset_category", "or", "eq", [CATEGORY]),
                Filter(
                    "asset_external_reference", "or", "starts_with", [REFERENCE_PREFIX]
                ),
            ],
        )
        assets: list[dict[str, Any]] = []
        page = 0
        while True:
            search = SearchPaginationInput(page, SEARCH_PAGE_SIZE, filters, None, None)
            result = self.api.http_post("/assets/search", post_data=search.to_dict())
            content = result.get("content") or []
            assets.extend(content)
            # A short page is the last one, whatever page fields the server serializes.
            if len(content) < SEARCH_PAGE_SIZE or result.get("last") is True:
                return assets
            page += 1

    def _end_date_removed(self, seen: set[str], complete_owners: set[str]) -> None:
        """End-date the assets of a complete owner that GitHub no longer returns.

        The asset is kept (never deleted): its metadata gets ``github_state: deleted`` and
        ``github_end_date``, and it is tagged ``github-state:deleted``. An owner whose listing
        failed in this run is left untouched.
        """
        now = datetime.now(UTC).isoformat()
        for known in self._known_assets():
            reference = known.get("asset_external_reference")
            name = known.get("asset_name") or ""
            if reference in seen or owner_of(name) not in complete_owners:
                continue
            try:
                overview = self.api.http_get(f"/assets/{known['asset_id']}")
                metadata = dict(overview.get("asset_metadata") or {})
                if metadata.get("github_state") == "deleted":
                    continue
                metadata["github_state"] = "deleted"
                metadata["github_end_date"] = now
                self.api.endpoint.upsert(
                    {
                        "asset_name": name,
                        "asset_external_reference": reference,
                        "asset_metadata": metadata,
                        "asset_tags": self._tag_ids([DELETED_TAG]),
                    }
                )
                self.logger.info(f"End-dated {name}: no longer on GitHub")
            except Exception as err:
                self.logger.error(f"Failed to end-date {name}: {err}")

    def _process_message(self) -> None:
        """Collect the configured GitHub owners and upsert their source-code assets."""
        self._tag_cache = {}
        try:
            self.logger.info("Starting GitHub collection...")
            inventory = Inventory(self._get_client(), self.settings, self.logger)
            result = inventory.collect()
            self.logger.info(f"Total GitHub assets to upsert: {len(result.assets)}")
            seen: set[str] = set()
            for asset in result.assets:
                tag_ids = self._tag_ids([SOURCE_TAG, *asset.tags])
                try:
                    self.api.endpoint.upsert(build_asset(asset, tag_ids))
                    seen.add(asset.external_reference)
                    self.logger.debug(
                        f"Upserted {asset.name} ({asset.external_reference})"
                    )
                except Exception as err:
                    # Not seen: never end-dated in this run either, the owner is not complete.
                    result.complete_owners.discard(asset.owner.lower())
                    self.logger.error(f"Failed to upsert {asset.name}: {err}")
            if self.end_date_removed and result.complete_owners:
                self._end_date_removed(seen, result.complete_owners)
            self.logger.info("GitHub collection completed")
        except Exception as err:
            self.logger.error(f"Error during GitHub collection: {err}")


def main() -> None:
    """Start the collector, accepting the GITHUB_* variables without their prefix."""
    for key in ENV_KEYS:
        value = os.environ.get(key)
        if not os.environ.get(f"COLLECTOR_{key}") and value:
            os.environ[f"COLLECTOR_{key}"] = value

    OpenAEVGitHub(configuration=ConfigLoader().to_daemon_config()).start()
