import os
from typing import Any

from pyoaev.configuration import Configuration
from pyoaev.daemons import CollectorDaemon

from ovhcloud.client import OvhClient
from ovhcloud.configuration.config_loader import ConfigLoader
from ovhcloud.inventory import (
    RESOURCE_DEDICATED_SERVER,
    Inventory,
    InventorySettings,
    OvhAsset,
    parse_list,
    parse_tags,
)

# OpenAEV has no dedicated cloud provider value for OVHcloud: assets are registered with
# OTHER and carry "ovhcloud" in their metadata and tags.
CLOUD_PROVIDER = "OTHER"

SUBCATEGORIES = {
    RESOURCE_DEDICATED_SERVER: "SERVER",
}
DEFAULT_SUBCATEGORY = "VIRTUAL_MACHINE"

TAG_COLORS = {
    "source": "#ef4444",
    "resource-type": "#8b5cf6",
    "region": "#3b82f6",
    "datacenter": "#10b981",
    "project": "#f59e0b",
    "ovh-tag": "#6b7280",
}

ENV_KEYS = [
    "OVHCLOUD_ENDPOINT",
    "OVHCLOUD_APPLICATION_KEY",
    "OVHCLOUD_APPLICATION_SECRET",
    "OVHCLOUD_CONSUMER_KEY",
    "OVHCLOUD_CLIENT_ID",
    "OVHCLOUD_CLIENT_SECRET",
]


def build_endpoint(asset: OvhAsset, tag_ids: list[str]) -> dict[str, Any]:
    """Build the agentless endpoint payload of an OVHcloud asset."""
    endpoint: dict[str, Any] = {
        "asset_name": asset.name,
        "asset_external_reference": asset.external_reference,
        "asset_hostname": asset.hostname,
        "endpoint_platform": asset.platform,
        "endpoint_arch": asset.arch,
        "asset_category": "HOST",
        "asset_subcategory": SUBCATEGORIES.get(
            asset.resource_type, DEFAULT_SUBCATEGORY
        ),
        "asset_cloud_provider": CLOUD_PROVIDER,
        "asset_cloud_native_type": asset.cloud_native_type,
        "asset_cloud_region": asset.region or asset.datacenter,
        "asset_ips": asset.ips,
        "asset_description": asset.description,
        "asset_metadata": {
            k: v for k, v in asset.metadata.items() if v not in (None, [], "")
        },
    }
    if asset.internet_facing is not None:
        endpoint["asset_internet_facing"] = asset.internet_facing
    if asset.mac_addresses:
        endpoint["asset_mac_addresses"] = asset.mac_addresses
    if tag_ids:
        endpoint["asset_tags"] = tag_ids
    return endpoint


def tag_names(asset: OvhAsset, include_ovh_tags: bool) -> list[tuple[str, str]]:
    """The OpenAEV tags (name, color) of an asset."""
    names = [
        ("source:ovhcloud", TAG_COLORS["source"]),
        (f"ovh-type:{asset.resource_type}", TAG_COLORS["resource-type"]),
    ]
    if asset.region:
        names.append((f"region:{asset.region.lower()}", TAG_COLORS["region"]))
    if asset.datacenter:
        names.append(
            (f"datacenter:{asset.datacenter.lower()}", TAG_COLORS["datacenter"])
        )
    if asset.project:
        names.append((f"ovh-project:{asset.project.lower()}", TAG_COLORS["project"]))
    if include_ovh_tags:
        for key, value in sorted(asset.iam_tags.items()):
            # ovh:* tags are set by OVHcloud itself (e.g. ovh:type), not by users.
            if key.startswith("ovh:"):
                continue
            names.append((f"ovh-{key.lower()}:{value.lower()}", TAG_COLORS["ovh-tag"]))
    return names


class OpenAEVOvhcloud(CollectorDaemon):
    def __init__(
        self,
        configuration: Configuration,
    ):
        super().__init__(
            configuration=configuration,
            callback=self._process_message,
            collector_type="openaev_ovhcloud",
        )
        get = self._configuration.get
        self.endpoint = get("ovhcloud_endpoint") or "ovh-eu"
        self.application_key = get("ovhcloud_application_key")
        self.application_secret = get("ovhcloud_application_secret")
        self.consumer_key = get("ovhcloud_consumer_key")
        self.client_id = get("ovhcloud_client_id")
        self.client_secret = get("ovhcloud_client_secret")
        self.import_ovh_tags = bool(get("ovhcloud_import_tags"))
        self.settings = InventorySettings(
            collect_dedicated_servers=bool(get("ovhcloud_collect_dedicated_servers")),
            collect_public_cloud=bool(get("ovhcloud_collect_public_cloud")),
            collect_vps=bool(get("ovhcloud_collect_vps")),
            collect_hosted_private_cloud=bool(
                get("ovhcloud_collect_hosted_private_cloud")
            ),
            public_cloud_project_ids=parse_list(
                get("ovhcloud_public_cloud_project_ids")
            ),
            regions=parse_list(get("ovhcloud_regions")),
            name_include=get("ovhcloud_name_include") or None,
            name_exclude=get("ovhcloud_name_exclude") or None,
            iam_tags=parse_tags(get("ovhcloud_iam_tags")),
            skip_inactive=bool(get("ovhcloud_skip_inactive")),
            include_public_ipv4=bool(get("ovhcloud_include_public_ipv4")),
            include_public_ipv6=bool(get("ovhcloud_include_public_ipv6")),
            include_private_ips=bool(get("ovhcloud_include_private_ips")),
            max_workers=int(get("ovhcloud_max_workers") or 5),
        )
        self.client: OvhClient | None = None
        self._tag_cache: dict[str, str | None] = {}

    def _get_client(self) -> OvhClient:
        if self.client is None:
            self.client = OvhClient(
                endpoint=self.endpoint,
                application_key=self.application_key,
                application_secret=self.application_secret,
                consumer_key=self.consumer_key,
                client_id=self.client_id,
                client_secret=self.client_secret,
                logger=self.logger,
            )
        return self.client

    def _tag_id(self, name: str, color: str) -> str | None:
        """Upsert an OpenAEV tag once per run and return its id."""
        if name not in self._tag_cache:
            try:
                result = self.api.tag.upsert({"tag_name": name, "tag_color": color})
                self._tag_cache[name] = result.get("tag_id")
            except Exception as err:
                self.logger.warning(f"Failed to upsert tag {name}: {err}")
                self._tag_cache[name] = None
        return self._tag_cache[name]

    def _process_message(self) -> None:
        """Collect the enabled OVHcloud resources and upsert them as agentless endpoints."""
        self._tag_cache = {}
        try:
            self.logger.info("Starting OVHcloud collection...")
            inventory = Inventory(self._get_client(), self.settings, self.logger)
            assets = inventory.collect()
            self.logger.info(f"Total OVHcloud assets to upsert: {len(assets)}")
            for asset in assets:
                tag_ids = [
                    tag_id
                    for name, color in tag_names(asset, self.import_ovh_tags)
                    if (tag_id := self._tag_id(name, color))
                ]
                try:
                    self.api.endpoint.upsert(build_endpoint(asset, tag_ids))
                    self.logger.info(
                        "Successfully upserted endpoint: "
                        f"{asset.name} ({asset.external_reference})"
                    )
                except Exception as err:
                    self.logger.error(f"Failed to upsert endpoint {asset.name}: {err}")
            self.logger.info("OVHcloud collection completed")
        except Exception as err:
            self.logger.error(f"Error during OVHcloud collection: {err}")


def main():
    for key in ENV_KEYS:
        if not os.environ.get(f"COLLECTOR_{key}") and os.environ.get(key):
            os.environ[f"COLLECTOR_{key}"] = os.environ.get(key)

    OpenAEVOvhcloud(configuration=ConfigLoader().to_daemon_config()).start()
