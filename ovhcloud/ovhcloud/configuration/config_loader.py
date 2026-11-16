from ovhcloud.configuration.collector_config_override import (
    CollectorConfigOverride,
)
from pydantic import Field, SecretStr
from pyoaev.configuration import ConfigLoaderOAEV, Configuration, SettingsLoader

SECRET_FIELDS = (
    "ovhcloud_application_key",
    "ovhcloud_application_secret",
    "ovhcloud_consumer_key",
    "ovhcloud_client_id",
    "ovhcloud_client_secret",
)

PLAIN_FIELDS = (
    "ovhcloud_endpoint",
    "ovhcloud_collect_dedicated_servers",
    "ovhcloud_collect_public_cloud",
    "ovhcloud_collect_vps",
    "ovhcloud_collect_hosted_private_cloud",
    "ovhcloud_public_cloud_project_ids",
    "ovhcloud_regions",
    "ovhcloud_name_include",
    "ovhcloud_name_exclude",
    "ovhcloud_iam_tags",
    "ovhcloud_skip_inactive",
    "ovhcloud_include_public_ipv4",
    "ovhcloud_include_public_ipv6",
    "ovhcloud_include_private_ips",
    "ovhcloud_import_tags",
    "ovhcloud_max_workers",
)


def _reveal(value: SecretStr | None) -> str | None:
    """Return the plain text behind an optional secret."""
    return None if value is None else value.get_secret_value()


class ConfigLoader(SettingsLoader):
    openaev: ConfigLoaderOAEV = Field(default_factory=ConfigLoaderOAEV)
    collector: CollectorConfigOverride = Field(default_factory=CollectorConfigOverride)

    def to_daemon_config(self) -> Configuration:
        hints: dict[str, dict[str, object]] = {
            # OpenAEV configuration (flattened)
            "openaev_url": {"data": str(self.openaev.url)},
            "openaev_token": {"data": self.openaev.token},
            "openaev_tenant_id": {"data": self.openaev.tenant_id},
            # Collector configuration (flattened)
            "collector_id": {"data": self.collector.id},
            "collector_name": {"data": self.collector.name},
            "collector_log_level": {"data": self.collector.log_level},
            "collector_period": {
                "data": int(self.collector.period.total_seconds()),  # type: ignore[union-attr]
                "is_number": True,
            },
            "collector_icon_filepath": {"data": self.collector.icon_filepath},
        }
        for name in SECRET_FIELDS:
            hints[name] = {"data": _reveal(getattr(self.collector, name))}
        for name in PLAIN_FIELDS:
            hints[name] = {"data": getattr(self.collector, name)}
        return Configuration(
            config_hints=hints,  # type: ignore[arg-type]
            config_base_model=self,
        )
