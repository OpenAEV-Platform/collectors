"""Load the configuration from config.yml and the environment for the daemon."""

from github_collector.configuration.collector_config_override import (
    CollectorConfigOverride,
)
from pydantic import Field
from pyoaev.configuration import ConfigLoaderOAEV, Configuration, SettingsLoader

PLAIN_FIELDS = (
    "github_api_url",
    "github_organizations",
    "github_users",
    "github_include_archived",
    "github_include_forks",
    "github_collect_workflows",
    "github_collect_packages",
    "github_package_types",
    "github_end_date_removed",
)


class ConfigLoader(SettingsLoader):  # type: ignore[misc]
    """The whole configuration: the openaev and collector sections."""

    openaev: ConfigLoaderOAEV = Field(default_factory=ConfigLoaderOAEV)
    collector: CollectorConfigOverride = Field(default_factory=CollectorConfigOverride)

    def to_daemon_config(self) -> Configuration:
        """Flatten the settings into the pyoaev daemon configuration."""
        token = self.collector.github_token
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
            "github_token": {
                "data": None if token is None else token.get_secret_value()
            },
        }
        for name in PLAIN_FIELDS:
            hints[name] = {"data": getattr(self.collector, name)}
        return Configuration(
            config_hints=hints,
            config_base_model=self,
        )
