from pydantic import Field
from pyoaev.configuration import ConfigLoaderOAEV, Configuration, SettingsLoader

from scenarios.configuration.collector_config_override import CollectorConfigOverride
from scenarios.configuration.source_config import SourceConfig


class ConfigLoader(SettingsLoader):
    openaev: ConfigLoaderOAEV = Field(default_factory=ConfigLoaderOAEV)
    collector: CollectorConfigOverride = Field(default_factory=CollectorConfigOverride)
    scenarios: SourceConfig = Field(default_factory=SourceConfig)

    def to_daemon_config(self) -> Configuration:
        token = self.scenarios.github_token
        return Configuration(
            config_hints={
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
                # Source configuration (flattened)
                "scenarios_repository": {"data": self.scenarios.repository},
                "scenarios_channel": {"data": self.scenarios.channel},
                "scenarios_github_api_url": {"data": self.scenarios.github_api_url},
                "scenarios_github_token": {
                    "data": token.get_secret_value() if token is not None else None
                },
                # As text: pyoaev gives a boolean back as 1 or 0, and "true" or "false" as one.
                "scenarios_dry_run": {"data": str(self.scenarios.dry_run).lower()},
            },
            config_base_model=self,
        )
