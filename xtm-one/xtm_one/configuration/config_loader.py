from pydantic import Field
from pyoaev.configuration import ConfigLoaderOAEV, Configuration, SettingsLoader
from xtm_one.configuration.collector_config_override import CollectorConfigOverride


class ConfigLoader(SettingsLoader):
    openaev: ConfigLoaderOAEV = Field(default_factory=ConfigLoaderOAEV)
    collector: CollectorConfigOverride = Field(default_factory=CollectorConfigOverride)

    def to_daemon_config(self) -> Configuration:
        return Configuration(
            config_hints={
                "openaev_url": {"data": str(self.openaev.url)},
                "openaev_token": {"data": self.openaev.token},
                "openaev_tenant_id": {"data": self.openaev.tenant_id},
                "collector_id": {"data": self.collector.id},
                "collector_name": {"data": self.collector.name},
                "collector_platform": {"data": self.collector.platform},
                "collector_log_level": {"data": self.collector.log_level},
                "collector_period": {
                    "data": int(self.collector.period.total_seconds()),  # type: ignore[union-attr]
                    "is_number": True,
                },
                "import_period": {
                    "data": int(self.collector.import_period.total_seconds()),  # type: ignore[union-attr]
                    "is_number": True,
                },
                "collector_icon_filepath": {"data": self.collector.icon_filepath},
                "xtm_one_url": {"data": self.collector.xtm_one_url},
                "xtm_one_token": {"data": self.collector.xtm_one_token},
                "validate_expectations": {"data": self.collector.validate_expectations},
                "include_bare_models": {"data": self.collector.include_bare_models},
                "agent_tags": {"data": self.collector.agent_tags},
            },
            config_base_model=self,
        )
