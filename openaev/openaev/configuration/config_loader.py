from pyoaev.configuration import Configuration, SettingsLoader
from openaev.configuration.collector_config_override import CollectorConfigOverride
from openaev.configuration.openaev_config_override import OpenaevConfigOverride

from pydantic import Field

class ConfigLoader(SettingsLoader):
    openaev: OpenaevConfigOverride = Field(default_factory=OpenaevConfigOverride)
    collector: CollectorConfigOverride = Field(default_factory=CollectorConfigOverride)

    def to_daemon_config(self) -> Configuration:
        return Configuration(
            config_hints={
                # OpenAEV configuration (flattened)
                "openaev_url": {"data": str(self.openaev.url)},
                "openaev_token": {"data": self.openaev.token},
                # Collector configuration (flattened)
                "collector_id": {"data": self.collector.id},
                "collector_name": {"data": self.collector.name},
                "collector_platform": {"data": self.collector.platform},
                "collector_log_level": {"data": self.collector.log_level},
                "collector_period": {
                    "data": int(self.collector.period.total_seconds()),  # type: ignore[union-attr]
                    "is_number": True,
                },
                "collector_icon_filepath": {"data": self.collector.icon_filepath},
                "openaev_url_prefix": {"data": self.openaev.url_prefix},
                "openaev_import_only_native": {"data": self.openaev.import_only_native},
            },
            config_base_model=self
        )