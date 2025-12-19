from pydantic import Field
from pyoaev.configuration import ConfigLoaderOAEV, Configuration, SettingsLoader

from crowdstrike.configuration.collector_config_override import CollectorConfigOverride
from crowdstrike.configuration.crowdstrike_settings import CrowdstrikeSettings


class ConfigLoader(SettingsLoader):
    openaev: ConfigLoaderOAEV = Field(default_factory=ConfigLoaderOAEV)
    collector: CollectorConfigOverride = Field(default_factory=CollectorConfigOverride)
    crowdstrike: CrowdstrikeSettings = Field(default_factory=CrowdstrikeSettings)

    def to_daemon_config(self) -> Configuration:
        """Convert the nested configuration to the list of config hints expected by BaseDaemon.

        Flattens the nested configuration structure into a dictionary format
        that can be consumed by the collector daemon infrastructure.

        Returns:
            Dictionary with flattened configuration keys and values suitable
            for daemon initialization.

        """
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
                # SplunkES configuration (flattened)
                "crowdstrike_client_id": {"data": str(self.crowdstrike.client_id)},
                "crowdstrike_client_secret": {
                    "data": self.crowdstrike.client_secret.get_secret_value()
                },
                "crowdstrike_api_base_url": {"data": self.crowdstrike.api_base_url},
                "crowdstrike_ui_base_url": {"data": self.crowdstrike.ui_base_url},
            },
            config_base_model = self
        )
