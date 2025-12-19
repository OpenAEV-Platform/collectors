from microsoft_intune.configuration.collector_config_override import \
    CollectorConfigOverride
from pydantic import Field
from pyoaev.configuration import (ConfigLoaderOAEV, Configuration,
                                  SettingsLoader)


class ConfigLoader(SettingsLoader):
    openaev: ConfigLoaderOAEV = Field(default_factory=ConfigLoaderOAEV)
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
                "collector_log_level": {"data": self.collector.log_level},
                "collector_period": {
                    "data": int(self.collector.period.total_seconds()),  # type: ignore[union-attr]
                    "is_number": True,
                },
                "collector_icon_filepath": {"data": self.collector.icon_filepath},
                # NVD NIST CVE
                "microsoft_intune_tenant_id": {
                    "data": self.collector.microsoft_intune_tenant_id
                },
                "microsoft_intune_client_id": {
                    "data": self.collector.microsoft_intune_client_id
                },
                "microsoft_intune_client_secret": {
                    "data": self.collector.microsoft_intune_client_secret.get_secret_value()
                },
                "microsoft_intune_device_filter": {
                    "data": self.collector.microsoft_intune_device_filter
                },
                "microsoft_intune_device_groups": {
                    "data": self.collector.microsoft_intune_device_groups
                },
            },
            config_base_model=self,
        )
