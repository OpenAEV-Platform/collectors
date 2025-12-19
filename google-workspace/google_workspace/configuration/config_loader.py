from google_workspace.configuration.collector_config_override import \
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
                # Google workspace
                "google_workspace_service_account_json": {
                    "data": self.collector.google_workspace_service_account_json
                },
                "google_workspace_delegated_admin_email": {
                    "data": self.collector.google_workspace_delegated_admin_email
                },
                "google_workspace_customer_id": {
                    "data": self.collector.google_workspace_customer_id
                },
                "include_suspended": {"data": self.collector.include_suspended},
                "sync_all_users": {"data": self.collector.sync_all_users},
            },
            config_base_model=self,
        )
