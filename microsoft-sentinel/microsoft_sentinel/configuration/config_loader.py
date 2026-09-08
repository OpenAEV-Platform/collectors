from microsoft_sentinel.configuration.collector_config_override import (
    CollectorConfigOverride,
)
from pydantic import Field
from pyoaev.configuration import ConfigLoaderOAEV, Configuration, SettingsLoader


class ConfigLoader(SettingsLoader):
    openaev: ConfigLoaderOAEV = Field(default_factory=ConfigLoaderOAEV)
    collector: CollectorConfigOverride = Field(default_factory=CollectorConfigOverride)

    def to_daemon_config(self) -> Configuration:
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
                "collector_platform": {"data": self.collector.platform},
                "collector_platform_description": {
                    "data": self.collector.platform_description
                },
                "collector_platform_tags": {"data": self.collector.platform_tags},
                "collector_period": {
                    "data": int(self.collector.period.total_seconds()),  # type: ignore[union-attr]
                    "is_number": True,
                },
                "collector_icon_filepath": {"data": self.collector.icon_filepath},
                # Microsoft Sentinel
                "microsoft_sentinel_tenant_id": {
                    "data": self.collector.microsoft_sentinel_tenant_id
                },
                "microsoft_sentinel_client_id": {
                    "data": self.collector.microsoft_sentinel_client_id
                },
                "microsoft_sentinel_use_certificate_auth": {
                    "data": self.collector.microsoft_sentinel_use_certificate_auth
                },
                "microsoft_sentinel_client_secret": {
                    "data": (
                        self.collector.microsoft_sentinel_client_secret.get_secret_value()
                        if self.collector.microsoft_sentinel_client_secret
                        else None
                    )
                },
                "microsoft_sentinel_client_cert_data": {
                    "data": (
                        self.collector.microsoft_sentinel_client_cert_data.get_secret_value()
                        if self.collector.microsoft_sentinel_client_cert_data
                        else None
                    )
                },
                "microsoft_sentinel_client_cert_thumbprint": {
                    "data": (
                        self.collector.microsoft_sentinel_client_cert_thumbprint.get_secret_value()
                        if self.collector.microsoft_sentinel_client_cert_thumbprint
                        else None
                    )
                },
                "microsoft_sentinel_client_cert_passphrase": {
                    "data": (
                        self.collector.microsoft_sentinel_client_cert_passphrase.get_secret_value()
                        if self.collector.microsoft_sentinel_client_cert_passphrase
                        else None
                    )
                },
                "microsoft_sentinel_subscription_id": {
                    "data": self.collector.microsoft_sentinel_subscription_id
                },
                "microsoft_sentinel_workspace_id": {
                    "data": self.collector.microsoft_sentinel_workspace_id
                },
                "microsoft_sentinel_resource_group": {
                    "data": self.collector.microsoft_sentinel_resource_group
                },
                "microsoft_sentinel_edr_collectors": {
                    "data": self.collector.microsoft_sentinel_edr_collectors
                },
            },
            config_base_model=self,
        )
