from microsoft_azure.configuration.collector_config_override import (
    CollectorConfigOverride,
)
from pydantic import Field, SecretStr
from pyoaev.configuration import ConfigLoaderOAEV, Configuration, SettingsLoader


def _reveal(value: SecretStr | None) -> str | None:
    """Return the plain text behind an optional secret.

    Credential fields are optional so that a deployment only has to provide the
    material for the authentication mode it actually uses.

    Args:
        value: The optional secret to unwrap.

    Returns:
        The secret value, or None when the secret was not configured.

    """
    return None if value is None else value.get_secret_value()


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
                "collector_period": {
                    "data": int(self.collector.period.total_seconds()),  # type: ignore[union-attr]
                    "is_number": True,
                },
                "collector_icon_filepath": {"data": self.collector.icon_filepath},
                # NVD NIST CVE
                "microsoft_azure_tenant_id": {
                    "data": self.collector.microsoft_azure_tenant_id
                },
                "microsoft_azure_client_id": {
                    "data": self.collector.microsoft_azure_client_id
                },
                "microsoft_azure_use_certificate_auth": {
                    "data": self.collector.microsoft_azure_use_certificate_auth
                },
                "microsoft_azure_client_secret": {
                    "data": _reveal(self.collector.microsoft_azure_client_secret)
                },
                "microsoft_azure_client_cert_data": {
                    "data": _reveal(self.collector.microsoft_azure_client_cert_data)
                },
                "microsoft_azure_client_cert_thumbprint": {
                    "data": _reveal(
                        self.collector.microsoft_azure_client_cert_thumbprint
                    )
                },
                "microsoft_azure_client_cert_passphrase": {
                    "data": _reveal(
                        self.collector.microsoft_azure_client_cert_passphrase
                    )
                },
                "microsoft_azure_subscription_id": {
                    "data": self.collector.microsoft_azure_subscription_id
                },
                "microsoft_azure_resource_groups": {
                    "data": self.collector.microsoft_azure_resource_groups
                },
            },
            config_base_model=self,
        )
