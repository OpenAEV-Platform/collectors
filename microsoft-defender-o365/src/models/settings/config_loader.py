"""Base class for global config models."""

from pathlib import Path

from pydantic import Field
from pydantic_settings import (
    BaseSettings,
    DotEnvSettingsSource,
    EnvSettingsSource,
    PydanticBaseSettingsSource,
    YamlConfigSettingsSource,
)
from pyoaev.configuration import Configuration
from src.models.settings import (
    ConfigBaseSettings,
    _ConfigLoaderCollector,
    _ConfigLoaderOAEV,
    _ConfigLoaderSource,
)


class ConfigLoaderCollector(_ConfigLoaderCollector):
    """Basic collector configurations.

    Extends the base collector configuration with specific default values
    for the Microsoft Defender for Office 365 collector instance.
    """

    id: str = Field(
        alias="COLLECTOR_ID",
        default="microsoft-defender-o365--0b13e3f7-5c9e-46f5-acc4-33032e9b4921",
        description="A unique UUIDv4 identifier for this collector instance.",
    )
    name: str = Field(
        alias="COLLECTOR_NAME",
        default="Microsoft Defender for Office 365",
        description="Name of the collector.",
    )


class ConfigLoader(ConfigBaseSettings):
    """Configuration loader for the collector.

    Main configuration class that combines OpenAEV, collector, and source
    settings. Supports loading from YAML files, environment variables, and
    provides methods for converting to daemon-compatible format.
    """

    openaev: _ConfigLoaderOAEV = Field(
        default_factory=_ConfigLoaderOAEV,  # type: ignore[unused-ignore]
        description="OpenAEV configurations.",
    )
    collector: ConfigLoaderCollector = Field(
        default_factory=ConfigLoaderCollector,  # type: ignore[unused-ignore]
        description="Collector configurations.",
    )
    source: _ConfigLoaderSource = Field(
        default_factory=_ConfigLoaderSource,
        description="Source configurations.",
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource]:
        """Pydantic settings customisation sources.

        Defines the priority order for loading configuration settings:
        1. .env file (if exists)
        2. config.yml file (if exists)
        3. Environment variables (fallback)

        Args:
            settings_cls: The settings class being configured.
            init_settings: Initialization settings source.
            env_settings: Environment variables settings source.
            dotenv_settings: .env file settings source.
            file_secret_settings: File secrets settings source.

        Returns:
            Tuple containing the selected settings source.

        """
        env_path = Path(__file__).parents[3] / ".env"
        yaml_path = Path(__file__).parents[3] / "config.yml"

        if env_path.exists():
            return (
                DotEnvSettingsSource(
                    settings_cls,
                    env_file=env_path,
                    env_ignore_empty=True,
                    env_file_encoding="utf-8",
                ),
            )

        if yaml_path.exists():
            return (
                YamlConfigSettingsSource(
                    settings_cls,
                    yaml_file=yaml_path,
                    yaml_file_encoding="utf-8",
                ),
            )

        return (
            EnvSettingsSource(
                settings_cls,
                env_ignore_empty=True,
            ),
        )

    def to_daemon_config(self) -> Configuration:
        """Convert the nested configuration to the flat format expected by BaseDaemon.

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
                "openaev_tenant_id": {"data": self.openaev.tenant_id},
                # Collector configuration (flattened)
                "collector_id": {"data": self.collector.id},
                "collector_name": {"data": self.collector.name},
                "collector_platform": {"data": self.collector.platform},
                "collector_log_level": {"data": self.collector.log_level},
                "collector_period": {
                    "data": int(self.collector.period.total_seconds())
                },  # type: ignore[union-attr]
                "collector_icon_filepath": {"data": self.collector.icon_filepath},
                # Source configuration (flattened)
                "source_tenant_id": {"data": self.source.tenant_id},
                "source_client_id": {"data": self.source.client_id},
                "source_use_certificate_auth": {
                    "data": self.source.use_certificate_auth
                },
                "source_client_secret": {"data": self.source.client_secret},
                "source_client_cert_path": {"data": self.source.client_cert_path},
                "source_client_cert_thumbprint": {
                    "data": self.source.client_cert_thumbprint
                },
                "source_base_url": {"data": self.source.base_url},
                "source_filter_service_source": {
                    "data": self.source.filter_service_source
                },
                "source_rate_limit_requests_per_minute": {
                    "data": self.source.rate_limit_requests_per_minute
                },
                "source_max_fetch_retries": {"data": self.source.max_fetch_retries},
            },
            config_base_model=self,
        )
