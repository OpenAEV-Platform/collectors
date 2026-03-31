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
    BaseConfigLoaderCollector,
    ConfigBaseSettings,
    ConfigLoaderHTTPLogwatcher,
    ConfigLoaderOAEV,
)


class ConfigLoaderCollector(BaseConfigLoaderCollector):
    """Basic collector configurations.

    Extends the base collector configuration with specific default values
    for the HTTP Logwatcher collector instance.
    """

    id: str = Field(
        alias="COLLECTOR_ID",
        default="http-logwatcher--54f5127d-6577-4b01-88c7-da65d3ddabd3",
        description="A unique UUIDv4 identifier for this collector instance.",
    )
    name: str = Field(
        alias="COLLECTOR_NAME",
        default="HTTP Logwatcher",
        description="Name of the collector.",
    )


class ConfigLoader(ConfigBaseSettings):
    """Configuration loader for the collector.

    Main configuration class that combines OpenAEV and collector
    settings. Supports loading from YAML files, environment variables, and
    provides methods for converting to daemon-compatible format.
    """

    openaev: ConfigLoaderOAEV = Field(
        default_factory=ConfigLoaderOAEV,
        description="OpenAEV configurations.",
    )
    collector: ConfigLoaderCollector = Field(
        default_factory=ConfigLoaderCollector,
        description="Collector configurations.",
    )
    http_logwatcher: ConfigLoaderHTTPLogwatcher = Field(
        default_factory=ConfigLoaderHTTPLogwatcher,
        description="HTTPLogwatcher configurations.",
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
        """Pydantic settings customization sources.

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
        env_path = Path(__file__).parents[2] / ".env"
        yaml_path = Path(__file__).parents[2] / "config.yml"

        if env_path.exists():
            return (
                DotEnvSettingsSource(
                    settings_cls,
                    env_file=env_path,
                    env_ignore_empty=True,
                    env_file_encoding="utf-8",
                ),
            )
        elif yaml_path.exists():
            return (
                YamlConfigSettingsSource(
                    settings_cls,
                    yaml_file=yaml_path,
                    yaml_file_encoding="utf-8",
                ),
            )
        else:
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
                # Collector configuration (flattened)
                "collector_id": {"data": self.collector.id},
                "collector_name": {"data": self.collector.name},
                "collector_platform": {"data": self.collector.platform},
                "collector_log_level": {"data": self.collector.log_level},
                "collector_period": {
                    "data": (
                        int(self.collector.period.total_seconds())
                        if self.collector.period
                        else 0
                    )
                },
                "collector_icon_filepath": {"data": self.collector.icon_filepath},
                # HTTPLogwatcher configuration (flattened)
                "http_logwatcher_logs_folder_path": {
                    "data": self.http_logwatcher.logs_folder_path
                },
                "http_logwatcher_time_window": {
                    "data": self.http_logwatcher.time_window
                },
            },
            config_base_model=self,
        )
