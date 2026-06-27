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
from src.models.configs import (
    ConfigBaseSettings,
    _ConfigLoaderCollector,
    _ConfigLoaderLogRhythm,
    _ConfigLoaderOAEV,
)


class ConfigLoaderCollector(_ConfigLoaderCollector):
    """Basic collector configurations.

    Extends the base collector configuration with specific default values
    for the LogRhythm collector instance.
    """

    id: str = Field(
        alias="Collector_ID",
        default="logrhythm--0b13e3f7-5c9e-46f5-acc4-33032e9b4921",
        description="A unique UUIDv4 identifier for this collector instance.",
    )
    name: str = Field(
        alias="Collector_NAME",
        default="LogRhythm",
        description="Name of the collector.",
    )


class ConfigLoader(ConfigBaseSettings):
    """Configuration loader for the collector.

    Main configuration class that combines OpenAEV, collector, and LogRhythm
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
    logrhythm: _ConfigLoaderLogRhythm = Field(
        default_factory=_ConfigLoaderLogRhythm,
        description="LogRhythm configurations.",
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
                "openaev_tenant_id": {"data": self.openaev.tenant_id},
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
                # LogRhythm configuration (flattened)
                "logrhythm_base_url": {"data": str(self.logrhythm.base_url)},
                "logrhythm_token": {
                    "data": (
                        self.logrhythm.token.get_secret_value()
                        if self.logrhythm.token
                        else None
                    )
                },
                "logrhythm_username": {"data": self.logrhythm.username},
                "logrhythm_password": {
                    "data": (
                        self.logrhythm.password.get_secret_value()
                        if self.logrhythm.password
                        else None
                    )
                },
                "logrhythm_query_event_manager": {
                    "data": self.logrhythm.query_event_manager
                },
                "logrhythm_max_msgs": {"data": self.logrhythm.max_msgs},
                "logrhythm_console_url": {"data": self.logrhythm.console_url},
                "logrhythm_time_window": {"data": self.logrhythm.time_window},
                "logrhythm_max_retry": {"data": self.logrhythm.max_retry},
                "logrhythm_offset": {"data": self.logrhythm.offset},
                "logrhythm_verify_ssl": {"data": self.logrhythm.verify_ssl},
            },
            config_base_model=self,
        )
