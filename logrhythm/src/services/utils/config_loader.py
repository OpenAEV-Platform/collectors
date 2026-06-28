"""Configuration loader."""

import logging

from pydantic import ValidationError
from src.models import ConfigLoader

LOG_PREFIX = "[CollectorConfig]"


class LogRhythmConfig:
    """Class for loading LogRhythm configuration."""

    def __init__(self) -> None:
        """Initialize LogRhythm configuration loader.

        Loads configuration from a single source selected in priority order:
        src/.env, then src/config.yml, then environment variables. The first
        source found wins and the others are not merged in; field defaults are
        applied for any values absent from the selected source. Sets up logging
        and validates the configuration structure.

        Raises:
            ValueError: If configuration loading or validation fails.

        """
        self.logger = logging.getLogger(__name__)
        self.logger.debug(f"{LOG_PREFIX} Initializing LogRhythm configuration loader")
        self.load = self._load_config()
        self.logger.info(f"{LOG_PREFIX} LogRhythm configuration loaded successfully")

    def _load_config(self) -> ConfigLoader:
        """Load configuration with proper error handling and logging.

        Instantiates ConfigLoader, which selects a single settings source in
        priority order (src/.env, then src/config.yml, then environment
        variables; the first one found wins and they are not merged) and
        applies field defaults for any missing values, then validates the
        structure. Logs configuration details for debugging purposes.

        Returns:
            ConfigLoader instance with validated configuration.

        Raises:
            ValueError: If configuration validation or loading fails.

        """
        try:
            self.logger.debug(
                f"{LOG_PREFIX} Selecting a single configuration source "
                f"(src/.env, then src/config.yml, then environment variables)"
            )
            load_settings = ConfigLoader()

            self.logger.debug(
                f"{LOG_PREFIX} Collector ID: {load_settings.collector.id}"
            )
            self.logger.debug(
                f"{LOG_PREFIX} Collector name: {load_settings.collector.name}"
            )
            self.logger.debug(
                f"{LOG_PREFIX} Log level: {load_settings.collector.log_level}"
            )
            self.logger.debug(f"{LOG_PREFIX} OpenAEV URL: {load_settings.openaev.url}")
            self.logger.debug(
                f"{LOG_PREFIX} LogRhythm base URL: {load_settings.logrhythm.base_url}"
            )

            return load_settings
        except ValidationError as err:
            self.logger.error(
                f"{LOG_PREFIX} Error in configuration validation: {err} (Context: error_type=ValidationError)"
            )
            raise ValueError(f"Configuration validation failed: {err}") from err
        except Exception as err:
            self.logger.error(
                f"{LOG_PREFIX} Error in configuration loading: {err} (Context: error_type={type(err).__name__})"
            )
            raise ValueError(f"Configuration loading failed: {err}") from err
