"""Configuration loader."""

import logging

from pydantic import ValidationError

from src.models import ConfigLoader

LOG_PREFIX = "[CollectorConfig]"


class SplunkESConfig:
    """Class for loading Splunk Enterprise Security configuration."""

    def __init__(self) -> None:
        """Initialize Splunk Enterprise Security configuration loader.

        Loads configuration from YAML files, environment variables, and defaults.
        Sets up logging and validates the configuration structure.

        Raises:
            ValueError: If configuration loading or validation fails.

        """
        self.logger = logging.getLogger(__name__)
        self.logger.debug(
            f"{LOG_PREFIX} Initializing Splunk Enterprise Security configuration loader"
        )
        self.load = self._load_config()
        self.logger.info(
            f"{LOG_PREFIX} Splunk Enterprise Security configuration loaded successfully"
        )

    def _load_config(self) -> ConfigLoader:
        """Load configuration with proper error handling and logging.

        Loads configuration from multiple sources and validates the structure.
        Logs configuration details for debugging purposes.

        Returns:
            ConfigLoader instance with validated configuration.

        Raises:
            ValueError: If configuration validation or loading fails.

        """
        try:
            self.logger.debug(
                f"{LOG_PREFIX} Loading configuration from sources (YAML/ENV/defaults)"
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
            self.logger.debug(f"{LOG_PREFIX} OpenBAS URL: {load_settings.openbas.url}")
            self.logger.debug(
                f"{LOG_PREFIX} Splunk Enterprise Security base URL: {load_settings.splunk_es.base_url}"
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
