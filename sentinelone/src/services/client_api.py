"""SentinelOne API client for session management and core HTTP functionality."""

import logging
from datetime import timedelta

import requests  # type: ignore[import-untyped]

from ..models.configs.config_loader import ConfigLoader
from .exception import SentinelOneSessionError

LOG_PREFIX = "[SentinelOneClientAPI]"


class SentinelOneClientAPI:
    """SentinelOne API client for managing HTTP sessions and core functionality."""

    def __init__(self, config: ConfigLoader) -> None:
        """Initialize SentinelOne API client.

        Args:
            config: Configuration loader with SentinelOne settings.

        Raises:
            SentinelOneValidationError: If configuration is invalid.
            SentinelOneSessionError: If session setup fails.

        """
        self.logger: logging.Logger = logging.getLogger(__name__)
        self.config: ConfigLoader = config

        self.base_url: str = str(config.sentinelone.base_url).rstrip("/")
        self.api_key: str = config.sentinelone.api_key.get_secret_value()

        self.time_window: timedelta = config.sentinelone.time_window

        try:
            self.session: requests.Session = self._create_session()
        except Exception as e:
            raise SentinelOneSessionError(f"Failed to create session: {e}") from e

        self.logger.debug(
            f"{LOG_PREFIX} Initializing SentinelOne API client components..."
        )

        self.logger.info(
            f"{LOG_PREFIX} SentinelOne API client initialized successfully"
        )

    def _create_session(self) -> requests.Session:
        """Create and configure HTTP session for SentinelOne API.

        Returns:
            Configured requests Session object.

        Raises:
            SentinelOneSessionError: If session configuration fails.

        """
        try:
            session = requests.Session()
            session.headers.update(
                {
                    "Authorization": f"ApiToken {self.api_key}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                }
            )

            return session
        except Exception as e:
            raise SentinelOneSessionError(f"Failed to configure session: {e}") from e
