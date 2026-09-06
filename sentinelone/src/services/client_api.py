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

        self.is_self_hosted: bool | None = None

        self.logger.debug(
            f"{LOG_PREFIX} Initializing SentinelOne API client components..."
        )

        self.logger.info(
            f"{LOG_PREFIX} SentinelOne API client initialized successfully"
        )

        self.detect_is_self_hosted()

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

    def detect_is_self_hosted(self) -> bool:
        """Resolve whether the SentinelOne instance is self-hosted.

        Detection is fully automatic: the MGMT account listing endpoint is
        probed to decide (SaaS accounts expose an accountType field,
        self-hosted instances do not). The resolved boolean is cached on
        the client instance, so the probe runs at most once per client and
        services can read the result from the attribute.

        Returns:
            True if the instance is self-hosted, False if it is SaaS.

        """
        if self.is_self_hosted is not None:
            return self.is_self_hosted

        self.is_self_hosted = self._probe_self_hosted()
        return self.is_self_hosted

    def _probe_self_hosted(self) -> bool:
        """Probe the MGMT account listing to detect SaaS vs self-hosted.

        Calls the account listing endpoint the connector already uses
        (GET {base_url}/web/api/v2.1/accounts). A successful response
        containing at least one account object with an accountType field
        identifies a SaaS instance (e.g. accountType=Trial); a successful
        response without accountType identifies a self-hosted instance.
        Any probe failure (HTTP error such as 404/401, network error,
        malformed body) logs a warning and defaults to SaaS (False), so a
        transient failure on a working instance never flips it to
        self-hosted.

        Returns:
            True if the instance is self-hosted, False if it is SaaS.

        """
        endpoint = f"{self.base_url}/web/api/v2.1/accounts"
        try:
            response = self.session.get(endpoint)
            response.raise_for_status()
            accounts = response.json().get("data", [])
        except Exception as e:
            self.logger.warning(
                f"{LOG_PREFIX} Self-hosted probe failed "
                f"({type(e).__name__}: {e}); defaulting to SaaS "
                "(is_self_hosted=False)"
            )
            return False

        for account in accounts:
            if isinstance(account, dict) and "accountType" in account:
                self.logger.info(
                    f"{LOG_PREFIX} SaaS detected "
                    f"(accountType={account['accountType']}); "
                    "is_self_hosted=False"
                )
                return False

        self.logger.info(
            f"{LOG_PREFIX} Self-hosted detected "
            "(no accountType in account listing); is_self_hosted=True"
        )
        return True
