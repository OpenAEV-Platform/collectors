"""Essential polyfactory factories for LogRhythm models and test fixtures."""

import contextlib
import os
import uuid
from collections.abc import Iterator, Mapping
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from unittest.mock import Mock

from polyfactory import Use
from polyfactory.factories.pydantic_factory import ModelFactory
from src.collector.models import ExpectationResult, ExpectationTrace
from src.models.configs.collector_configs import _ConfigLoaderOAEV
from src.models.configs.config_loader import ConfigLoader, ConfigLoaderCollector
from src.models.configs.logrhythm_configs import _ConfigLoaderLogRhythm
from src.services.models import LogRhythmAlert, LogRhythmSearchCriteria


@contextlib.contextmanager
def _temporary_env(
    updates: Mapping[str, str], remove: Optional[list[str]] = None
) -> Iterator[None]:
    """Temporarily set/unset environment variables, restoring prior state.

    The factories must populate the environment while the settings-based models
    are constructed (the parent ``ConfigLoader`` rebuilds its nested settings
    from the environment), but they must not leak that state to other tests.
    This snapshots every affected key and restores it on exit so factory
    ``build()`` calls are side-effect free and not order-dependent.

    Args:
        updates: Mapping of environment variable names to values to set.
        remove: Optional list of environment variable names to unset.

    Yields:
        None.

    """
    remove = list(remove or [])
    affected = set(updates) | set(remove)
    saved = {key: os.environ.get(key) for key in affected}
    try:
        for key, value in updates.items():
            os.environ[key] = value
        for key in remove:
            os.environ.pop(key, None)
        yield
    finally:
        for key, previous in saved.items():
            if previous is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = previous


class ConfigLoaderOAEVFactory(ModelFactory[_ConfigLoaderOAEV]):
    """Factory for OpenAEV configuration.

    Creates test instances of OpenAEV configuration with required
    environment variables automatically set.
    """

    __check_model__ = False

    @classmethod
    def build(cls, **kwargs):
        """Build the model with required environment variables set.

        Args:
            **kwargs: Additional keyword arguments for model creation.

        Returns:
            _ConfigLoaderOAEV instance with test configuration.

        """
        with _temporary_env(
            {
                "OPENAEV_URL": "https://test-openaev.example.com",
                "OPENAEV_TOKEN": "test-openaev-token-12345",  # noqa: S105
            }
        ):
            return super().build(**kwargs)


class ConfigLoaderLogRhythmFactory(ModelFactory[_ConfigLoaderLogRhythm]):
    """Factory for LogRhythm configuration.

    Constructs deterministic test instances of the LogRhythm
    configuration (basic authentication, instant retries). The model is built
    directly so values are passed as the highest-priority init source and are
    never overridden by ambient environment variables.
    """

    __check_model__ = False

    token = Use(lambda: "test-token")  # noqa: S106
    username = Use(lambda: None)
    password = Use(lambda: None)

    @classmethod
    def build(cls, **kwargs):
        """Build the model with required environment variables set.

        Two build paths must both yield valid auth: polyfactory's own field
        generation (covered by the ``Use`` overrides above) and the nested
        ``logrhythm`` settings rebuilt from the environment when the parent
        ``ConfigLoader`` is constructed (covered by the env vars below).

        Args:
            **kwargs: Additional keyword arguments for model creation.

        Returns:
            _ConfigLoaderLogRhythm instance with test configuration.

        """
        with _temporary_env(
            {
                "LOGRHYTHM_BASE_URL": "https://test-logrhythm.example.com",
                "LOGRHYTHM_TOKEN": "test-token",  # noqa: S105
                "LOGRHYTHM_API_VERSION": "20.0",
                "LOGRHYTHM_MAX_RETRY": "1",
                "LOGRHYTHM_OFFSET": "PT0S",
                "LOGRHYTHM_POLL_INTERVAL": "PT0S",
                "LOGRHYTHM_SEARCH_TIMEOUT": "PT5S",
            },
            remove=[
                "LOGRHYTHM_USERNAME",
                "LOGRHYTHM_PASSWORD",
                "LOGRHYTHM_CONSOLE_URL",
            ],
        ):
            return super().build(**kwargs)


class ConfigLoaderCollectorFactory(ModelFactory[ConfigLoaderCollector]):
    """Factory for Collector configuration.

    Creates test instances of collector configuration with auto-generated
    UUIDs and sensible defaults.
    """

    __check_model__ = False

    id = Use(lambda: f"logrhythm--{uuid.uuid4()}")
    name = "LogRhythm"


class ConfigLoaderFactory(ModelFactory[ConfigLoader]):
    """Factory for main configuration.

    Creates complete test configuration instances combining OpenAEV,
    collector, and LogRhythm settings using subfactories.
    """

    __check_model__ = False

    openaev = Use(ConfigLoaderOAEVFactory.build)
    collector = Use(ConfigLoaderCollectorFactory.build)
    logrhythm = Use(ConfigLoaderLogRhythmFactory.build)

    @classmethod
    def build(cls, **kwargs):
        """Build the full config with required env vars set during construction.

        The parent ``ConfigLoader`` rebuilds its nested ``openaev`` / ``logrhythm``
        settings from the environment (see the ``disable_config_yml`` fixture in
        ``tests/conftest.py``), so the environment must stay populated for the
        whole build - the sub-factory restores only roll back to the values set
        here. This wrapper restores the original environment on exit so no state
        leaks across tests.

        Args:
            **kwargs: Additional keyword arguments for model creation.

        Returns:
            ConfigLoader instance with test configuration.

        """
        with _temporary_env(
            {
                "OPENAEV_URL": "https://test-openaev.example.com",
                "OPENAEV_TOKEN": "test-openaev-token-12345",  # noqa: S105
                "LOGRHYTHM_BASE_URL": "https://test-logrhythm.example.com",
                "LOGRHYTHM_TOKEN": "test-token",  # noqa: S105
                "LOGRHYTHM_API_VERSION": "20.0",
                "LOGRHYTHM_MAX_RETRY": "1",
                "LOGRHYTHM_OFFSET": "PT0S",
                "LOGRHYTHM_POLL_INTERVAL": "PT0S",
                "LOGRHYTHM_SEARCH_TIMEOUT": "PT5S",
            },
            remove=[
                "LOGRHYTHM_USERNAME",
                "LOGRHYTHM_PASSWORD",
                "LOGRHYTHM_CONSOLE_URL",
            ],
        ):
            return super().build(**kwargs)


class LogRhythmSearchCriteriaFactory(ModelFactory[LogRhythmSearchCriteria]):
    """Factory for LogRhythmSearchCriteria.

    Creates test instances of LogRhythm search criteria with
    realistic IP addresses and date ranges for queries.
    """

    __check_model__ = False

    source_ips = Use(lambda: ["192.168.1.100", "10.0.0.50"])
    target_ips = Use(lambda: ["172.16.0.10", "203.0.113.5"])
    start_date = Use(
        lambda: (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat() + "Z"
    )
    end_date = Use(
        lambda: (datetime.now(timezone.utc) + timedelta(microseconds=1)).isoformat()
        + "Z"
    )


class LogRhythmAlertFactory(ModelFactory[LogRhythmAlert]):
    """Factory for LogRhythm alerts.

    Creates test instances of LogRhythm alert objects with
    randomized IP addresses and alert metadata.
    """

    __check_model__ = False

    time = Use(lambda: datetime.now(timezone.utc).isoformat() + "Z")
    src_ip = Use(lambda: f"192.168.1.{uuid.uuid4().int % 255}")
    dst_ip = Use(lambda: f"10.0.0.{uuid.uuid4().int % 255}")
    signature = Use(lambda: f"Test Malicious Activity {uuid.uuid4().hex[:8]}")
    rule_name = Use(lambda: f"Test Security Rule {uuid.uuid4().hex[:8]}")
    event_type = "Security Alert"
    severity = "High"


class ExpectationResultFactory(ModelFactory[ExpectationResult]):
    """Factory for ExpectationResult.

    Creates test instances of expectation processing results with
    valid expectation IDs and configurable validation status.
    """

    __check_model__ = False

    expectation_id = Use(lambda: str(uuid.uuid4()))
    is_valid = True
    error_message = None
    matched_alerts = Use(lambda: [])


class ExpectationTraceFactory(ModelFactory[ExpectationTrace]):
    """Factory for ExpectationTrace.

    Creates test instances of expectation traces for OpenAEV
    with properly formatted trace data.
    """

    __check_model__ = False

    inject_expectation_trace_expectation = Use(lambda: str(uuid.uuid4()))
    inject_expectation_trace_source_id = Use(lambda: f"logrhythm--{uuid.uuid4()}")
    inject_expectation_trace_alert_name = "LogRhythm Detection Alert"
    inject_expectation_trace_alert_link = Use(
        lambda: f"https://test-logrhythm.example.com:5601/app/security/alerts?query=test-{uuid.uuid4().hex[:8]}"
    )
    inject_expectation_trace_date = Use(
        lambda: datetime.now(timezone.utc).isoformat() + "Z"
    )


# Mock Objects Factory
class MockObjectsFactory:
    """Factory for creating mock objects.

    Provides static methods for creating various mock objects
    used throughout the test suite.
    """

    @staticmethod
    def create_mock_client_api():
        """Create mock LogRhythm client API.

        Returns:
            Mock LogRhythmClientAPI instance with basic attributes set.

        """
        mock_client = Mock()
        mock_client.base_url = "https://test-logrhythm.example.com:9200"
        mock_client.session = Mock()
        mock_client.session.headers = {}
        return mock_client

    @staticmethod
    def create_mock_detection_helper(match_result: bool = True):
        """Create mock detection helper.

        Args:
            match_result: Whether the helper should return matches (default True).

        Returns:
            Mock OpenAEVDetectionHelper instance.

        """
        mock_helper = Mock()
        mock_helper.match_alert_elements.return_value = match_result
        return mock_helper

    @staticmethod
    def create_mock_expectation(
        expectation_type: str = "detection", expectation_id: str = None
    ):
        """Create mock expectation for testing.

        Args:
            expectation_type: Type of expectation ("detection" only for LogRhythm).
            expectation_id: Optional custom expectation ID.

        Returns:
            Mock expectation object with required attributes.

        """
        mock_expectation = Mock()
        mock_expectation.inject_expectation_id = expectation_id or str(uuid.uuid4())
        mock_expectation.inject_expectation_signatures = []
        mock_expectation.expectation_type = expectation_type
        return mock_expectation

    @staticmethod
    def create_mock_session():
        """Create mock requests session.

        Returns:
            Mock requests.Session instance with headers attribute.

        """
        mock_session = Mock()
        mock_session.headers = {}
        mock_session.auth = ("test-user", "test-password")
        return mock_session


# Test Data Factory
class TestDataFactory:
    """Factory for creating essential test data.

    Provides static methods for creating complex test data structures
    that simulate real-world scenarios.
    """

    @staticmethod
    def create_expectation_signatures(
        signature_type: str = "source_ipv4_address", signature_value: str = None
    ) -> List[Dict[str, Any]]:
        """Create expectation signatures.

        Args:
            signature_type: Type of signature to create.
            signature_value: Optional custom signature value.

        Returns:
            List of signature dictionaries for testing.

        """
        if signature_value is None:
            if "ip" in signature_type:
                signature_value = f"192.168.1.{uuid.uuid4().int % 255}"
            else:
                signature_value = f"test-{signature_type}-{uuid.uuid4().hex[:8]}"

        return [{"type": signature_type, "value": signature_value}]

    @staticmethod
    def create_oaev_detection_data() -> List[Dict[str, Any]]:
        """Create OAEV detection data for IP-based matching.

        Returns:
            List of OAEV-formatted detection data dictionaries.

        """
        return [
            {
                "source_ipv4_address": {
                    "type": "simple",
                    "data": f"192.168.1.{uuid.uuid4().int % 255}",
                },
                "target_ipv4_address": {
                    "type": "simple",
                    "data": f"10.0.0.{uuid.uuid4().int % 255}",
                },
                "parent_process_name": {
                    "type": "simple",
                    "data": "test_process.exe",
                },
            }
        ]

    @staticmethod
    def create_mixed_logrhythm_data() -> List[Any]:
        """Create mixed LogRhythm data (alerts).

        Returns:
            List containing LogRhythmAlert instances.

        """
        return create_test_logrhythm_alerts(count=3)

    @staticmethod
    def create_api_response_data() -> Dict[str, Any]:
        """Create mock LogRhythm search-result data.

        Returns:
            Dictionary simulating a completed ``/actions/search-result`` response.

        """
        return {
            "TaskStatus": "Completed",
            "TaskId": "task-123",
            "Items": [
                {
                    "originIp": "192.168.1.100",
                    "impactedIp": "10.0.0.50",
                    "url": "/api/test",
                    "commonEventName": "Malicious Activity Detected",
                    "classificationName": "Suspicious Activity",
                    "normalDateMin": "2024-01-01T12:30:00Z",
                },
                {
                    "originIp": "172.16.0.10",
                    "impactedIp": "203.0.113.5",
                    "commonEventName": "Network Anomaly",
                    "classificationName": "Network",
                    "normalDateMin": "2024-01-01T12:31:00Z",
                },
            ],
        }


# Helper functions
def create_test_config(**overrides) -> ConfigLoader:
    """Create test configuration.

    Args:
        **overrides: Configuration values to override defaults.

    Returns:
        ConfigLoader instance with test configuration.

    """
    return ConfigLoaderFactory.build(**overrides)


def create_test_logrhythm_alerts(count: int = 1) -> List[LogRhythmAlert]:
    """Create test LogRhythm alerts with varied IP configurations.

    Args:
        count: Number of alerts to create (default 1).

    Returns:
        List of LogRhythmAlert instances with test data.

    """
    alerts = []
    for i in range(count):
        if i % 2 == 0:
            alert = LogRhythmAlertFactory.build(
                src_ip=f"192.168.1.{100 + i}",
                dst_ip=f"10.0.0.{50 + i}",
            )
        else:
            # Odd alerts intentionally carry no IPs to exercise the
            # converter's "filter out alerts without IPs" path.
            alert = LogRhythmAlertFactory.build(src_ip=None, dst_ip=None)
        alerts.append(alert)
    return alerts


def create_test_search_criteria(**overrides) -> LogRhythmSearchCriteria:
    """Create test search criteria.

    Args:
        **overrides: Criteria values to override defaults.

    Returns:
        LogRhythmSearchCriteria instance with test configuration.

    """
    return LogRhythmSearchCriteriaFactory.build(**overrides)
