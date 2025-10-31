"""Essential polyfactory factories for SentinelOne models and test fixtures."""

import os
import uuid
from typing import Any
from unittest.mock import Mock

from polyfactory import Use
from polyfactory.factories.pydantic_factory import ModelFactory
from src.collector.models import ExpectationResult, ExpectationTrace
from src.models.configs.collector_configs import _ConfigLoaderOAEV
from src.models.configs.config_loader import ConfigLoader, ConfigLoaderCollector
from src.models.configs.sentinelone_configs import _ConfigLoaderSentinelOne
from src.services.model_threat import SentinelOneThreat


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
        os.environ["OPENAEV_URL"] = "https://test-openaev.example.com"
        os.environ["OPENAEV_TOKEN"] = "test-openaev-token-12345"  # noqa: S105
        return super().build(**kwargs)


class ConfigLoaderSentinelOneFactory(ModelFactory[_ConfigLoaderSentinelOne]):
    """Factory for SentinelOne configuration.

    Creates test instances of SentinelOne configuration with required
    environment variables automatically set.
    """

    __check_model__ = False

    @classmethod
    def build(cls, **kwargs):
        """Build the model with required environment variables set.

        Args:
            **kwargs: Additional keyword arguments for model creation.

        Returns:
            _ConfigLoaderSentinelOne instance with test configuration.

        """
        os.environ["SENTINELONE_API_KEY"] = "test-sentinelone-api-key"
        os.environ["SENTINELONE_BASE_URL"] = "https://test-sentinelone.example.com"
        return super().build(**kwargs)


class ConfigLoaderCollectorFactory(ModelFactory[ConfigLoaderCollector]):
    """Factory for Collector configuration.

    Creates test instances of collector configuration with auto-generated
    UUIDs and sensible defaults.
    """

    __check_model__ = False

    id = Use(lambda: f"sentinelone--{uuid.uuid4()}")
    name = "SentinelOne"


class ConfigLoaderFactory(ModelFactory[ConfigLoader]):
    """Factory for main configuration.

    Creates complete test configuration instances combining OpenAEV,
    collector, and SentinelOne settings using subfactories.
    """

    __check_model__ = False

    openaev = Use(ConfigLoaderOAEVFactory.build)
    collector = Use(ConfigLoaderCollectorFactory.build)
    sentinelone = Use(ConfigLoaderSentinelOneFactory.build)


class SentinelOneThreatFactory(ModelFactory[SentinelOneThreat]):
    """Factory for SentinelOne threats.

    Creates test instances of SentinelOne threat objects with
    auto-generated threat IDs.
    """

    __check_model__ = False


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


class MockObjectsFactory:
    """Factory for creating mock objects.

    Provides static methods for creating various mock objects
    used throughout the test suite.
    """

    @staticmethod
    def create_mock_client_api():
        """Create mock SentinelOne client API.

        Returns:
            Mock SentinelOneClientAPI instance with basic attributes set.

        """
        mock_client = Mock()
        mock_client.base_url = "https://test-api.example.com"
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
            expectation_type: Type of expectation ("detection" or "prevention").
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
        return mock_session


class TestDataFactory:
    """Factory for creating essential test data.

    Provides static methods for creating complex test data structures
    that simulate real-world scenarios.
    """

    @staticmethod
    def create_expectation_signatures(
        signature_type: str = "parent_process_name", signature_value: str = None
    ) -> list[dict[str, Any]]:
        """Create expectation signatures.

        Args:
            signature_type: Type of signature to create.
            signature_value: Optional custom signature value.

        Returns:
            List of signature dictionaries for testing.

        """
        if signature_value is None:
            signature_value = f"test-{signature_type}-{uuid.uuid4().hex[:8]}"

        return [{"type": signature_type, "value": signature_value}]

    @staticmethod
    def create_oaev_detection_data() -> list[dict[str, Any]]:
        """Create OAEV detection data.

        Returns:
            List of OAEV-formatted detection data dictionaries.

        """
        return [
            {
                "parent_process_name": {
                    "type": "simple",
                    "data": [f"oaev-implant-test-{uuid.uuid4().hex[:8]}"],
                },
                "threat_id": {
                    "type": "simple",
                    "data": [f"threat-{uuid.uuid4().hex[:8]}"],
                },
            }
        ]

    @staticmethod
    def create_oaev_prevention_data() -> list[dict[str, Any]]:
        """Create OAEV prevention data.

        Returns:
            List of OAEV-formatted prevention data dictionaries.

        """
        return [
            {
                "parent_process_name": {
                    "type": "simple",
                    "data": [f"oaev-implant-test-{uuid.uuid4().hex[:8]}"],
                },
                "threat_id": {
                    "type": "simple",
                    "data": [f"threat-{uuid.uuid4().hex[:8]}"],
                },
            }
        ]

    @staticmethod
    def create_mixed_sentinelone_data() -> list[Any]:
        """Create mixed SentinelOne data (DV events + threats).

        Returns:
            List containing both DV event dicts and SentinelOneThreat instances.

        """
        return []


# Helper functions
def create_test_config(**overrides) -> ConfigLoader:
    """Create test configuration.

    Args:
        **overrides: Configuration values to override defaults.

    Returns:
        ConfigLoader instance with test configuration.

    """
    return ConfigLoaderFactory.build(**overrides)


def create_test_dv_events(count: int = 1) -> list[dict]:
    """Create test Deep Visibility events.

    Args:
        count: Number of DV events to create (default 1).

    Returns:
        List of dictionary representations of DV events for testing.

    """
    events = []
    for i in range(count):
        events.append(
            {
                "src_proc_parent_name": f"oaev-implant-test-{uuid.uuid4().hex[:8]}",
                "src_proc_name": f"process-{i}.exe",
                "event_type": "process_creation",
                "timestamp": "2024-01-01T10:00:00Z",
            }
        )
    return events


def create_test_threats(count: int = 1) -> list[SentinelOneThreat]:
    """Create test SentinelOne threats.

    Args:
        count: Number of threats to create (default 1).

    Returns:
        List of SentinelOneThreat instances for testing.

    """
    return [SentinelOneThreatFactory.build() for _ in range(count)]
