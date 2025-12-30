"""Essential polyfactory factories for Splunk ES models and test fixtures."""

import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List
from unittest.mock import Mock

from polyfactory import Use
from polyfactory.factories.pydantic_factory import ModelFactory
from src.collector.models import ExpectationResult, ExpectationTrace
from src.models.configs.collector_configs import _ConfigLoaderOAEV
from src.models.configs.config_loader import ConfigLoader, ConfigLoaderCollector
from src.models.configs.splunkes_configs import _ConfigLoaderSplunkES
from src.services.models import SplunkESAlert, SplunkESSearchCriteria


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


class ConfigLoaderSplunkESFactory(ModelFactory[_ConfigLoaderSplunkES]):
    """Factory for Splunk ES configuration.

    Creates test instances of Splunk ES configuration with required
    environment variables automatically set.
    """

    __check_model__ = False

    @classmethod
    def build(cls, **kwargs):
        """Build the model with required environment variables set.

        Args:
            **kwargs: Additional keyword arguments for model creation.

        Returns:
            _ConfigLoaderSplunkES instance with test configuration.

        """
        os.environ["SPLUNKES_BASE_URL"] = "https://test-splunk.example.com:8089"
        os.environ["SPLUNKES_USERNAME"] = "test-user"
        os.environ["SPLUNKES_PASSWORD"] = "test-password"  # noqa: S105
        os.environ["SPLUNKES_ALERTS_INDEX"] = "_notable"
        return super().build(**kwargs)


class ConfigLoaderCollectorFactory(ModelFactory[ConfigLoaderCollector]):
    """Factory for Collector configuration.

    Creates test instances of collector configuration with auto-generated
    UUIDs and sensible defaults.
    """

    __check_model__ = False

    id = Use(lambda: f"splunk-es--{uuid.uuid4()}")
    name = "Splunk ES"


class ConfigLoaderFactory(ModelFactory[ConfigLoader]):
    """Factory for main configuration.

    Creates complete test configuration instances combining OpenAEV,
    collector, and Splunk ES settings using subfactories.
    """

    __check_model__ = False

    openaev = Use(ConfigLoaderOAEVFactory.build)
    collector = Use(ConfigLoaderCollectorFactory.build)
    splunk_es = Use(ConfigLoaderSplunkESFactory.build)


class SplunkESSearchCriteriaFactory(ModelFactory[SplunkESSearchCriteria]):
    """Factory for SplunkESSearchCriteria.

    Creates test instances of Splunk ES search criteria with
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


class SplunkESAlertFactory(ModelFactory[SplunkESAlert]):
    """Factory for Splunk ES alerts.

    Creates test instances of Splunk ES alert objects with
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
    inject_expectation_trace_source_id = Use(lambda: f"splunk-es--{uuid.uuid4()}")
    inject_expectation_trace_alert_name = "Splunk ES Detection Alert"
    inject_expectation_trace_alert_link = Use(
        lambda: f"https://test-splunk.example.com:8000/en-US/app/search/search?q=test-{uuid.uuid4().hex[:8]}"
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
        """Create mock Splunk ES client API.

        Returns:
            Mock SplunkESClientAPI instance with basic attributes set.

        """
        mock_client = Mock()
        mock_client.base_url = "https://test-splunk.example.com:8089"
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
            expectation_type: Type of expectation ("detection" only for Splunk ES).
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
    def create_mixed_splunk_es_data() -> List[Any]:
        """Create mixed Splunk ES data (alerts).

        Returns:
            List containing SplunkESAlert instances.

        """
        return create_test_splunk_alerts(count=3)

    @staticmethod
    def create_api_response_data() -> Dict[str, Any]:
        """Create mock Splunk ES API response data.

        Returns:
            Dictionary simulating Splunk ES search API response.

        """
        return {
            "results": [
                {
                    "_time": "2024-01-01T12:30:00Z",
                    "src_ip": "192.168.1.100",
                    "dst_ip": "10.0.0.50",
                    "signature": "Malicious Traffic Detected",
                    "rule_name": "High Risk Connection",
                    "event_type": "Security Alert",
                    "severity": "High",
                    "_raw": "test raw event data",
                },
                {
                    "_time": "2024-01-01T12:31:00Z",
                    "source_ip": "172.16.0.10",
                    "destination_ip": "203.0.113.5",
                    "signature": "Suspicious Activity",
                    "rule_name": "Network Anomaly",
                    "event_type": "Network Alert",
                    "severity": "Medium",
                    "_raw": "test raw network data",
                },
            ]
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


def create_test_splunk_alerts(count: int = 1) -> List[SplunkESAlert]:
    """Create test Splunk ES alerts with varied IP configurations.

    Args:
        count: Number of alerts to create (default 1).

    Returns:
        List of SplunkESAlert instances with test data.

    """
    alerts = []
    for i in range(count):
        if i % 2 == 0:
            alert = SplunkESAlertFactory.build(
                src_ip=f"192.168.1.{100 + i}",
                dst_ip=f"10.0.0.{50 + i}",
            )
        else:
            alert = SplunkESAlertFactory.build(
                source_ip=f"172.16.0.{10 + i}",
                destination_ip=f"203.0.113.{5 + i}",
                src_ip=None,
                dst_ip=None,
            )
        alerts.append(alert)
    return alerts


def create_test_search_criteria(**overrides) -> SplunkESSearchCriteria:
    """Create test search criteria.

    Args:
        **overrides: Criteria values to override defaults.

    Returns:
        SplunkESSearchCriteria instance with test configuration.

    """
    return SplunkESSearchCriteriaFactory.build(**overrides)
