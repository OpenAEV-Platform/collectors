"""Essential polyfactory factories for Elastic Security models and test fixtures."""

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
from src.models.configs.elastic_configs import _ConfigLoaderElastic
from src.services.models import ElasticAlert, ElasticSearchCriteria


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


class ConfigLoaderElasticFactory(ModelFactory[_ConfigLoaderElastic]):
    """Factory for Elastic Security configuration.

    Constructs deterministic test instances of the Elastic Security
    configuration (basic authentication, instant retries). The model is built
    directly so values are passed as the highest-priority init source and are
    never overridden by ambient environment variables.
    """

    __check_model__ = False

    api_key = Use(lambda: None)
    username = Use(lambda: "test-user")
    password = Use(lambda: "test-password")  # noqa: S106

    @classmethod
    def build(cls, **kwargs):
        """Build the model with required environment variables set.

        Two build paths must both yield valid auth: polyfactory's own field
        generation (covered by the ``Use`` overrides above) and the nested
        ``elastic`` settings rebuilt from the environment when the parent
        ``ConfigLoader`` is constructed (covered by the env vars below).

        Args:
            **kwargs: Additional keyword arguments for model creation.

        Returns:
            _ConfigLoaderElastic instance with test configuration.

        """
        os.environ["ELASTIC_BASE_URL"] = "https://test-elastic.example.com:9200"
        os.environ["ELASTIC_USERNAME"] = "test-user"
        os.environ["ELASTIC_PASSWORD"] = "test-password"  # noqa: S105
        os.environ["ELASTIC_ALERTS_INDEX"] = ".alerts-security.alerts-*"
        os.environ["ELASTIC_MAX_RETRY"] = "1"
        os.environ["ELASTIC_OFFSET"] = "PT0S"
        os.environ.pop("ELASTIC_API_KEY", None)
        os.environ.pop("ELASTIC_KIBANA_URL", None)
        return super().build(**kwargs)


class ConfigLoaderCollectorFactory(ModelFactory[ConfigLoaderCollector]):
    """Factory for Collector configuration.

    Creates test instances of collector configuration with auto-generated
    UUIDs and sensible defaults.
    """

    __check_model__ = False

    id = Use(lambda: f"elastic--{uuid.uuid4()}")
    name = "Elastic Security"


class ConfigLoaderFactory(ModelFactory[ConfigLoader]):
    """Factory for main configuration.

    Creates complete test configuration instances combining OpenAEV,
    collector, and Elastic Security settings using subfactories.
    """

    __check_model__ = False

    openaev = Use(ConfigLoaderOAEVFactory.build)
    collector = Use(ConfigLoaderCollectorFactory.build)
    elastic = Use(ConfigLoaderElasticFactory.build)


class ElasticSearchCriteriaFactory(ModelFactory[ElasticSearchCriteria]):
    """Factory for ElasticSearchCriteria.

    Creates test instances of Elastic Security search criteria with
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


class ElasticAlertFactory(ModelFactory[ElasticAlert]):
    """Factory for Elastic Security alerts.

    Creates test instances of Elastic Security alert objects with
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
    inject_expectation_trace_source_id = Use(lambda: f"elastic--{uuid.uuid4()}")
    inject_expectation_trace_alert_name = "Elastic Security Detection Alert"
    inject_expectation_trace_alert_link = Use(
        lambda: f"https://test-elastic.example.com:5601/app/security/alerts?query=test-{uuid.uuid4().hex[:8]}"
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
        """Create mock Elastic Security client API.

        Returns:
            Mock ElasticClientAPI instance with basic attributes set.

        """
        mock_client = Mock()
        mock_client.base_url = "https://test-elastic.example.com:9200"
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
            expectation_type: Type of expectation ("detection" only for Elastic Security).
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
    def create_mixed_elastic_data() -> List[Any]:
        """Create mixed Elastic Security data (alerts).

        Returns:
            List containing ElasticAlert instances.

        """
        return create_test_elastic_alerts(count=3)

    @staticmethod
    def create_api_response_data() -> Dict[str, Any]:
        """Create mock Elasticsearch ``_search`` API response data.

        Returns:
            Dictionary simulating an Elasticsearch ``_search`` API response.

        """
        return {
            "took": 5,
            "timed_out": False,
            "hits": {
                "total": {"value": 2, "relation": "eq"},
                "hits": [
                    {
                        "_index": ".alerts-security.alerts-default",
                        "_id": "alert-1",
                        "_source": {
                            "@timestamp": "2024-01-01T12:30:00.000Z",
                            "source": {"ip": "192.168.1.100"},
                            "destination": {"ip": "10.0.0.50"},
                            "url": {"path": "/api/test"},
                            "event": {"category": "intrusion_detection"},
                            "kibana": {
                                "alert": {
                                    "rule": {"name": "High Risk Connection"},
                                    "severity": "high",
                                }
                            },
                        },
                    },
                    {
                        "_index": ".alerts-security.alerts-default",
                        "_id": "alert-2",
                        "_source": {
                            "@timestamp": "2024-01-01T12:31:00.000Z",
                            "source": {"ip": "172.16.0.10"},
                            "destination": {"ip": "203.0.113.5"},
                            "event": {"category": "network"},
                            "kibana": {
                                "alert": {
                                    "rule": {"name": "Network Anomaly"},
                                    "severity": "medium",
                                }
                            },
                        },
                    },
                ],
            },
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


def create_test_elastic_alerts(count: int = 1) -> List[ElasticAlert]:
    """Create test Elastic Security alerts with varied IP configurations.

    Args:
        count: Number of alerts to create (default 1).

    Returns:
        List of ElasticAlert instances with test data.

    """
    alerts = []
    for i in range(count):
        if i % 2 == 0:
            alert = ElasticAlertFactory.build(
                src_ip=f"192.168.1.{100 + i}",
                dst_ip=f"10.0.0.{50 + i}",
            )
        else:
            alert = ElasticAlertFactory.build(
                source_ip=f"172.16.0.{10 + i}",
                destination_ip=f"203.0.113.{5 + i}",
                src_ip=None,
                dst_ip=None,
            )
        alerts.append(alert)
    return alerts


def create_test_search_criteria(**overrides) -> ElasticSearchCriteria:
    """Create test search criteria.

    Args:
        **overrides: Criteria values to override defaults.

    Returns:
        ElasticSearchCriteria instance with test configuration.

    """
    return ElasticSearchCriteriaFactory.build(**overrides)
