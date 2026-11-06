"""Test module for the Elastic Security Collector setup connectivity logs."""

from os import environ as os_environ
from typing import Any
from unittest.mock import Mock, patch

import pytest
from src.collector import Collector
from src.collector.exception import CollectorSetupError
from tests.conftest import mock_env_vars

COLLECTOR_ENV = {
    "OPENAEV_URL": "http://fake-url/",
    "OPENAEV_TOKEN": "fake-oaev-token",
    "OPENAEV_TENANT_ID": "deadbeef-dead-beef-dead-beefdeadbeef",
    "COLLECTOR_ID": "fake-collector-id",
    "COLLECTOR_NAME": "Elastic Security",
    "ELASTIC_BASE_URL": "https://fake-elastic.net:9200/",
    "ELASTIC_USERNAME": "fake-user",
    "ELASTIC_PASSWORD": "fake-password",
    "COLLECTOR_ICON_FILEPATH": "src/img/elastic-logo.png",
}


@pytest.fixture()
def collector_and_service() -> Any:  # type: ignore
    """Build a collector whose services are mocked, with its Elastic service mock."""
    mock_env = mock_env_vars(os_environ, COLLECTOR_ENV)
    with (
        patch("src.collector.collector.ElasticExpectationService") as service_cls,
        patch("src.collector.collector.ElasticTraceService"),
        patch("src.collector.collector.GenericExpectationManager"),
        patch("src.collector.collector.OpenAEVDetectionHelper"),
    ):
        instance = Collector()
        instance.logger = Mock()
        yield instance, service_cls.return_value
    mock_env.stop()


def _info_messages(collector: Collector) -> str:
    return " ".join(str(call.args[0]) for call in collector.logger.info.call_args_list)


@patch("pyoaev.daemons.CollectorDaemon._setup")
def test_setup_logs_openaev_connection_and_checks_elastic(
    _daemon_setup, collector_and_service
):  # type: ignore
    """Once registered, setup reports OpenAEV and runs the Elastic check."""
    # Arrange
    collector, service = collector_and_service

    # Act
    collector._setup()

    # Assert
    assert "Connected to OpenAEV at http://fake-url" in _info_messages(  # noqa: S101
        collector
    )
    service.check_connectivity.assert_called_once_with()


@patch("pyoaev.daemons.CollectorDaemon._setup")
def test_setup_survives_failed_elastic_check(
    _daemon_setup, collector_and_service
):  # type: ignore
    """An unreachable Elastic is logged by the check but does not abort setup."""
    # Arrange
    collector, service = collector_and_service
    service.check_connectivity.return_value = False

    # Act
    collector._setup()

    # Assert
    assert "Collector setup completed successfully" in _info_messages(  # noqa: S101
        collector
    )


@patch("pyoaev.daemons.CollectorDaemon._setup")
def test_setup_unreachable_openaev_is_not_reported_connected(
    daemon_setup, collector_and_service
):  # type: ignore
    """A failed registration fails setup without a misleading success log."""
    # Arrange
    collector, service = collector_and_service
    daemon_setup.side_effect = ConnectionError("Connection refused")

    # Act / Assert
    with pytest.raises(CollectorSetupError):
        collector._setup()
    assert "Connected to OpenAEV" not in _info_messages(collector)  # noqa: S101
    service.check_connectivity.assert_not_called()


@patch("pyoaev.daemons.CollectorDaemon._setup")
def test_setup_shares_one_elastic_client(_daemon_setup):  # type: ignore
    """The trace service reuses the expectation service's client (one client, one log)."""
    # Arrange
    mock_env = mock_env_vars(os_environ, COLLECTOR_ENV)
    with (
        patch("src.collector.collector.ElasticExpectationService") as service_cls,
        patch("src.collector.collector.ElasticTraceService") as trace_cls,
        patch("src.collector.collector.GenericExpectationManager"),
        patch("src.collector.collector.OpenAEVDetectionHelper"),
    ):
        collector = Collector()
        collector.logger = Mock()

        # Act
        collector._setup()

    mock_env.stop()

    # Assert
    assert (  # noqa: S101
        trace_cls.call_args.kwargs["client_api"] is service_cls.return_value.client_api
    )
