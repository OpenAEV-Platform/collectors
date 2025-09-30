"""Essential tests for SentinelOne Expectation Service."""

from unittest.mock import Mock

import pytest
from pyobas.signatures.types import SignatureTypes
from src.collector.models import ExpectationResult
from src.services.exception import (
    SentinelOneExpectationError,
    SentinelOneNoAlertsFoundError,
    SentinelOneNoMatchingAlertsError,
    SentinelOneValidationError,
)
from src.services.expectation_service import SentinelOneExpectationService
from tests.services.fixtures.factories import (
    MockObjectsFactory,
    TestDataFactory,
    create_test_config,
)


class TestSentinelOneExpectationServiceEssential:
    """Essential test cases for SentinelOneExpectationService.

    Tests the core functionality of the SentinelOne expectation service including
    initialization, signature support, batch processing, and matching operations.
    """

    def test_init_with_valid_config(self):
        """Test that service initializes correctly with valid config.

        Verifies that the service properly initializes with configuration values,
        sets up client API and converter components, and configures time window.
        """
        config = create_test_config()

        service = SentinelOneExpectationService(config=config)

        assert service.config == config  # noqa: S101
        assert service.client_api is not None  # noqa: S101
        assert service.converter is not None  # noqa: S101
        assert service.time_window is not None  # noqa: S101

    def test_init_without_config_raises_error(self):
        """Test that initialization without config raises configuration error.

        Verifies that attempting to initialize the service without a valid
        configuration raises a SentinelOneValidationError.
        """
        with pytest.raises(SentinelOneValidationError):
            SentinelOneExpectationService(config=None)

    def test_get_supported_signatures(self):
        """Test that service returns correct supported signatures.

        Verifies that the service returns the expected list of signature types
        it can process for expectation handling.
        """
        config = create_test_config()
        service = SentinelOneExpectationService(config=config)

        signatures = service.get_supported_signatures()

        expected_signatures = [
            SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME,
            SignatureTypes.SIG_TYPE_START_DATE,
            SignatureTypes.SIG_TYPE_END_DATE,
        ]
        assert signatures == expected_signatures  # noqa: S101

    def test_handle_batch_expectations_success(self):
        """Test successful batch expectation handling.

        Verifies that the service can process multiple expectations in batch,
        returning appropriate ExpectationResult objects for each.
        """
        config = create_test_config()
        service = SentinelOneExpectationService(config=config)

        mock_result = ExpectationResult(
            expectation_id="test-id",
            is_valid=True,
            expectation=None,
        )
        service.process_expectation = Mock(return_value=mock_result)

        expectations = [
            MockObjectsFactory.create_mock_expectation(expectation_type="detection"),
            MockObjectsFactory.create_mock_expectation(expectation_type="prevention"),
        ]

        mock_detection_helper = MockObjectsFactory.create_mock_detection_helper()

        results = service.handle_batch_expectations(expectations, mock_detection_helper)

        assert len(results) == 2  # noqa: S101
        assert all(isinstance(r, ExpectationResult) for r in results)  # noqa: S101
        assert service.process_expectation.call_count == 2  # noqa: S101

    def test_handle_batch_expectations_with_error(self):
        """Test batch expectation handling when expectation fails.

        Verifies that individual expectation failures are handled gracefully
        in batch processing, returning error results without stopping the batch.
        """
        config = create_test_config()
        service = SentinelOneExpectationService(config=config)

        service.process_expectation = Mock(
            side_effect=SentinelOneExpectationError("Test error")
        )

        expectations = [MockObjectsFactory.create_mock_expectation()]
        mock_detection_helper = MockObjectsFactory.create_mock_detection_helper()

        results = service.handle_batch_expectations(expectations, mock_detection_helper)

        assert len(results) == 1  # noqa: S101
        assert results[0].is_valid is False  # noqa: S101

    def test_match_success(self):
        """Test successful matching for detection expectation.

        Verifies that the matching logic correctly identifies when OAEV data
        matches expectation signatures and returns appropriate result data.
        """
        config = create_test_config()
        service = SentinelOneExpectationService(config=config)

        oaev_data = TestDataFactory.create_oaev_detection_data()
        matching_signatures = [
            {
                "type": "parent_process_name",
                "value": oaev_data[0]["parent_process_name"]["data"][0],
            }
        ]

        mock_detection_helper = MockObjectsFactory.create_mock_detection_helper(
            match_result=True
        )

        result = service._match(
            oaev_data, matching_signatures, mock_detection_helper, "detection"
        )

        assert result["is_valid"] is True  # noqa: S101
        assert result["matching_data"] == [oaev_data[0]]  # noqa: S101

    def test_match_no_data_raises_exception(self):
        """Test matching with no data raises NoAlertsFound exception.

        Verifies that attempting to match against empty data properly
        raises SentinelOneNoAlertsFoundError.
        """
        config = create_test_config()
        service = SentinelOneExpectationService(config=config)

        mock_detection_helper = MockObjectsFactory.create_mock_detection_helper()

        with pytest.raises(SentinelOneNoAlertsFoundError):
            service._match([], [], mock_detection_helper, "detection")

    def test_match_no_matching_alerts_raises_exception(self):
        """Test matching that finds no matches raises NoMatchingAlerts exception.

        Verifies that when data is available but no matches are found,
        the service raises SentinelOneNoMatchingAlertsError.
        """
        config = create_test_config()
        service = SentinelOneExpectationService(config=config)

        oaev_data = TestDataFactory.create_oaev_detection_data()
        matching_signatures = [
            {"type": "parent_process_name", "value": "different-process"}
        ]

        mock_detection_helper = MockObjectsFactory.create_mock_detection_helper(
            match_result=False
        )

        with pytest.raises(SentinelOneNoMatchingAlertsError):
            service._match(
                oaev_data, matching_signatures, mock_detection_helper, "detection"
            )

    def test_create_error_result_object(self):
        """Test creating error result objects from exceptions.

        Verifies that service errors are properly converted to ExpectationResult
        objects with appropriate error information and validation status.
        """
        config = create_test_config()
        service = SentinelOneExpectationService(config=config)

        mock_expectation = MockObjectsFactory.create_mock_expectation()
        error = SentinelOneNoAlertsFoundError("No alerts found")

        result = service._create_error_result_object(error, mock_expectation)

        assert isinstance(result, ExpectationResult)  # noqa: S101
        assert result.is_valid is False  # noqa: S101
        assert result.error_message is not None  # noqa: S101
        assert "No alerts found" in result.error_message  # noqa: S101

    def test_get_service_info(self):
        """Test getting service information.

        Verifies that the service provides accurate metadata about its
        capabilities, supported signatures, and service type information.
        """
        config = create_test_config()
        service = SentinelOneExpectationService(config=config)

        info = service.get_service_info()

        assert info["service_name"] == "SentinelOne"  # noqa: S101
        assert info["supports_detection"] is True  # noqa: S101
        assert info["supports_prevention"] is True  # noqa: S101
        assert "supported_signatures" in info  # noqa: S101
        assert len(info["supported_signatures"]) == 3  # noqa: S101
