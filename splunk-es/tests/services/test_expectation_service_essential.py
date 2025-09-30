"""Essential tests for Splunk ES Expectation Service."""

from unittest.mock import Mock

import pytest
from pyobas.signatures.types import SignatureTypes

from src.collector.models import ExpectationResult
from src.services.exception import (
    SplunkESExpectationError,
    SplunkESNoAlertsFoundError,
    SplunkESNoMatchingAlertsError,
    SplunkESValidationError,
)
from src.services.expectation_service import SplunkESExpectationService
from tests.services.fixtures.factories import (
    MockObjectsFactory,
    TestDataFactory,
    create_test_config,
)


class TestSplunkESExpectationServiceEssential:
    """Essential test cases for SplunkESExpectationService.

    Tests the core functionality of the Splunk ES expectation service including
    initialization, signature support, batch processing, and matching operations.
    """

    def test_init_with_valid_config(self):
        """Test that service initializes correctly with valid config.

        Verifies that the service properly initializes with configuration values,
        sets up client API and converter components, and configures time window.
        """
        config = create_test_config()

        service = SplunkESExpectationService(config=config)

        assert service.config == config  # noqa: S101
        assert service.client_api is not None  # noqa: S101
        assert service.converter is not None  # noqa: S101
        assert service.time_window is not None  # noqa: S101

    def test_init_without_config_raises_error(self):
        """Test that initialization without config raises configuration error.

        Verifies that attempting to initialize the service without a valid
        configuration raises a SplunkESValidationError.
        """
        with pytest.raises(SplunkESValidationError):
            SplunkESExpectationService(config=None)

    def test_get_supported_signatures(self):
        """Test that service returns correct supported signatures.

        Verifies that the service returns the expected list of signature types
        it can process for expectation handling (only IP addresses and dates).
        """
        config = create_test_config()
        service = SplunkESExpectationService(config=config)

        signatures = service.get_supported_signatures()

        expected_signatures = [
            SignatureTypes.SIG_TYPE_SOURCE_IPV4_ADDRESS,
            SignatureTypes.SIG_TYPE_TARGET_IPV4_ADDRESS,
            SignatureTypes.SIG_TYPE_SOURCE_IPV6_ADDRESS,
            SignatureTypes.SIG_TYPE_TARGET_IPV6_ADDRESS,
            SignatureTypes.SIG_TYPE_START_DATE,
            SignatureTypes.SIG_TYPE_END_DATE,
            SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME,
        ]
        assert signatures == expected_signatures  # noqa: S101

    def test_handle_batch_expectations_success(self):
        """Test successful batch expectation handling.

        Verifies that the service can process multiple expectations in batch,
        returning appropriate ExpectationResult objects for each.
        """
        config = create_test_config()
        service = SplunkESExpectationService(config=config)

        mock_result = ExpectationResult(
            expectation_id="test-id",
            is_valid=True,
            expectation=None,
        )
        service.process_expectation = Mock(return_value=mock_result)

        expectations = [
            MockObjectsFactory.create_mock_expectation(expectation_type="detection"),
            MockObjectsFactory.create_mock_expectation(expectation_type="detection"),
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
        service = SplunkESExpectationService(config=config)

        service.process_expectation = Mock(
            side_effect=SplunkESExpectationError("Test error")
        )

        expectations = [MockObjectsFactory.create_mock_expectation()]
        mock_detection_helper = MockObjectsFactory.create_mock_detection_helper()

        results = service.handle_batch_expectations(expectations, mock_detection_helper)

        assert len(results) == 1  # noqa: S101
        assert results[0].is_valid is False  # noqa: S101

    def test_prevention_expectation_not_supported(self):
        """Test that prevention expectations raise error.

        Verifies that Splunk ES correctly rejects prevention expectation
        types as it only supports detection expectations.
        """
        config = create_test_config()
        service = SplunkESExpectationService(config=config)

        mock_prevention_expectation = Mock()
        mock_prevention_expectation.inject_expectation_id = "test-prevention-id"

        # Mock the isinstance check to return False for DetectionExpectation
        # and True for PreventionExpectation
        # We'll simulate this by calling the method that checks expectation type
        from pyobas.apis.inject_expectation.model import PreventionExpectation

        # Create a mock that will fail the detection check
        prevention_mock = Mock(spec=PreventionExpectation)
        prevention_mock.inject_expectation_id = "test-prevention-id"

        mock_detection_helper = MockObjectsFactory.create_mock_detection_helper()

        result = service.process_expectation(prevention_mock, mock_detection_helper)

        assert isinstance(result, ExpectationResult)  # noqa: S101
        assert result.is_valid is False  # noqa: S101
        assert (  # noqa: S101
            "only supports DetectionExpectations" in result.error_message
        )

    def test_match_success(self):
        """Test successful matching for detection expectation.

        Verifies that the matching logic correctly identifies when OAEV data
        matches expectation signatures and returns appropriate result data.
        """
        config = create_test_config()
        service = SplunkESExpectationService(config=config)

        oaev_data = TestDataFactory.create_oaev_detection_data()
        matching_signatures = [
            {
                "type": "source_ipv4_address",
                "value": oaev_data[0]["source_ipv4_address"]["data"],
            },
            {
                "type": "parent_process_name",
                "value": "test_process.exe",
            },
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
        raises SplunkESNoAlertsFoundError.
        """
        config = create_test_config()
        service = SplunkESExpectationService(config=config)

        mock_detection_helper = MockObjectsFactory.create_mock_detection_helper()

        with pytest.raises(SplunkESNoAlertsFoundError):
            service._match([], [], mock_detection_helper, "detection")

    def test_match_no_matching_alerts_raises_exception(self):
        """Test matching that finds no matches raises NoMatchingAlerts exception.

        Verifies that when data is available but no matches are found,
        the service raises SplunkESNoMatchingAlertsError.
        """
        config = create_test_config()
        service = SplunkESExpectationService(config=config)

        oaev_data = TestDataFactory.create_oaev_detection_data()
        matching_signatures = [
            {"type": "source_ipv4_address", "value": "192.168.99.99"}  # Different IP
        ]

        mock_detection_helper = MockObjectsFactory.create_mock_detection_helper(
            match_result=False
        )

        with pytest.raises(SplunkESNoMatchingAlertsError):
            service._match(
                oaev_data, matching_signatures, mock_detection_helper, "detection"
            )

    def test_extract_signatures_filters_correctly(self):
        """Test signature extraction and filtering.

        Verifies that signature extraction properly separates search signatures
        from matching signatures, excluding date metadata from matching.
        """
        config = create_test_config()
        service = SplunkESExpectationService(config=config)

        # Create mock expectation with mixed signature types
        mock_expectation = Mock()
        mock_signature_ip = Mock()
        mock_signature_ip.type.value = "source_ipv4_address"
        mock_signature_ip.value = "192.168.1.100"

        mock_signature_date = Mock()
        mock_signature_date.type.value = "start_date"
        mock_signature_date.value = "2024-01-01T00:00:00Z"

        mock_expectation.inject_expectation_signatures = [
            mock_signature_ip,
            mock_signature_date,
        ]

        search_signatures, matching_signatures = service._extract_signatures(
            mock_expectation
        )

        # Search signatures should include both
        assert len(search_signatures) == 2  # noqa: S101

        # Matching signatures should exclude dates
        assert len(matching_signatures) == 1  # noqa: S101
        assert matching_signatures[0]["type"] == "source_ipv4_address"  # noqa: S101

    def test_create_error_result_object(self):
        """Test creating error result objects from exceptions.

        Verifies that service errors are properly converted to ExpectationResult
        objects with appropriate error information and validation status.
        """
        config = create_test_config()
        service = SplunkESExpectationService(config=config)

        mock_expectation = MockObjectsFactory.create_mock_expectation()
        error = SplunkESNoAlertsFoundError("No alerts found")

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
        service = SplunkESExpectationService(config=config)

        info = service.get_service_info()

        assert info["service_name"] == "Splunk ES"  # noqa: S101
        assert info["supports_detection"] is True  # noqa: S101
        assert info["supports_prevention"] is False  # noqa: S101
        assert "supported_signatures" in info  # noqa: S101
        assert len(info["supported_signatures"]) == 7  # noqa: S101

    def test_convert_dict_to_result(self):
        """Test converting dictionary results to ExpectationResult objects.

        Verifies that result dictionaries are properly converted to
        structured ExpectationResult instances.
        """
        config = create_test_config()
        service = SplunkESExpectationService(config=config)

        mock_expectation = MockObjectsFactory.create_mock_expectation()
        result_dict = {
            "is_valid": True,
            "matching_data": [
                {"source_ipv4_address": {"type": "simple", "data": "192.168.1.100"}}
            ],
            "total_data_found": 1,
        }

        result = service._convert_dict_to_result(result_dict, mock_expectation)

        assert isinstance(result, ExpectationResult)  # noqa: S101
        assert result.is_valid is True  # noqa: S101
        assert result.matched_alerts is not None  # noqa: S101
        assert result.expectation == mock_expectation  # noqa: S101
