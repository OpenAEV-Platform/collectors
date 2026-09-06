"""Essential tests for Splunk ES Expectation Service."""

from unittest.mock import Mock

import pytest
from pyoaev.signatures.types import SignatureTypes
from src.collector.models import ExpectationResult
from src.services.exception import (
    SplunkESExpectationError,
    SplunkESNoAlertsFoundError,
    SplunkESNoMatchingAlertsError,
    SplunkESValidationError,
)
from src.services.expectation_service import SplunkESExpectationService
from src.services.models import SplunkESResponse
from tests.services.fixtures.factories import (
    MockObjectsFactory,
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

        Verifies that the service dynamically supports every SignatureTypes
        member instead of a hardcoded subset.
        """
        config = create_test_config()
        service = SplunkESExpectationService(config=config)

        signatures = service.get_supported_signatures()

        assert signatures == list(SignatureTypes)  # noqa: S101

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
        from pyoaev.apis.inject_expectation.model import PreventionExpectation

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
        """Test successful matching for a detection expectation.

        Verifies that the matching logic identifies a fetched alert whose raw
        event text contains the content signature value (filter types are
        excluded upstream) and returns that alert's converted data as
        matching data.
        """
        config = create_test_config()
        service = SplunkESExpectationService(config=config)

        raw_row = {
            "_time": "2024-01-01T12:30:00Z",
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.50",
            "_raw": (
                "2024-01-01T12:30:00Z notable event src=192.168.1.100 "
                "dst=10.0.0.50 process=test_process.exe"
            ),
        }
        alerts = SplunkESResponse.from_raw_response({"results": [raw_row]}).results

        # Content-only: filter types (IPs, hostnames, dates) are excluded
        # upstream by _extract_signatures; the matcher only sees content.
        matching_signatures = [
            {
                "type": "parent_process_name",
                "value": "test_process.exe",
            },
        ]

        result = service._match(alerts, matching_signatures, "detection")

        assert result["is_valid"] is True  # noqa: S101
        assert result["matching_data"] == [
            service.converter._alert_data(alerts[0])
        ]  # noqa: S101
        assert result["total_data_found"] == 1  # noqa: S101

    def test_match_no_data_raises_exception(self):
        """Test matching with no data raises NoAlertsFound exception.

        Verifies that attempting to match against an empty alert list properly
        raises SplunkESNoAlertsFoundError.
        """
        config = create_test_config()
        service = SplunkESExpectationService(config=config)

        with pytest.raises(SplunkESNoAlertsFoundError):
            service._match([], [], "detection")

    def test_match_no_matching_alerts_raises_exception(self):
        """Test matching that finds no matches raises NoMatchingAlerts exception.

        Verifies that when alerts are available but none of their raw event
        text contains the signature values, the service raises
        SplunkESNoMatchingAlertsError.
        """
        config = create_test_config()
        service = SplunkESExpectationService(config=config)

        raw_row = {
            "_time": "2024-01-01T12:30:00Z",
            "src_ip": "10.9.8.7",
            "_raw": "2024-01-01T12:30:00Z unrelated benign event",
        }
        alerts = SplunkESResponse.from_raw_response({"results": [raw_row]}).results

        matching_signatures = [
            {"type": "source_ipv4_address", "value": "192.168.99.99"}  # Different IP
        ]

        with pytest.raises(SplunkESNoMatchingAlertsError):
            service._match(alerts, matching_signatures, "detection")

    def test_match_accepts_fetched_when_no_content_signatures(self):
        """Test that a filter-only expectation accepts what the query fetched.

        When an expectation carries only filter-type signatures (IP, date),
        the matching set is empty: the SPL query's enough-filter is the only
        filter, so every fetched alert is accepted without a content check.
        """
        config = create_test_config()
        service = SplunkESExpectationService(config=config)

        mock_expectation = Mock()
        mock_expectation.inject_expectation_id = "filter-only-1"

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

        # Both signatures are filter types, so the content set is empty.
        assert len(search_signatures) == 2  # noqa: S101
        assert matching_signatures == []  # noqa: S101

        raw_row = {
            "_time": "2024-01-01T12:30:00Z",
            "src_ip": "192.168.1.100",
            "_raw": "2024-01-01T12:30:00Z notable event with no signature text",
        }
        alerts = SplunkESResponse.from_raw_response({"results": [raw_row]}).results

        result = service._match(alerts, matching_signatures, "detection")

        assert result["is_valid"] is True  # noqa: S101
        assert len(result["matching_data"]) == 1  # noqa: S101
        assert result["total_data_found"] == 1  # noqa: S101

    def test_match_email_signatures_against_raw(self):
        """Test matching email-injector signatures against a raw event line.

        Verifies that when a detection expectation carries only the five email
        injector signature types (no IP or date signatures), matching still
        works: the fetched alert's _raw event text is searched for the
        signature values, and the matching alert is returned even though the
        old structured-field matching path could never handle these types.
        """
        config = create_test_config()
        service = SplunkESExpectationService(config=config)

        email_signatures = {
            "source_email": "attacker@evil.example",
            "target_email": "victim@corp.example",
            "url_hash": "d41d8cd98f00b204e9800998ecf8427e",
            "file_hash": "deadbeefcafe",
            "email_custom_header": "X-OpenAEV-Trace: 42",
        }
        mock_expectation = Mock()
        mock_expectation.inject_expectation_id = "email-injector-1"
        mock_expectation.inject_expectation_signatures = [
            Mock(**{"type.value": sig_type, "value": value})
            for sig_type, value in email_signatures.items()
        ]

        search_signatures, matching_signatures = service._extract_signatures(
            mock_expectation
        )

        # No date signatures present, so nothing is filtered out.
        assert len(search_signatures) == 5  # noqa: S101
        assert len(matching_signatures) == 5  # noqa: S101

        raw_row = {
            "_time": "2024-01-01T12:30:00Z",
            "_raw": (
                "2024-01-01T12:30:00Z mail from attacker@evil.example to "
                "victim@corp.example attachment deadbeefcafe url "
                "d41d8cd98f00b204e9800998ecf8427e X-OpenAEV-Trace: 42"
            ),
        }
        alerts = SplunkESResponse.from_raw_response({"results": [raw_row]}).results

        result = service._match(alerts, matching_signatures, "detection")

        assert result["is_valid"] is True  # noqa: S101
        assert len(result["matching_data"]) == 1  # noqa: S101
        assert result["matching_data"][0] == (
            service.converter._alert_data(alerts[0]) or alerts[0]._raw
        )

    def test_match_ignores_structured_field_requirements(self):
        """Test matching works on the full raw row, not structured keys.

        Verifies that an alert whose raw row has no _raw string field is
        still matchable: the engine falls back to the flattened key=value
        representation of the whole row, so matching does not depend on any
        particular structured field names.
        """
        config = create_test_config()
        service = SplunkESExpectationService(config=config)

        mock_expectation = Mock()
        mock_expectation.inject_expectation_id = "email-structured-1"
        email_signature = Mock()
        email_signature.type.value = "source_email"
        email_signature.value = "attacker@evil.example"
        mock_expectation.inject_expectation_signatures = [email_signature]

        _, matching_signatures = service._extract_signatures(mock_expectation)

        # No _raw string in the row: the flattened fields must carry the match.
        raw_row = {
            "_time": "2024-01-01T12:30:00Z",
            "sender": "attacker@evil.example",
        }
        alerts = SplunkESResponse.from_raw_response({"results": [raw_row]}).results

        result = service._match(alerts, matching_signatures, "detection")

        assert result["is_valid"] is True  # noqa: S101
        assert len(result["matching_data"]) == 1  # noqa: S101

    def test_extract_signatures_excludes_filter_types(self):
        """Test signature extraction separates query filters from content.

        Verifies that every signature goes into the search list (the query
        needs them all to build its enough-filter) while matching receives
        only content signatures: the IP, hostname, and date types are the
        filter types the SPL query already applies, so the regex engine
        must not double-filter on them.
        """
        config = create_test_config()
        service = SplunkESExpectationService(config=config)

        # Create mock expectation with mixed filter and content types
        mock_expectation = Mock()
        mock_signature_ip = Mock()
        mock_signature_ip.type.value = "source_ipv4_address"
        mock_signature_ip.value = "192.168.1.100"

        mock_signature_date = Mock()
        mock_signature_date.type.value = "start_date"
        mock_signature_date.value = "2024-01-01T00:00:00Z"

        # hostname is a filter type too: the query already constrains on it
        mock_signature_hostname = Mock()
        mock_signature_hostname.type.value = "hostname"
        mock_signature_hostname.value = "victim-host-01"

        # content type: carried by the matcher, not by the query
        mock_signature_ppn = Mock()
        mock_signature_ppn.type.value = "parent_process_name"
        mock_signature_ppn.value = "implant-agent.exe"

        mock_expectation.inject_expectation_signatures = [
            mock_signature_ip,
            mock_signature_date,
            mock_signature_hostname,
            mock_signature_ppn,
        ]

        search_signatures, matching_signatures = service._extract_signatures(
            mock_expectation
        )

        # Search keeps every signature (the query needs the full enough-filter)
        all_signatures = [
            {"type": sig.type.value, "value": sig.value}
            for sig in mock_expectation.inject_expectation_signatures
        ]
        assert search_signatures == all_signatures  # noqa: S101
        assert len(search_signatures) == 4  # noqa: S101

        # Matching receives only the content signature; filter types are excluded
        assert matching_signatures == [  # noqa: S101
            {"type": "parent_process_name", "value": "implant-agent.exe"}
        ]

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
        assert len(info["supported_signatures"]) == len(
            list(SignatureTypes)
        )  # noqa: S101

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
