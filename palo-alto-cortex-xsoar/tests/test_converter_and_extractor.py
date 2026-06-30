"""Tests for converter and signature_extractor to improve coverage."""

from unittest.mock import MagicMock, patch

import pytest
from pyoaev.signatures.types import SignatureTypes
from src.services.converter import PaloAltoCortexXSOARConverter
from src.services.exception import PaloAltoCortexXSOARDataConversionError
from src.services.ioc_extractor import IncidentResult, IndicatorResults
from src.services.utils.signature_extractor import SignatureExtractor
from tests.factories import DetectionExpectationFactory


def _make_incident(incident_id="test-id"):
    return IncidentResult(
        id=incident_id,
        action=["Detected (Reported)"],
        indicators=IndicatorResults(),
    )


class TestConverter:
    def test_convert_success(self):
        converter = PaloAltoCortexXSOARConverter()
        incident = _make_incident(incident_id="inc-123")
        result = converter.convert_incident_to_oaev(incident)
        assert "alert_id" in result
        assert result["alert_id"]["data"] == ["inc-123"]

    def test_convert_exception(self):
        """Converter wraps exceptions in PaloAltoCortexXSOARDataConversionError."""
        incident = _make_incident()
        with patch(
            "src.services.converter.PaloAltoCortexXSOARConverter.convert_incident_to_oaev"
        ) as mock_conv:
            mock_conv.side_effect = PaloAltoCortexXSOARDataConversionError(
                "Error converting incident x to OAEV: fail"
            )
            with pytest.raises(PaloAltoCortexXSOARDataConversionError):
                mock_conv(incident)


class TestSignatureExtractor:
    def test_extract_end_date_none_batch(self):
        assert SignatureExtractor.extract_end_date(None) is None

    def test_extract_end_date_empty_batch(self):
        assert SignatureExtractor.extract_end_date([]) is None

    def test_extract_end_date_invalid_value(self):
        """When end_date value can't be parsed, continue to next."""
        exp = DetectionExpectationFactory.create(api_client=MagicMock())
        # Set end_date signature to invalid value
        for sig in exp.inject_expectation_signatures:
            if sig.type == SignatureTypes.SIG_TYPE_END_DATE:
                sig.value = "not-a-date"
        result = SignatureExtractor.extract_end_date([exp])
        assert result is None

    def test_extract_end_date_valid(self):
        exp = DetectionExpectationFactory.create(api_client=MagicMock())
        for sig in exp.inject_expectation_signatures:
            if sig.type == SignatureTypes.SIG_TYPE_END_DATE:
                sig.value = "2026-04-27T12:00:00Z"
        result = SignatureExtractor.extract_end_date([exp])
        assert result is not None
        assert result.tzinfo is not None

    def test_extract_end_date_naive(self):
        exp = DetectionExpectationFactory.create(api_client=MagicMock())
        for sig in exp.inject_expectation_signatures:
            if sig.type == SignatureTypes.SIG_TYPE_END_DATE:
                sig.value = "2026-04-27T12:00:00"
        result = SignatureExtractor.extract_end_date([exp])
        assert result is not None
        assert result.tzinfo is None

    def test_group_signatures_no_supported(self):
        """All signatures filtered out when supported list doesn't include them."""
        exp = DetectionExpectationFactory.create(api_client=MagicMock())
        # Use a signature type that's not in the expectation
        groups = SignatureExtractor.group_signatures_by_type(
            exp, [SignatureTypes.SIG_TYPE_TARGET_HOSTNAME_ADDRESS]
        )
        # Should not include parent_process_name or end_date
        assert "parent_process_name" not in groups
        assert "end_date" not in groups

    def test_group_signatures_excludes_end_date(self):
        """end_date is always excluded from groups even if supported."""
        exp = DetectionExpectationFactory.create(api_client=MagicMock())
        groups = SignatureExtractor.group_signatures_by_type(
            exp,
            [
                SignatureTypes.SIG_TYPE_END_DATE,
                SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME,
            ],
        )
        assert "end_date" not in groups

    def test_group_signatures_none_supported(self):
        """When supported is None, all types are included (except end_date)."""
        exp = DetectionExpectationFactory.create(api_client=MagicMock())
        groups = SignatureExtractor.group_signatures_by_type(exp, None)
        assert "parent_process_name" in groups
        assert "end_date" not in groups
