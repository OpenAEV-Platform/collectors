"""Additional branch-coverage tests for the IBM QRadar Converter."""

import pytest
from src.services.converter import Converter
from src.services.exception import QRadarValidationError
from src.services.models import QRadarAlert

INJECT_UUID = "12345678-1234-1234-1234-123456789abc"
AGENT_UUID = "87654321-4321-4321-4321-cba987654321"
URL_PATH = f"/api/injects/{INJECT_UUID}/{AGENT_UUID}/executable-payload"


class TestConverterExtra:
    """Branch-coverage tests for Converter."""

    def test_convert_alert_with_parent_process(self):
        """An alert whose url_path encodes UUIDs yields a parent_process_name field."""
        converter = Converter()
        alert = QRadarAlert(time="t", src_ip="1.2.3.4", url_path=URL_PATH)

        result = converter.convert_data_to_oaev_data(alert)

        assert len(result) == 1  # noqa: S101
        assert "parent_process_name" in result[0]  # noqa: S101
        assert result[0]["parent_process_name"]["type"] == "fuzzy"  # noqa: S101

    def test_convert_alert_with_signature_and_rule(self):
        """Signature and rule name on the alert are handled without error."""
        converter = Converter()
        alert = QRadarAlert(
            time="t",
            src_ip="1.2.3.4",
            signature="Malicious Activity",
            rule_name="High Risk Rule",
        )

        result = converter.convert_data_to_oaev_data(alert)

        assert result[0]["source_ipv4_address"]["data"] == ["1.2.3.4"]  # noqa: S101

    def test_extract_parent_process_name_no_url(self):
        """An alert without a url_path yields no parent process name."""
        converter = Converter()
        alert = QRadarAlert(time="t", src_ip="1.2.3.4")
        assert converter._extract_parent_process_name(alert) == ""  # noqa: S101

    def test_extract_parent_process_name_non_matching_url(self):
        """A url_path without UUIDs yields no parent process name."""
        converter = Converter()
        alert = QRadarAlert(time="t", src_ip="1.2.3.4", url_path="/api/other")
        assert converter._extract_parent_process_name(alert) == ""  # noqa: S101

    def test_alert_data_rejects_invalid_type(self):
        """_alert_data rejects non-QRadarAlert input."""
        converter = Converter()
        with pytest.raises(QRadarValidationError):
            converter._alert_data({"not": "an-alert"})
