"""Essential tests for Elastic Security Converter service."""

from src.services.converter import Converter
from tests.services.fixtures.factories import (
    ElasticAlertFactory,
    create_test_elastic_alerts,
)


class TestConverterEssential:
    """Essential test cases for Elastic Security Converter.

    Tests the core functionality of the Elastic Security data converter including
    initialization, data type detection, and conversion to OAEV format.
    """

    def test_init(self):
        """Test that Converter initializes correctly.

        Verifies that the converter instance is properly initialized
        with a logger and ready for data conversion operations.
        """
        converter = Converter()
        assert converter.logger is not None  # noqa: S101

    def test_convert_empty_data_returns_empty_list(self):
        """Test converting empty data returns empty list.

        Verifies that both None and empty list inputs result in
        empty list outputs without raising exceptions.
        """
        converter = Converter()

        result_none = converter.convert_data_to_oaev_data(None)
        result_empty = converter.convert_data_to_oaev_data([])

        assert result_none == []  # noqa: S101
        assert result_empty == []  # noqa: S101

    def test_convert_alert_with_source_and_target_ips(self):
        """Test converting alert with both source and target IP addresses.

        Verifies that Elastic Security alerts containing both source and target IPs
        are properly converted to OAEV format with correct structure.
        """
        converter = Converter()
        alert = ElasticAlertFactory.build(src_ip="192.168.1.100", dst_ip="10.0.0.50")

        result = converter.convert_data_to_oaev_data(alert)

        assert len(result) == 1  # noqa: S101
        assert "source_ipv4_address" in result[0]  # noqa: S101
        assert "target_ipv4_address" in result[0]  # noqa: S101
        assert result[0]["source_ipv4_address"]["type"] == "simple"  # noqa: S101
        assert result[0]["target_ipv4_address"]["type"] == "simple"  # noqa: S101
        assert result[0]["source_ipv4_address"]["data"] == [  # noqa: S101
            "192.168.1.100"
        ]
        assert result[0]["target_ipv4_address"]["data"] == ["10.0.0.50"]  # noqa: S101

    def test_convert_alert_with_only_source_ip(self):
        """Test converting alert with only source IP address.

        Verifies that alerts containing only source IP addresses
        result in OAEV data with only source IP field populated.
        """
        converter = Converter()
        alert = ElasticAlertFactory.build(src_ip="192.168.1.100", dst_ip=None)

        result = converter.convert_data_to_oaev_data(alert)

        assert len(result) == 1  # noqa: S101
        assert "source_ipv4_address" in result[0]  # noqa: S101
        assert "target_ipv4_address" not in result[0]  # noqa: S101
        assert result[0]["source_ipv4_address"]["data"] == [  # noqa: S101
            "192.168.1.100"
        ]

    def test_convert_alert_with_only_target_ip(self):
        """Test converting alert with only target IP address.

        Verifies that alerts containing only target IP addresses
        result in OAEV data with only target IP field populated.
        """
        converter = Converter()
        alert = ElasticAlertFactory.build(src_ip=None, dst_ip="10.0.0.50")

        result = converter.convert_data_to_oaev_data(alert)

        assert len(result) == 1  # noqa: S101
        assert "source_ipv4_address" not in result[0]  # noqa: S101
        assert "target_ipv4_address" in result[0]  # noqa: S101
        assert result[0]["target_ipv4_address"]["data"] == ["10.0.0.50"]  # noqa: S101

    def test_convert_alert_without_ips(self):
        """Test converting alert without any IP addresses.

        Verifies that alerts without any IP addresses are filtered out
        and do not appear in the final OAEV data list.
        """
        converter = Converter()
        alert = ElasticAlertFactory.build(src_ip=None, dst_ip=None)

        result = converter.convert_data_to_oaev_data(alert)

        # Should be filtered out completely - no results
        assert len(result) == 0  # noqa: S101

    def test_convert_multiple_alerts_list(self):
        """Test converting list of multiple alerts.

        Verifies that lists containing multiple ElasticAlert objects
        are processed correctly, with each alert converted to its
        appropriate OAEV format.
        """
        converter = Converter()

        alerts = create_test_elastic_alerts(count=3)

        result = converter.convert_data_to_oaev_data(alerts)

        # Every generated alert carries source/destination IPs, so all convert.
        assert len(result) == 3  # noqa: S101
        # Each result should be a dictionary with both IP fields populated.
        assert all(isinstance(item, dict) for item in result)  # noqa: S101
        assert all("source_ipv4_address" in item for item in result)  # noqa: S101
        assert all("target_ipv4_address" in item for item in result)  # noqa: S101

    def test_convert_invalid_data_handles_gracefully(self):
        """Test converting invalid data handles gracefully.

        Verifies that unknown or invalid data types are handled gracefully
        by returning empty results without raising exceptions.
        """
        converter = Converter()
        invalid_data = {"unknown": "data", "type": "mystery"}

        result = converter.convert_data_to_oaev_data(invalid_data)

        assert result == []  # noqa: S101

    def test_extract_source_ips_from_src_ip(self):
        """Test extracting source IPs from the alert ``src_ip`` field.

        ``ElasticAlert`` exposes the source IP solely through ``src_ip``
        (populated from ECS ``source.ip`` / ``client.ip`` during parsing), so
        the converter reads that field and returns a single-item,
        de-duplicated list.
        """
        converter = Converter()
        alert = ElasticAlertFactory.build(src_ip="192.168.1.100")

        source_ips = converter._extract_source_ips(alert)

        assert len(source_ips) == 1  # noqa: S101
        assert source_ips == ["192.168.1.100"]  # noqa: S101

    def test_extract_target_ips_from_dst_ip(self):
        """Test extracting target IPs from the alert ``dst_ip`` field.

        ``ElasticAlert`` exposes the target IP solely through ``dst_ip``
        (populated from ECS ``destination.ip`` / ``server.ip`` during
        parsing), so the converter reads that field and returns a single-item,
        de-duplicated list.
        """
        converter = Converter()
        alert = ElasticAlertFactory.build(dst_ip="10.0.0.50")

        target_ips = converter._extract_target_ips(alert)

        assert len(target_ips) == 1  # noqa: S101
        assert target_ips == ["10.0.0.50"]  # noqa: S101

    def test_alert_data_type_detection(self):
        """Test that converter correctly detects ElasticAlert data type.

        Verifies that the _is_alert_data method correctly identifies
        ElasticAlert instances vs other data types.
        """
        converter = Converter()
        alert = ElasticAlertFactory.build()
        non_alert = {"not": "an alert"}

        assert converter._is_alert_data(alert) is True  # noqa: S101
        assert converter._is_alert_data(non_alert) is False  # noqa: S101
        assert converter._is_alert_data(None) is False  # noqa: S101
