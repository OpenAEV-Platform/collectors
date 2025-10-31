"""Essential tests for SentinelOne Converter service."""

from src.services.converter import Converter
from tests.services.fixtures.factories import (
    DeepVisibilityEventFactory,
    SentinelOneThreatFactory,
)


class TestConverterEssential:
    """Essential test cases for SentinelOne Converter.

    Tests the core functionality of the SentinelOne data converter including
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

    def test_convert_dv_event_with_oaev_parent_process(self):
        """Test converting DV event with oaev-implant parent process name.

        Verifies that Deep Visibility events containing OAEV implant process
        names are properly converted to OAEV format with correct structure.
        """
        converter = Converter()
        parent_process_name = "oaev-implant-test-12345"
        dv_event = DeepVisibilityEventFactory.build(
            src_proc_parent_name=parent_process_name
        )

        result = converter.convert_data_to_oaev_data(dv_event)

        assert len(result) == 1  # noqa: S101
        assert "parent_process_name" in result[0]  # noqa: S101
        assert result[0]["parent_process_name"]["type"] == "simple"  # noqa: S101
        assert result[0]["parent_process_name"]["data"] == [  # noqa: S101
            parent_process_name
        ]

    def test_convert_dv_event_without_oaev_process_names(self):
        """Test converting DV event without any oaev-implant process names.

        Verifies that Deep Visibility events without OAEV implant patterns
        result in empty conversion output as they're not relevant for OAEV.
        """
        converter = Converter()
        dv_event = DeepVisibilityEventFactory.build(
            src_proc_parent_name="regular-parent",
            src_proc_name="regular-process",
        )

        result = converter.convert_data_to_oaev_data(dv_event)

        assert len(result) == 0  # noqa: S101

    def test_convert_threat_data(self):
        """Test converting threat data.

        Verifies that SentinelOne threat objects are properly converted
        to OAEV format with threat_id field correctly structured.
        """
        converter = Converter()
        threat_id = "threat-test-id-12345"
        threat = SentinelOneThreatFactory.build(threat_id=threat_id)

        result = converter.convert_data_to_oaev_data(threat)

        assert len(result) == 1  # noqa: S101
        assert "threat_id" in result[0]  # noqa: S101
        assert result[0]["threat_id"]["type"] == "simple"  # noqa: S101
        assert result[0]["threat_id"]["data"] == [threat_id]  # noqa: S101

    def test_convert_mixed_data_list(self):
        """Test converting mixed list of DV events and threats.

        Verifies that lists containing both Deep Visibility events and
        threat objects are processed correctly, with each type converted
        to its appropriate OAEV format.
        """
        converter = Converter()

        dv_event = DeepVisibilityEventFactory.build(
            src_proc_parent_name="oaev-implant-dv-test"
        )
        threat = SentinelOneThreatFactory.build(threat_id="threat-mixed-test")
        mixed_data = [dv_event, threat]

        result = converter.convert_data_to_oaev_data(mixed_data)

        assert len(result) == 2  # noqa: S101
        dv_result = next((r for r in result if "parent_process_name" in r), None)
        threat_result = next((r for r in result if "threat_id" in r), None)

        assert dv_result is not None  # noqa: S101
        assert threat_result is not None  # noqa: S101

    def test_convert_invalid_data_handles_gracefully(self):
        """Test converting invalid data handles gracefully.

        Verifies that unknown or invalid data types are handled gracefully
        by returning empty results without raising exceptions.
        """
        converter = Converter()
        invalid_data = {"unknown": "data", "type": "mystery"}

        result = converter.convert_data_to_oaev_data(invalid_data)

        assert result == []  # noqa: S101
