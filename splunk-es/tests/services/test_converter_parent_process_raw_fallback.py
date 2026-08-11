"""Tests for parent process name extraction fallback from _raw alert data.

This module tests the enhancement where the converter falls back to scanning
the _raw alert data for the parent process name pattern when url_path
extraction fails.

See: feat/489-splunkes-enhanced-process-name-retrieval
"""

from src.services.converter import Converter
from src.services.models import SplunkESAlert


class TestConverterParentProcessRawFallback:
    """Test cases for parent process name extraction from _raw alert data.

    Tests the fallback behaviour when url_path does not contain parseable
    UUIDs but the _raw dict does contain the parent process name in the
    format: oaev-implant-{inject_uuid}-agent-{agent_uuid}
    """

    def test_extract_parent_process_name_from_url_path(self):
        """Test extracting parent process name from a valid url_path.

        Verifies that when url_path contains the expected OpenAEV callback
        URL format, the parent process name is correctly reconstructed.
        """
        converter = Converter()
        inject_uuid = "877b423b-ae91-4fc5-86c3-fa8ea3c938ba"
        agent_uuid = "1402422f-2eaa-4fbd-80b2-b30df1b83b19"
        url_path = f"/api/injects/{inject_uuid}/{agent_uuid}/executable-payload"

        alert = SplunkESAlert(time="2024-01-01T12:30:00Z", url_path=url_path)

        result = converter._extract_parent_process_name(alert)

        assert result == [  # noqa: S101
            f"oaev-implant-{inject_uuid}-agent-{agent_uuid}"
        ]

    def test_extract_parent_process_name_from_url_path_not_found(self):
        """Test that extraction returns empty string when url_path has no UUIDs.

        Verifies that when url_path is present but does not contain the
        expected URL pattern, an empty string is returned.
        """
        converter = Converter()
        alert = SplunkESAlert(
            time="2024-01-01T12:30:00Z",
            url_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        )

        result = converter._extract_parent_process_name(alert)

        assert result == []  # noqa: S101

    def test_extract_parent_process_name_from_raw_when_url_path_fails(self):
        """Test fallback to _raw when url_path extraction fails.

        Verifies that when url_path does not contain parseable UUIDs, the
        converter falls back to scanning _raw for the parent process name
        pattern and returns the full process name directly.
        """
        converter = Converter()
        inject_uuid = "877b423b-ae91-4fc5-86c3-fa8ea3c938ba"
        agent_uuid = "1402422f-2eaa-4fbd-80b2-b30df1b83b19"
        expected_process_name = f"oaev-implant-{inject_uuid}-agent-{agent_uuid}"

        alert = SplunkESAlert(
            time="2024-01-01T12:30:00Z",
            url_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        )
        alert._raw = {
            "parent_process_name": expected_process_name,
            "src": "192.168.1.100",
            "dest": "10.0.0.50",
        }

        result = converter._extract_parent_process_name(alert)

        assert result == [expected_process_name]  # noqa: S101

    def test_extract_parent_process_name_from_raw_with_multiple_patterns(self):
        """Test fallback to _raw when multiple process name patterns exist.

        Verifies that when _raw contains multiple parent process name
        patterns, all of them are extracted and returned.
        """
        converter = Converter()
        inject_uuid_1 = "877b423b-ae91-4fc5-86c3-fa8ea3c938ba"
        agent_uuid_1 = "1402422f-2eaa-4fbd-80b2-b30df1b83b19"
        inject_uuid_2 = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        agent_uuid_2 = "f1e2d3c4-b5a6-9780-fedc-ba0987654321"
        process_name_1 = f"oaev-implant-{inject_uuid_1}-agent-{agent_uuid_1}"
        process_name_2 = f"oaev-implant-{inject_uuid_2}-agent-{agent_uuid_2}"

        alert = SplunkESAlert(
            time="2024-01-01T12:30:00Z",
            url_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        )
        alert._raw = {
            "parent_process_name": process_name_1,
            "process_name": process_name_2,
            "src": "192.168.1.100",
        }

        result = converter._extract_parent_process_name(alert)

        assert process_name_1 in result  # noqa: S101
        assert process_name_2 in result  # noqa: S101

    def test_extract_parent_process_name_url_path_takes_precedence(self):
        """Test that url_path extraction takes precedence over _raw fallback.

        Verifies that when both url_path and _raw contain valid data,
        the url_path result is used (existing behaviour preserved).
        """
        converter = Converter()
        inject_uuid_url = "11111111-2222-3333-4444-555555555555"
        agent_uuid_url = "66666666-7777-8888-9999-aaaaaaaaaaaa"
        inject_uuid_raw = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
        agent_uuid_raw = "11111111-2222-3333-4444-555555555555"
        url_path = f"/api/injects/{inject_uuid_url}/{agent_uuid_url}/executable-payload"
        expected_from_url = f"oaev-implant-{inject_uuid_url}-agent-{agent_uuid_url}"
        expected_from_raw = f"oaev-implant-{inject_uuid_raw}-agent-{agent_uuid_raw}"

        alert = SplunkESAlert(time="2024-01-01T12:30:00Z", url_path=url_path)
        alert._raw = {
            "parent_process_name": expected_from_raw,
        }

        result = converter._extract_parent_process_name(alert)

        assert result == [expected_from_url]  # noqa: S101
        assert expected_from_raw not in result  # noqa: S101

    def test_extract_parent_process_name_no_url_no_raw(self):
        """Test extraction when neither url_path nor _raw contain data.

        Verifies that when both url_path is empty and _raw has no parent
        process name pattern, an empty string is returned.
        """
        converter = Converter()
        alert = SplunkESAlert(time="2024-01-01T12:30:00Z")
        alert._raw = {"src": "192.168.1.100", "dest": "10.0.0.50"}

        result = converter._extract_parent_process_name(alert)

        assert result == []  # noqa: S101

    def test_convert_alert_with_raw_fallback_includes_parent_process(self):
        """Test full conversion includes parent_process_name from _raw fallback.

        Verifies that converting an alert with no parseable url_path but
        a valid parent process name in _raw results in OAEV data containing
        the parent_process_name field.
        """
        converter = Converter()
        inject_uuid = "877b423b-ae91-4fc5-86c3-fa8ea3c938ba"
        agent_uuid = "1402422f-2eaa-4fbd-80b2-b30df1b83b19"
        expected_process_name = f"oaev-implant-{inject_uuid}-agent-{agent_uuid}"

        alert = SplunkESAlert(
            time="2024-01-01T12:30:00Z",
            src_ip="192.168.1.100",
            dst_ip="10.0.0.50",
            url_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        )
        alert._raw = {
            "parent_process_name": expected_process_name,
        }

        result = converter.convert_data_to_oaev_data(alert)

        assert len(result) == 1  # noqa: S101
        assert "parent_process_name" in result[0]  # noqa: S101
        assert result[0]["parent_process_name"]["type"] == "fuzzy"  # noqa: S101
        assert (
            expected_process_name in result[0]["parent_process_name"]["data"]
        )  # noqa: S101
