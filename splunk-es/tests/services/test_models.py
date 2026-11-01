"""Behavior tests for Splunk ES response models."""

from src.services.models import SplunkESResponse


def test_raw_response_retains_the_original_result_row_on_the_alert():
    """A parsed alert retains its complete source result for later processing."""
    raw_result = {
        "_time": "2026-08-28T10:42:17.000+00:00",
        "host": "windows-endpoint-01",
        "source": "WinEventLog:Security",
        "sourcetype": "XmlWinEventLog:Security",
        "EventCode": "4688",
        "src": "192.0.2.25",
        "dest": "198.51.100.40",
        "process_name": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "parent_process_name": "C:\\Windows\\explorer.exe",
        "severity": "high",
    }
    payload = {"preview": False, "offset": 0, "results": [raw_result]}

    response = SplunkESResponse.from_raw_response(payload)

    assert response.results[0]._raw == raw_result  # noqa: S101
