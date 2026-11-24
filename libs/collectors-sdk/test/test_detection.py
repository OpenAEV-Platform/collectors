"""Tests for the OpenAEVDetectionHelper alert-element matching."""

import base64
from unittest.mock import MagicMock

import pytest
from collectors_sdk import OpenAEVDetectionHelper


def _given_helper(relevant_types=("process_name", "command_line", "file_name")):
    return OpenAEVDetectionHelper(MagicMock(), list(relevant_types))


@pytest.mark.parametrize(
    ("alert", "expected"),
    [
        ({"type": "simple", "data": ["svchost.exe evil.exe"]}, True),
        ({"type": "simple", "data": ["svchost.exe"]}, False),
        ({"type": "fuzzy", "data": ["evil.exe"], "score": 80}, True),
        ({"type": "fuzzy", "data": ["benign.dll"], "score": 80}, False),
    ],
)
def test_matches_a_single_signature_by_policy(alert, expected) -> None:
    """It applies the simple or fuzzy policy declared by the alert data."""
    helper = _given_helper()
    signatures = [{"type": "process_name", "value": "evil.exe"}]
    result = helper.match_alert_elements(signatures, {"process_name": alert})
    assert result is expected


def test_requires_every_relevant_signature_to_match() -> None:
    """It matches only when all relevant signatures match."""
    helper = _given_helper(relevant_types=("process_name", "file_name"))
    signatures = [
        {"type": "process_name", "value": "evil.exe"},
        {"type": "file_name", "value": "payload.bin"},
    ]
    alert = {
        "process_name": {"type": "simple", "data": ["evil.exe"]},
        "file_name": {"type": "simple", "data": ["other.bin"]},
    }
    assert helper.match_alert_elements(signatures, alert) is False


def test_ignores_signature_types_that_are_not_relevant() -> None:
    """It skips signatures whose type is not relevant to the collector."""
    helper = _given_helper(relevant_types=("process_name",))
    signatures = [
        {"type": "process_name", "value": "evil.exe"},
        {"type": "hostname", "value": "victim"},
    ]
    alert = {"process_name": {"type": "simple", "data": ["evil.exe"]}}
    assert helper.match_alert_elements(signatures, alert) is True


def test_matches_base64_command_line_against_alert_process_data() -> None:
    """It decodes base64 command-line signatures before matching."""
    helper = _given_helper(relevant_types=("hostname",))
    command = base64.b64encode(b"powershell.exe -enc AAAA").decode()
    signatures = [{"type": "command_line", "value": command}]
    alert = {"process_name": {"type": "simple", "data": [" PowerShell.exe "]}}
    assert helper.match_alert_elements(signatures, alert) is True


def test_no_command_line_signature_means_no_command_line_match() -> None:
    """It does not fall back to command-line matching without such signature."""
    helper = _given_helper(relevant_types=("process_name",))
    signatures = [{"type": "process_name", "value": "evil.exe"}]
    alert = {"process_name": {"type": "simple", "data": ["other.exe"]}}
    assert helper.match_alert_elements(signatures, alert) is False


def test_no_relevant_signature_is_a_vacuous_match() -> None:
    """It matches when no signature is relevant (zero of zero matched)."""
    helper = _given_helper(relevant_types=("hostname",))
    signatures = [{"type": "process_name", "value": "evil.exe"}]
    alert = {"hostname": {"type": "simple", "data": ["other"]}}
    assert helper.match_alert_elements(signatures, alert) is True
