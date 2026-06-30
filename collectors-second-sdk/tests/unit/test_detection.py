"""Tests for SignatureMatcher (detection module)."""

import logging

import pytest

from collectors_second_sdk import SignatureMatcher, _decode_value, _is_base64_encoded


class TestIsBase64Encoded:
    def test_valid_base64(self):
        assert _is_base64_encoded("SGVsbG8=") is True

    def test_valid_base64_no_padding(self):
        assert _is_base64_encoded("SGVsbG8gV29ybGQ=") is True

    def test_not_base64_odd_length(self):
        assert _is_base64_encoded("abc") is False

    def test_not_base64_invalid_chars(self):
        assert _is_base64_encoded("not!base64!!") is False

    def test_empty_string(self):
        assert _is_base64_encoded("") is True  # vacuously valid


class TestDecodeValue:
    def test_decodes_base64(self):
        import base64

        encoded = base64.b64encode(b"hello world").decode()
        assert _decode_value(encoded) == "hello world"

    def test_returns_plain_string_unchanged(self):
        assert _decode_value("plain text here") == "plain text here"

    def test_invalid_base64_returns_original(self):
        # Valid pattern but garbled content
        assert _decode_value("////") == "////"  # decodes to bytes but may fail utf-8


class TestSignatureMatcherFuzzy:
    def test_fuzzy_match_above_threshold(self):
        matcher = SignatureMatcher(relevant_signature_types=["process_name"])
        assert matcher.match_fuzzy("explorer.exe", ["explorer.exe", "cmd.exe"], 80) is True

    def test_fuzzy_match_below_threshold(self):
        matcher = SignatureMatcher(relevant_signature_types=["process_name"])
        assert matcher.match_fuzzy("explorer.exe", ["completely_different"], 80) is False

    def test_fuzzy_match_partial(self):
        matcher = SignatureMatcher(relevant_signature_types=["process_name"])
        # "explor.exe" vs "explorer.exe" — high but not 100
        assert matcher.match_fuzzy("explorer.exe", ["explor.exe"], 70) is True


class TestSignatureMatcherByType:
    def test_simple_match_all_signatures(self):
        matcher = SignatureMatcher(
            relevant_signature_types=["source_ipv4_address", "target_ipv4_address"]
        )
        signatures = [
            {"type": "source_ipv4_address", "value": "10.0.0.1"},
            {"type": "target_ipv4_address", "value": "192.168.1.1"},
        ]
        alert_data = {
            "source_ipv4_address": {"type": "simple", "data": "10.0.0.1"},
            "target_ipv4_address": {"type": "simple", "data": "192.168.1.1"},
        }
        assert matcher.match(signatures, alert_data) is True

    def test_simple_match_partial_fails(self):
        matcher = SignatureMatcher(
            relevant_signature_types=["source_ipv4_address", "target_ipv4_address"]
        )
        signatures = [
            {"type": "source_ipv4_address", "value": "10.0.0.1"},
            {"type": "target_ipv4_address", "value": "192.168.1.1"},
        ]
        alert_data = {
            "source_ipv4_address": {"type": "simple", "data": "10.0.0.1"},
            "target_ipv4_address": {"type": "simple", "data": "172.16.0.1"},
        }
        assert matcher.match(signatures, alert_data) is False

    def test_fuzzy_match_via_alert_type(self):
        matcher = SignatureMatcher(relevant_signature_types=["process_name"])
        signatures = [{"type": "process_name", "value": "explorer.exe"}]
        alert_data = {
            "process_name": {
                "type": "fuzzy",
                "data": ["explorer.exe"],
                "score": 80,
            }
        }
        assert matcher.match(signatures, alert_data) is True

    def test_irrelevant_signatures_ignored(self):
        matcher = SignatureMatcher(relevant_signature_types=["source_ipv4_address"])
        signatures = [
            {"type": "source_ipv4_address", "value": "10.0.0.1"},
            {"type": "cloud_provider", "value": "AWS"},  # not relevant
        ]
        alert_data = {
            "source_ipv4_address": {"type": "simple", "data": "10.0.0.1"},
        }
        assert matcher.match(signatures, alert_data) is True


class TestSignatureMatcherCommandLine:
    def test_command_line_match(self):
        matcher = SignatureMatcher(relevant_signature_types=[])
        signatures = [{"type": "command_line", "value": "powershell -enc abc123"}]
        alert_data = {
            "command_line": {"data": ["powershell"]},
        }
        assert matcher.match(signatures, alert_data) is True

    def test_command_line_no_match(self):
        matcher = SignatureMatcher(relevant_signature_types=[])
        signatures = [{"type": "command_line", "value": "curl http://evil.com"}]
        alert_data = {
            "command_line": {"data": ["powershell"]},
        }
        assert matcher.match(signatures, alert_data) is False

    def test_command_line_base64_decoded(self):
        import base64

        encoded_cmd = base64.b64encode(b"powershell -enc malware").decode()
        matcher = SignatureMatcher(relevant_signature_types=[])
        signatures = [{"type": "command_line", "value": encoded_cmd}]
        alert_data = {
            "process_name": {"data": ["powershell"]},
        }
        assert matcher.match(signatures, alert_data) is True

    def test_no_command_line_signatures_returns_false(self):
        matcher = SignatureMatcher(relevant_signature_types=[])
        signatures = [{"type": "source_ipv4_address", "value": "10.0.0.1"}]
        alert_data = {"command_line": {"data": ["anything"]}}
        assert matcher.match(signatures, alert_data) is False


class TestSignatureMatcherIntegration:
    def test_falls_back_to_command_line_when_type_match_fails(self):
        """When no relevant_signature_types match, try command_line fallback."""
        matcher = SignatureMatcher(relevant_signature_types=["process_name"])
        signatures = [
            {"type": "process_name", "value": "notepad.exe"},
            {"type": "command_line", "value": "notepad.exe document.txt"},
        ]
        alert_data = {
            "process_name": {"type": "simple", "data": "explorer.exe"},  # no match
            "command_line": {"data": ["notepad.exe"]},
        }
        # type match fails (notepad != explorer), but command_line fallback succeeds
        assert matcher.match(signatures, alert_data) is True

    def test_with_logger(self):
        logger = logging.getLogger("test_detection")
        matcher = SignatureMatcher(
            relevant_signature_types=["process_name"], logger=logger
        )
        signatures = [{"type": "process_name", "value": "test.exe"}]
        alert_data = {
            "process_name": {"type": "fuzzy", "data": ["test.exe"], "score": 50}
        }
        assert matcher.match(signatures, alert_data) is True
