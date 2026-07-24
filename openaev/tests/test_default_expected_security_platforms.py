from openaev.constants import DEFAULT_EXPECTED_SECURITY_PLATFORMS
from openaev.processors.common_processor import CommonProcessor


def test_fills_defaults_for_declared_expectation_types():
    payload_information = {"payload_expectations": ["PREVENTION", "DETECTION"]}

    CommonProcessor._apply_default_expected_security_platforms(payload_information)

    assert payload_information["payload_expected_security_platforms"] == {
        "DETECTION": ["EDR", "XDR", "SIEM"],
        "PREVENTION": ["EDR", "XDR"],
    }


def test_fills_defaults_only_for_declared_expectation_types():
    payload_information = {"payload_expectations": ["DETECTION"]}

    CommonProcessor._apply_default_expected_security_platforms(payload_information)

    assert payload_information["payload_expected_security_platforms"] == {
        "DETECTION": ["EDR", "XDR", "SIEM"],
    }


def test_ignores_expectation_types_without_defaults():
    payload_information = {"payload_expectations": ["MANUAL"]}

    CommonProcessor._apply_default_expected_security_platforms(payload_information)

    assert "payload_expected_security_platforms" not in payload_information


def test_explicit_value_takes_precedence():
    explicit = {"DETECTION": ["SIEM"]}
    payload_information = {
        "payload_expectations": ["PREVENTION", "DETECTION"],
        "payload_expected_security_platforms": explicit,
    }

    CommonProcessor._apply_default_expected_security_platforms(payload_information)

    assert payload_information["payload_expected_security_platforms"] == {
        "DETECTION": ["SIEM"],
    }


def test_explicit_empty_map_is_preserved():
    # An explicit empty map means "any platform" and must not be overwritten.
    payload_information = {
        "payload_expectations": ["PREVENTION", "DETECTION"],
        "payload_expected_security_platforms": {},
    }

    CommonProcessor._apply_default_expected_security_platforms(payload_information)

    assert payload_information["payload_expected_security_platforms"] == {}


def test_explicit_null_is_treated_as_missing():
    # A JSON null (Python None) means "not declared" and gets the defaults.
    payload_information = {
        "payload_expectations": ["PREVENTION", "DETECTION"],
        "payload_expected_security_platforms": None,
    }

    CommonProcessor._apply_default_expected_security_platforms(payload_information)

    assert payload_information["payload_expected_security_platforms"] == {
        "DETECTION": ["EDR", "XDR", "SIEM"],
        "PREVENTION": ["EDR", "XDR"],
    }


def test_payload_without_expectations_left_untouched():
    for payload_information in ({}, {"payload_expectations": []}):
        CommonProcessor._apply_default_expected_security_platforms(payload_information)

        assert "payload_expected_security_platforms" not in payload_information


def test_defaults_are_copied_per_payload():
    first = {"payload_expectations": ["DETECTION"]}
    second = {"payload_expectations": ["DETECTION"]}

    CommonProcessor._apply_default_expected_security_platforms(first)
    CommonProcessor._apply_default_expected_security_platforms(second)

    first["payload_expected_security_platforms"]["DETECTION"].append("NDR")

    assert second["payload_expected_security_platforms"]["DETECTION"] == [
        "EDR",
        "XDR",
        "SIEM",
    ]
    assert DEFAULT_EXPECTED_SECURITY_PLATFORMS["DETECTION"] == ["EDR", "XDR", "SIEM"]
