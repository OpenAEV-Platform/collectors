"""Essential tests for numeric field minimum-bound validation - Gherkin GWT Format."""

from types import ModuleType

import pytest
from tests.conftest import (
    _given_microsoft_defender_o365_all_required_fields_present,
    _given_microsoft_defender_o365_env_var_set,
    _then_microsoft_defender_o365_error_references_field,
    _then_microsoft_defender_o365_validation_error_is_raised,
    _when_microsoft_defender_o365_config_is_instantiated,
)

# --------
# Scenarios
# --------


# Scenario Outline: Numeric field below minimum threshold raises ValidationError
@pytest.mark.parametrize(
    "numeric_field, invalid_value, error_field",
    [
        ("RATE_LIMIT_REQUESTS_PER_MINUTE", "0", "rate_limit_requests_per_minute"),
        ("RATE_LIMIT_REQUESTS_PER_MINUTE", "-1", "rate_limit_requests_per_minute"),
    ],
    ids=[
        "rate_limit_requests_per_minute_zero",
        "rate_limit_requests_per_minute_negative",
    ],
)
def test_numeric_field_below_minimum_threshold_raises_validation_error(
    monkeypatch,
    microsoft_defender_o365_source_config_module: ModuleType,
    numeric_field,
    invalid_value,
    error_field,
):
    """Scenario Outline: Numeric field below minimum threshold raises ValidationError"""
    # Given: all required fields are set, and SOURCE_<NUMERIC_FIELD> is
    # "<invalid_value>"
    _given_microsoft_defender_o365_all_required_fields_present(monkeypatch)
    _given_microsoft_defender_o365_env_var_set(
        monkeypatch, numeric_field, invalid_value
    )

    # When: DefenderO365Config is instantiated
    _, error = _when_microsoft_defender_o365_config_is_instantiated(
        monkeypatch, microsoft_defender_o365_source_config_module
    )

    # Then: a ValidationError is raised, and the error references the "<error_field>" field
    _then_microsoft_defender_o365_validation_error_is_raised(error)
    _then_microsoft_defender_o365_error_references_field(error, error_field)
