"""Essential tests for valid configuration loading via Pydantic BaseSettings - Gherkin GWT Format."""

from types import ModuleType

import pytest
from tests.conftest import (
    _given_microsoft_defender_o365_env_var_set,
    _then_microsoft_defender_o365_no_validation_error_raised,
    _when_microsoft_defender_o365_config_is_instantiated,
)

# --------
# Scenarios
# --------


# Scenario Outline: Valid configuration with all required fields loads successfully
@pytest.mark.parametrize(
    "field_1, field_2, field_3, field_1_attr, default_field, default_value",
    [
        (
            "TENANT_ID",
            "CLIENT_ID",
            "CLIENT_SECRET",
            "tenant_id",
            "base_url",
            "https://graph.microsoft.com/v1.0",
        ),
    ],
    ids=[
        "tenant_client_id_and_secret_set",
    ],
)
def test_valid_configuration_with_all_required_fields_loads_successfully(
    monkeypatch,
    microsoft_defender_o365_source_config_module: ModuleType,
    field_1,
    field_2,
    field_3,
    field_1_attr,
    default_field,
    default_value,
):
    """Scenario Outline: Valid configuration with all required fields loads successfully"""
    # Given: MICROSOFT_DEFENDER_O365_<FIELD_1>/<FIELD_2>/<FIELD_3> are each set to a non-empty
    # string
    _given_microsoft_defender_o365_env_var_set(monkeypatch, field_1, "test-tenant-id")
    _given_microsoft_defender_o365_env_var_set(monkeypatch, field_2, "test-client-id")
    _given_microsoft_defender_o365_env_var_set(
        monkeypatch, field_3, "test-client-secret"
    )

    # When: DefenderO365Config is instantiated
    config, error = _when_microsoft_defender_o365_config_is_instantiated(
        microsoft_defender_o365_source_config_module
    )

    # Then: no ValidationError is raised, config.<FIELD_1_ATTR> is not None, and
    # config.<DEFAULT_FIELD> equals "<default_value>"
    _then_microsoft_defender_o365_no_validation_error_raised(error)
    _then_config_attr_is_not_none(config, field_1_attr)
    _then_config_attr_equals(config, default_field, default_value)


# --------
# Given Methods
# --------


# --------
# When Methods
# --------


# --------
# Then Methods
# --------


def _then_config_attr_is_not_none(config, attr_name: str) -> None:
    """Then config.<FIELD_1_ATTR> is not None.

    Args:
        config: The instantiated configuration object.
        attr_name: The attribute name expected to be non-``None`` (e.g. ``"tenant_id"``).

    """
    assert getattr(config, attr_name) is not None


def _then_config_attr_equals(config, attr_name: str, expected_value: str) -> None:
    """Then config.<DEFAULT_FIELD> equals "<default_value>".

    Args:
        config: The instantiated configuration object.
        attr_name: The attribute name to check (e.g. ``"base_url"``).
        expected_value: The value the attribute is expected to equal.

    """
    assert str(getattr(config, attr_name)) == expected_value
