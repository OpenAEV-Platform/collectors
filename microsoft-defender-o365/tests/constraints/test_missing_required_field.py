"""Essential tests for missing required field validation - Gherkin GWT Format."""

from types import ModuleType

import pytest
from tests.conftest import (
    _given_microsoft_defender_o365_all_required_fields_present,
    _given_microsoft_defender_o365_env_var_not_set,
    _then_microsoft_defender_o365_error_references_field,
    _then_microsoft_defender_o365_validation_error_is_raised,
    _when_microsoft_defender_o365_config_is_instantiated,
)

# --------
# Scenarios
# --------


# Scenario Outline: Missing required field raises ValidationError referencing the field
@pytest.mark.parametrize(
    "required_field, error_field",
    [
        ("TENANT_ID", "tenant_id"),
    ],
    ids=[
        "missing_tenant_id",
    ],
)
def test_missing_required_field_raises_validation_error_referencing_the_field(
    monkeypatch,
    microsoft_defender_o365_source_config_module: ModuleType,
    required_field,
    error_field,
):
    """Scenario Outline: Missing required field raises ValidationError referencing the field"""
    # Given: MICROSOFT_DEFENDER_O365_<REQUIRED_FIELD> is not set, and all other required fields
    # are present
    _given_microsoft_defender_o365_env_var_not_set(monkeypatch, required_field)
    _given_microsoft_defender_o365_all_required_fields_present(
        monkeypatch, exclude=required_field
    )

    # When: DefenderO365Config is instantiated
    _, error = _when_microsoft_defender_o365_config_is_instantiated(
        microsoft_defender_o365_source_config_module
    )

    # Then: a ValidationError is raised, and the error references the "<error_field>" field
    _then_microsoft_defender_o365_validation_error_is_raised(error)
    _then_microsoft_defender_o365_error_references_field(error, error_field)
