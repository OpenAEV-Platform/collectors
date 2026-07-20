"""Essential tests for cross-field authentication mode consistency validation - Gherkin GWT Format."""

from types import ModuleType

import pytest
from tests.conftest import (
    _given_microsoft_defender_o365_all_required_fields_present,
    _given_microsoft_defender_o365_env_var_not_set,
    _given_microsoft_defender_o365_env_var_set,
    _then_microsoft_defender_o365_error_references_field,
    _then_microsoft_defender_o365_error_references_one_of_fields,
    _then_microsoft_defender_o365_validation_error_is_raised,
    _when_microsoft_defender_o365_config_is_instantiated,
)

# --------
# Scenarios
# --------


# Scenario Outline: Certificate auth mode enabled without certificate required fields raises
# ValidationError
@pytest.mark.parametrize(
    "mode_flag_value, error_field_a, error_field_b",
    [
        ("true", "client_cert_path", "client_cert_thumbprint"),
    ],
    ids=[
        "certificate_auth_enabled_missing_cert_fields",
    ],
)
def test_certificate_auth_mode_enabled_without_certificate_required_fields_raises_validation_error(
    monkeypatch,
    microsoft_defender_o365_source_config_module: ModuleType,
    mode_flag_value,
    error_field_a,
    error_field_b,
):
    """Scenario Outline: Certificate auth mode enabled without certificate required fields raises ValidationError"""
    # Given: SOURCE_USE_CERTIFICATE_AUTH is "<mode_flag_value>", and
    # SOURCE_CLIENT_CERT_PATH/CLIENT_CERT_THUMBPRINT are not set
    _given_microsoft_defender_o365_all_required_fields_present(monkeypatch)
    _given_microsoft_defender_o365_env_var_set(
        monkeypatch, "USE_CERTIFICATE_AUTH", mode_flag_value
    )
    _given_microsoft_defender_o365_env_var_not_set(monkeypatch, "CLIENT_CERT_PATH")
    _given_microsoft_defender_o365_env_var_not_set(
        monkeypatch, "CLIENT_CERT_THUMBPRINT"
    )

    # When: DefenderO365Config is instantiated
    _, error = _when_microsoft_defender_o365_config_is_instantiated(
        monkeypatch, microsoft_defender_o365_source_config_module
    )

    # Then: a ValidationError is raised, and the error references "<error_field_a>" or
    # "<error_field_b>"
    _then_microsoft_defender_o365_validation_error_is_raised(error)
    _then_microsoft_defender_o365_error_references_one_of_fields(
        error, [error_field_a, error_field_b]
    )


# Scenario Outline: Credential auth mode enabled without credential required fields raises
# ValidationError
@pytest.mark.parametrize(
    "mode_flag_value, error_field",
    [
        ("false", "client_secret"),
    ],
    ids=[
        "credential_auth_enabled_missing_client_secret",
    ],
)
def test_credential_auth_mode_enabled_without_credential_required_fields_raises_validation_error(
    monkeypatch,
    microsoft_defender_o365_source_config_module: ModuleType,
    mode_flag_value,
    error_field,
):
    """Scenario Outline: Credential auth mode enabled without credential required fields raises ValidationError"""
    # Given: SOURCE_USE_CERTIFICATE_AUTH is "<mode_flag_value>", and
    # SOURCE_CLIENT_SECRET is not set
    _given_microsoft_defender_o365_all_required_fields_present(
        monkeypatch, exclude="CLIENT_SECRET"
    )
    _given_microsoft_defender_o365_env_var_set(
        monkeypatch, "USE_CERTIFICATE_AUTH", mode_flag_value
    )
    _given_microsoft_defender_o365_env_var_not_set(monkeypatch, "CLIENT_SECRET")

    # When: DefenderO365Config is instantiated
    _, error = _when_microsoft_defender_o365_config_is_instantiated(
        monkeypatch, microsoft_defender_o365_source_config_module
    )

    # Then: a ValidationError is raised, and the error references "<error_field>"
    _then_microsoft_defender_o365_validation_error_is_raised(error)
    _then_microsoft_defender_o365_error_references_field(error, error_field)
