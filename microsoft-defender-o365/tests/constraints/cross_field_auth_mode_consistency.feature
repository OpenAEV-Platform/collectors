@configuration @validation @cross-field

Feature: Cross-field validator enforces mutually-exclusive field group consistency
  As a developer
  I want the config model to reject inconsistent field combinations
  So that incompatible authentication or operational modes are caught at startup

  Background:
    Given the pydantic-settings library is available
    And a @model_validator enforces group consistency

  Scenario Outline: Certificate auth mode enabled without certificate required fields raises ValidationError
    Given SOURCE_USE_CERTIFICATE_AUTH is "<mode_flag_value>"
    And SOURCE_CLIENT_CERT_PATH is not set
    And SOURCE_CLIENT_CERT_THUMBPRINT is not set
    When DefenderO365Config is instantiated
    Then a ValidationError is raised
    And the error references "<error_field_a>" or "<error_field_b>"

    Examples:
      | mode_flag_value | error_field_a    | error_field_b            |
      | true             | client_cert_path | client_cert_thumbprint   |

  Scenario Outline: Credential auth mode enabled without credential required fields raises ValidationError
    Given SOURCE_USE_CERTIFICATE_AUTH is "<mode_flag_value>"
    And SOURCE_CLIENT_SECRET is not set
    When DefenderO365Config is instantiated
    Then a ValidationError is raised
    And the error references "<error_field>"

    Examples:
      | mode_flag_value | error_field   |
      | false            | client_secret |
