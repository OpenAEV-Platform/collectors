@configuration @validation @fail-fast

Feature: Missing required field raises a ValidationError at instantiation
  As a developer
  I want the config model to fail immediately when a required field is absent
  So that I get a clear error message instead of a runtime NoneType crash

  Background:
    Given the pydantic-settings library is available
    And all fields except the tested one are correctly set

  Scenario Outline: Missing required field raises ValidationError referencing the field
    Given SOURCE_<REQUIRED_FIELD> is not set
    And all other required fields are present
    When DefenderO365Config is instantiated
    Then a ValidationError is raised
    And the error references the "<error_field>" field

    Examples:
      | REQUIRED_FIELD | error_field |
      | TENANT_ID      | tenant_id   |
