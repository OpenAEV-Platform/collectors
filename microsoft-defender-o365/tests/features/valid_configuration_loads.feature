@configuration @validation @pydantic

Feature: Valid configuration loads without error via Pydantic BaseSettings
  As a developer
  I want my component configuration to validate on instantiation
  So that misconfigured deployments are caught at startup, not at runtime

  Background:
    Given the pydantic-settings library is available
    And environment variables are the primary configuration source

  Scenario Outline: Valid configuration with all required fields loads successfully
    Given SOURCE_<FIELD_1> is set to a non-empty string
    And SOURCE_<FIELD_2> is set to a non-empty string
    And SOURCE_<FIELD_3> is set to a non-empty string
    When DefenderO365Config is instantiated
    Then no ValidationError is raised
    And config.<FIELD_1_ATTR> is not None
    And config.<DEFAULT_FIELD> equals "<default_value>"

    Examples:
      | FIELD_1     | FIELD_2     | FIELD_3        | FIELD_1_ATTR | DEFAULT_FIELD | default_value                     |
      | TENANT_ID   | CLIENT_ID   | CLIENT_SECRET  | tenant_id    | base_url      | https://graph.microsoft.com/v1.0  |
