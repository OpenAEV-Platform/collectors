@configuration @validation @constraint

Feature: Numeric field below minimum raises a ValidationError
  As a developer
  I want numeric configuration fields to enforce minimum bounds
  So that invalid operational parameters are rejected at startup

  Background:
    Given the pydantic-settings library is available
    And all required fields are set to valid values

  Scenario Outline: Numeric field below minimum threshold raises ValidationError
    Given all required fields are set
    And MICROSOFT_DEFENDER_O365_<NUMERIC_FIELD> is "<invalid_value>"
    When DefenderO365Config is instantiated
    Then a ValidationError is raised
    And the error references the "<error_field>" field

    Examples:
      | NUMERIC_FIELD                  | invalid_value | error_field                    |
      | RATE_LIMIT_REQUESTS_PER_MINUTE | 0              | rate_limit_requests_per_minute |
      | RATE_LIMIT_REQUESTS_PER_MINUTE | -1             | rate_limit_requests_per_minute |
