@configuration @environment @loading

Feature: Component loads configuration from environment variables at instantiation
  As a developer
  I want configuration to be automatically loaded from environment variables
  So that deployment configuration is externalized and follows 12-factor app principles

  Background:
    Given the configuration model uses pydantic-settings BaseSettings
    And environment variables follow the SOURCE_<FIELD> naming convention

  Scenario Outline: Environment variables are correctly mapped to config attributes
    Given SOURCE_<FIELD_1> is set to "<field_1_value>"
    And SOURCE_<FIELD_2> is set to "<field_2_value>"
    And SOURCE_<FIELD_3> is set to "<field_3_value>"
    When <COMPONENT_CLASS> is instantiated
    Then <CONFIG_CLASS> loads without error
    And config.<field_1_attr> equals "<field_1_value>"

    Examples:
      | FIELD_1     | FIELD_2     | FIELD_3        | field_1_value | field_2_value | field_3_value | COMPONENT_CLASS | CONFIG_CLASS  | field_1_attr |
      | <FIELD_A>   | <FIELD_B>   | <FIELD_C>      | test-value-a  | test-value-b  | test-value-c  | <ComponentName> | <ConfigClass> | <attr_a>     |
