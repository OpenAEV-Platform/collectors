@lifecycle @catalog @registration

Feature: Service registers in a platform catalog on startup
  As a platform operator
  I want deployed services to self-register in the platform catalog
  So that they are discoverable and their status is tracked centrally

  Background:
    Given the platform catalog is accessible
    And the service is configured with a valid registration

  Scenario Outline: Service appears in the catalog after startup
    Given the service is running with its catalog registration configuration
    When the platform catalog is queried for registered services
    Then "<service_name>" appears in the service list
    And its status is "<registration_status>"

    Examples:
      | service_name | registration_status |
      | Collector    | Deployed             |
