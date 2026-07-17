@lifecycle @container @startup

Feature: Containerized service starts without errors
  As a developer
  I want my containerized service to start cleanly in daemon mode
  So that I can verify the deployment scaffold is functional before adding business logic

  Background:
    Given a <PLATFORM> instance is running
    And a docker-compose.yml is configured with the service container

  Scenario Outline: Service process remains alive with no unhandled exceptions
    Given a minimal <SERVICE_NAME> instantiated from <BASE_CLASS> with stub Source wired
    When the service process is started via docker-compose
    Then the process remains alive in daemon mode
    And no unhandled exception appears in the service logs within <startup_window_seconds> seconds of startup

    Examples:
      | PLATFORM | SERVICE_NAME | BASE_CLASS    | startup_window_seconds |
      | OpenAEV  | Collector    | BaseCollector | 10                     |
