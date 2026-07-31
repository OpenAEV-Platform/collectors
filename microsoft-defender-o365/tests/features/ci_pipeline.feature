@ci @quality @automation

Feature: CI pipeline runs lint and tests on push
  As a developer
  I want every push to trigger automated lint and test jobs
  So that regressions are caught before code review

  Background:
    Given a CI pipeline is configured (GitHub Actions, GitLab CI, or equivalent)
    And lint and test jobs are defined in the pipeline configuration

  Scenario Outline: Push triggers lint and test jobs that both pass
    Given a commit is pushed to the repository
    When the CI pipeline runs
    Then the lint job completes with exit code <lint_exit_code>
    And the test job completes with exit code <test_exit_code>

    Examples:
      | lint_exit_code | test_exit_code |
      | 0              | 0              |
