@serialization @oaev @microsoft-defender-o365

Feature: DefenderO365SourceData.to_traces_data() produces TraceData for the engine's per-element trace serialization

  As a collector source data implementation
  I want to_traces_data() to return a valid TraceData from raw alert fields
  So that the template engine can serialize confirmed traces into ExpectationResult.matched_alerts

  Background:
    Given a DefenderO365SourceData wrapping a raw Graph Security alert

  Scenario Outline: Alert with title, alertWebUrl, and createdDateTime produces valid TraceData
    Given a DefenderO365SourceData wrapping a raw alert with title = "<title>", alertWebUrl = "<alert_url>", createdDateTime = "<created_dt>"
    When to_traces_data() is called
    Then the returned object is a TraceData instance
    And TraceData.alert_name = "<title>"
    And TraceData.alert_link equals "<alert_url>"
    And TraceData.alert_date equals "<created_dt>"

    Examples:
      | title                   | alert_url                                       | created_dt           |
      | Phishing email detected | https://security.microsoft.com/alerts/alert-001 | 2026-07-05T14:00:00Z |

  Scenario Outline: alertWebUrl absent causes fallback to incidentWebUrl
    Given a DefenderO365SourceData wrapping a raw alert with alertWebUrl = None
    And the raw alert has incidentWebUrl = "<incident_url>"
    And the raw alert has title = "<title>"
    And the raw alert has createdDateTime = "<created_dt>"
    When to_traces_data() is called
    Then the returned object is a TraceData instance
    And TraceData.alert_link equals "<incident_url>"

    Examples:
      | incident_url                                           | title       | created_dt           |
      | https://security.microsoft.com/incidents/incident-007 | Test Alert  | 2026-07-05T14:00:00Z |

  Scenario: TraceData.model_dump() round-trip preserves keys readable by ExpectationTrace
    Given a TraceData produced by to_traces_data() with valid alert_name and alert_link
    When TraceData.model_dump() is called
    Then the resulting dict contains key "alert_name"
    And the resulting dict contains key "alert_link"
    And the resulting dict contains key "alert_date"

  Scenario: Both alertWebUrl and incidentWebUrl absent (missing-URL edge case)
    Given a DefenderO365SourceData wrapping a raw alert where alertWebUrl is None and incidentWebUrl is None
    And the raw alert has title = "<title>"
    And the raw alert has createdDateTime = "<created_dt>"
    When to_traces_data() is called
    Then the returned object is a TraceData instance
    And TraceData.alert_link is a valid URL

    Examples:
      | title      | created_dt           |
      | No Link    | 2026-07-05T14:00:00Z |
