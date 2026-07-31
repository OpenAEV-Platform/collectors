@data-mapping @oaev @source-data

Feature: MicrosoftDefenderO365SourceData.to_oaev_data maps a compacted alert to OAEVData

  As a collector source data implementation
  I want each alert to be expressed as OAEVData with correct signature-keyed fields
  So that the matching engine can compare it against expectations

  Background:
    Given SUPPORTED_SIGNATURES is defined with 5 types
    And OAEVData accepts extra fields matching SignatureTypes enum values (extra="allow")

  Scenario Outline: Alert with full evidence maps all signature fields correctly
    Given a compacted alert with id = "<alert_id>"
    And evidence containing p1_sender_email = "<p1_sender>"
    And evidence containing p2_sender_email = "<p2_sender>"
    And evidence containing recipient_email_address = "<recipient>"
    And evidence containing url = "<url>"
    When to_oaev_data is called
    Then OAEVData[SIG_TYPE_SOURCE_EMAIL] is a list containing "<p1_sender>" and "<p2_sender>"
    And OAEVData[SIG_TYPE_TARGET_EMAIL] is a list containing "<recipient>"
    And OAEVData[SIG_TYPE_URL_HASH] is a list containing the SHA256, SHA1, and MD5 digest of "<url>"
    And OAEVData[SIG_TYPE_FILE_HASH] is an empty string
    And OAEVData[SIG_TYPE_EMAIL_CUSTOM_HEADER] is an empty string

    Examples:
      | alert_id | p1_sender    | p2_sender    | recipient       | url                        |
      | ALT-001  | bad@evil.com | spam@evil.com | victim@corp.com | https://phish.example.com/ |

  Scenario: Alert with duplicate sender emails deduplicates source list
    Given a compacted alert with id = "ALT-002"
    And evidence item 1 containing p1_sender_email = "bad@evil.com"
    And evidence item 2 containing p1_sender_email = "bad@evil.com"
    And evidence item 2 containing recipient_email_address = "victim@corp.com"
    And evidence item 1 containing recipient_email_address = "victim@corp.com"
    When to_oaev_data is called
    Then OAEVData[SIG_TYPE_SOURCE_EMAIL] is a list containing exactly one "bad@evil.com" entry

  Scenario: Alert with empty evidence produces empty lists for evidence-derived fields
    Given a compacted alert with id = "ALT-003"
    And evidence is an empty list
    When to_oaev_data is called
    Then OAEVData[SIG_TYPE_SOURCE_EMAIL] is an empty list
    And OAEVData[SIG_TYPE_TARGET_EMAIL] is an empty list
    And OAEVData[SIG_TYPE_URL_HASH] is an empty list

  Scenario: Alert with multiple evidence items merges all fields
    Given a compacted alert with id = "ALT-004"
    And evidence item 1 containing p1_sender_email = "sender1@evil.com"
    And evidence item 1 containing recipient_email_address = "victim1@corp.com"
    And evidence item 1 containing url = "https://url1.example.com/"
    And evidence item 2 containing p1_sender_email = "sender2@evil.com"
    And evidence item 2 containing recipient_email_address = "victim2@corp.com"
    And evidence item 2 containing url = "https://url2.example.com/"
    When to_oaev_data is called
    Then OAEVData[SIG_TYPE_SOURCE_EMAIL] is a list containing "sender1@evil.com" and "sender2@evil.com"
    And OAEVData[SIG_TYPE_TARGET_EMAIL] is a list containing "victim1@corp.com" and "victim2@corp.com"
    And OAEVData[SIG_TYPE_URL_HASH] contains hashes derived from both URLs
