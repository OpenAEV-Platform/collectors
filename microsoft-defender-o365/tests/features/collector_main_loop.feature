@orchestration @oaev @microsoft-defender-o365

Feature: DefenderO365Collector main loop executes end-to-end with stubs
  As a developer
  I want the orchestrator loop to run without errors even when all steps are stubbed
  So that I can verify the wiring before implementing individual steps

  Background:
    Given CHK.1 scaffold is in place
    And CHK.2 DefenderO365Config is defined
    And DataFetcher.fetch_data() is configured to return at least one mock alert element
    And the OpenAEV API returns at least one mock expectation
    And match_signature_groups_and_oaevdata returns True for the mock data
    And Source is declared as Source(data_fetcher_model=DefenderO365DataFetcher, source_data_model=DefenderO365SourceData, signatures=SUPPORTED_SIGNATURES)

  Scenario Outline: Collector loop completes a full cycle with stubs
    Given a DefenderO365Collector(BaseCollector) instance with all methods stubbed
    When one loop iteration is triggered
    Then get_source_data is called exactly once
    And serialize_as_oaevdata is called exactly once
    And get_expectation_signature_groups is called exactly once
    And match_signature_groups_and_oaevdata is called exactly once
    And match_expectation_and_sourcedata is called exactly once
    And serialize_as_tracedata is called exactly once
    And no unhandled exception is raised

    Examples:
      | stub_return_get_source_data | stub_return_match_groups | stub_return_match_expectation |
      | [<mock_alert>]              | True                     | (True, False)                 |

  Scenario Outline: Configuration is loaded correctly via ConfigLoader
    Given SOURCE_TENANT_ID is set to "<tenant_id>"
    And SOURCE_CLIENT_ID is set to "<client_id>"
    And SOURCE_CLIENT_SECRET is set to "<client_secret>"
    When the collector is instantiated via ConfigLoader
    Then DefenderO365Config loads without error
    And config.tenant_id equals "<tenant_id>"

    Examples:
      | tenant_id   | client_id   | client_secret |
      | test-tenant | test-client | test-secret   |

  Scenario: Main entry point starts BaseCollector with the declared Source
    Given the collector entry point dependencies are stubbed
    When the collector main entry point is invoked
    Then Source is declared with the Microsoft Defender O365 data fetcher, source data, and signatures
    And BaseCollector is instantiated with the declared Source
    And BaseCollector is started exactly once

  Scenario Outline: Loop emits LOG_PREFIX log messages at each engine step
    Given a DefenderO365Collector with a DataFetcher returning at least one mock alert
    And the OpenAEV API returns at least one mock expectation
    When one engine cycle is triggered via run_engine()
    Then a log message containing "[BasicCollectorEngine]" and "Starting processing cycle" at INFO is emitted
    And a log message containing "[BasicCollectorEngine]" and "Fetching data providing" at INFO is emitted
    And a log message containing "[BasicCollectorEngine]" and "Batch processed" at INFO is emitted
    And a log message containing "[BasicCollectorEngine]" and "Processing cycle completed" at INFO is emitted

    Examples:
      | expected_log_count |
      | 4                  |
