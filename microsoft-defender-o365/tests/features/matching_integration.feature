@matching @oaev @microsoft-defender-o365

Feature: BasicCollectorEngine produces ExpectationResult for O365 alerts via template matching flow

  As a collector integration
  I want the template engine to match O365 OAEVData against expectations using the 5 supported signatures
  So that satisfied expectations produce ExpectationResult with is_valid=True and matched traces

  Background:
    Given SUPPORTED_SIGNATURES is defined with 5 types
    And BasicCollectorEngine is configured with DefenderO365DataFetcher and MicrosoftDefenderO365SourceData
    And OpenAEVDetectionHelper is initialized with the 5 supported signature types

  Scenario: Fully matching alert produces ExpectationResult with is_valid=True
    Given a DetectionExpectation with signatures matching the 5 supported types
    And MicrosoftDefenderO365SourceData.to_oaev_data() produces OAEVData with matching values for all signature keys
    And MicrosoftDefenderO365SourceData.is_detected() returns True
    When the engine processes the expectation against the fetched data
    Then ExpectationResult.is_valid is True
    And ExpectationResult.matched_alerts contains the serialized TraceData

  Scenario: Non-matching alert produces ExpectationResult with is_valid=False
    Given a DetectionExpectation with signatures for the supported types
    And MicrosoftDefenderO365SourceData.to_oaev_data() produces OAEVData with non-matching values
    When the engine processes the expectation against the fetched data
    Then ExpectationResult.is_valid is False
    And ExpectationResult.matched_alerts is empty

  Scenario: Unsupported signature types in expectation are filtered out
    Given an expectation with signatures including types NOT in SUPPORTED_SIGNATURES
    When SourceHandler.get_expectation_signature_groups filters against the 5 supported types
    Then only signatures matching SUPPORTED_SIGNATURES are retained in the groups
    And unsupported types are silently ignored

  Scenario: PreventionExpectation with is_prevented=True produces is_valid=True with break
    Given a PreventionExpectation with matching signatures
    And MicrosoftDefenderO365SourceData.is_prevented() returns True
    When the engine processes the expectation
    Then ExpectationResult.is_valid is True
    And processing breaks out of the data loop (breakflag=True)

  Scenario: Empty fetched data produces is_valid=False for all expectations
    Given expectations exist but DefenderO365DataFetcher.fetch_data() returns empty list
    When the engine processes the batch
    Then all ExpectationResult objects have is_valid=False

  Scenario: Data fetch error produces ExpectationResult.from_error per expectation
    Given DefenderO365DataFetcher.fetch_data() raises an exception
    When the engine processes the batch
    Then each expectation gets an ExpectationResult with is_valid=False and error_message set
