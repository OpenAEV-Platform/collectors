@fetch @chk6 @data_fetcher
Feature: Fetch source data from Microsoft Defender O365

  As a collector operator
  I want the data fetcher to retrieve alerts from the Graph Security API
  So that alerts are available for downstream processing

  Background:
    Given the Microsoft Defender O365 source is configured
    And the Graph Security API v2 endpoint is accessible

  Scenario: Fetch alerts from a single page response
    When the data fetcher retrieves alerts
    And the API returns a single page of alerts
    Then the fetcher returns a list of source data objects
    And each source data object contains the raw alert data
    And the number of results matches the API response count

  Scenario: Fetch alerts with pagination
    When the data fetcher retrieves alerts
    And the API returns multiple pages of alerts
    Then the fetcher follows all pagination links
    And the total result count equals the sum of all pages
    And each page is processed before following the next link

  Scenario: Handle rate limiting (HTTP 429)
    When the data fetcher retrieves alerts
    And the API returns a 429 rate limit response
    Then the fetcher sleeps for the Retry-After duration
    And the fetcher retries the request
    And the final result includes the alerts

  Scenario: Handle token expiry (HTTP 401)
    When the data fetcher retrieves alerts
    And the API returns a 401 unauthorized response
    Then the fetcher refreshes the access token
    And the fetcher retries with the new token
    And the final result includes the alerts

  Scenario: Filter evidence to analyzedMessageEvidence only
    When the data fetcher retrieves alerts
    And the alerts contain mixed evidence types
    Then only analyzedMessageEvidence items are preserved
    And other evidence types are excluded from the result

  Scenario: Empty response returns empty list
    When the data fetcher retrieves alerts
    And the API returns an empty value array
    Then the fetcher returns an empty list

  Scenario: OData filter is applied to the request
    When the data fetcher retrieves alerts
    Then the request URL contains the serviceSource filter
    And the filter matches the configured service source
