@oauth2 @oaev @microsoft-defender-o365

Feature: MSGraphAuthClient acquires Microsoft Graph access tokens via MSAL
  As a collector process
  I want to obtain a valid access token for the Microsoft Graph API
  So that all downstream API calls can be authenticated

  Background:
    Given a valid DefenderO365Config is available
    And msal.ConfidentialClientApplication is patched for all tests
    And the scope is ["https://graph.microsoft.com/.default"]

  Scenario Outline: Client credentials mode returns an access token on first call
    Given use_certificate_auth is False
    And client_secret is a non-empty string
    And acquire_token_silent returns None (no cached token)
    And acquire_token_for_client returns {"access_token": "<token>", "token_type": "Bearer"}
    When get_access_token is called
    Then the returned value is "<token>"
    And acquire_token_for_client was called once

    Examples:
      | token  |
      | tok123 |

  Scenario Outline: Silent refresh returns the cached token without re-authentication
    Given acquire_token_silent returns {"access_token": "<cached_token>", "token_type": "Bearer"}
    When get_access_token is called
    Then acquire_token_for_client is NOT called
    And the returned value is "<cached_token>"

    Examples:
      | cached_token |
      | cached_tok   |

  Scenario Outline: Certificate mode initializes MSAL with private_key and thumbprint
    Given use_certificate_auth is True
    And client_cert_data containing "<pem_content>"
    And client_cert_thumbprint is "<thumbprint>"
    And acquire_token_for_client returns {"access_token": "<token>", "token_type": "Bearer"}
    When get_access_token is called
    Then ConfidentialClientApplication was initialized with client_credential containing "thumbprint" and "private_key" keys
    And the returned value is "<token>"

    Examples:
      | pem_content         | thumbprint       | token    |
      | -----BEGIN RSA...   | AABBCCDD112233   | cert_tok |

  Scenario Outline: MSAL error response raises AuthenticationError
    Given acquire_token_silent returns None
    And acquire_token_for_client returns {"error": "<error_code>", "error_description": "<error_desc>"}
    When get_access_token is called
    Then an AuthenticationError is raised
    And the exception message contains "<error_code>"

    Examples:
      | error_code     | error_desc  |
      | invalid_client | Bad secret. |

  Scenario Outline: MSAL result missing access_token key raises AuthenticationError
    Given acquire_token_for_client returns {"token_type": "Bearer"} with no "access_token" key
    When get_access_token is called
    Then an AuthenticationError is raised

    Examples:
      | missing_key    |
      | access_token   |
