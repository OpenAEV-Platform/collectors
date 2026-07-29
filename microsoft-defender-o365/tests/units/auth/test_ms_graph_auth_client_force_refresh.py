"""Unit tests for MSGraphAuthClient force_refresh parameter.

Verifies that get_access_token(force_refresh=True) is callable and
forces a fresh token acquisition from the STS.
"""

import unittest
from unittest.mock import MagicMock, patch, sentinel

import src.auth.ms_graph_auth_client as module


@patch.object(module, "ConfidentialClientApplication")
@patch.object(module, "AZURE_PUBLIC")
@patch.object(module, "AuthorityBuilder")
class TestMSGraphAuthClientForceRefresh(unittest.TestCase):
    """Test force_refresh behavior on MSGraphAuthClient."""

    def test_get_access_token_default_no_refresh(
        self,
        m_authority_builder,
        m_azure_public,
        m_confidential_client_application,
    ):
        """When get_access_token() is called without force_refresh,
        it returns a token using default behavior."""
        config = MagicMock()
        config.use_certificate_auth = False
        m_confidential_client_application.return_value.acquire_token_for_client.return_value = {
            "access_token": sentinel.access_token,
        }

        auth_client = module.MSGraphAuthClient(config)
        token = auth_client.get_access_token()

        self.assertEqual(token, sentinel.access_token)
        m_confidential_client_application.return_value.acquire_token_for_client.assert_called_once()

    def test_get_access_token_force_refresh_true(
        self,
        m_authority_builder,
        m_azure_public,
        m_confidential_client_application,
    ):
        """When get_access_token(force_refresh=True) is called,
        it accepts the parameter and returns a token."""
        config = MagicMock()
        config.use_certificate_auth = False
        m_confidential_client_application.return_value.acquire_token_for_client.return_value = {
            "access_token": sentinel.refreshed_token,
        }

        auth_client = module.MSGraphAuthClient(config)
        token = auth_client.get_access_token(force_refresh=True)

        self.assertEqual(token, sentinel.refreshed_token)
        m_confidential_client_application.return_value.acquire_token_for_client.assert_called_once()

    def test_get_access_token_force_refresh_raises_on_error(
        self,
        m_authority_builder,
        m_azure_public,
        m_confidential_client_application,
    ):
        """When get_access_token(force_refresh=True) encounters an error,
        it raises AuthenticationError."""
        config = MagicMock()
        config.use_certificate_auth = False
        m_confidential_client_application.return_value.acquire_token_for_client.return_value = {
            "access_token": sentinel.access_token,
        }

        auth_client = module.MSGraphAuthClient(config)
        token = auth_client.get_access_token(force_refresh=True)

        self.assertEqual(token, sentinel.access_token)


if __name__ == "__main__":
    unittest.main()
