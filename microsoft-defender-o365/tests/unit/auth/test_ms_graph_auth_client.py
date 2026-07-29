import unittest
from unittest.mock import MagicMock, patch, sentinel

import src.auth.ms_graph_auth_client as module


@patch.object(module, "ConfidentialClientApplication")
@patch.object(module, "AZURE_PUBLIC")
@patch.object(module, "AuthorityBuilder")
class TestMSGraphAuthClient(unittest.TestCase):
    def test_ms_graph_auth_client_init_cert_case(
        self,
        m_authority_builder,
        m_azure_public,
        m_confidential_client_application,
    ):
        config = MagicMock()
        config.tenant_id = sentinel.tenant_id
        config.use_certificate_auth = True
        config.client_id = sentinel.client_id
        config.client_cert_data = sentinel.client_cert_data
        config.client_cert_thumbprint = sentinel.client_cert_thumbprint

        auth_client = module.MSGraphAuthClient(config)

        m_authority_builder.assert_called_with(m_azure_public, sentinel.tenant_id)
        m_confidential_client_application.assert_called_with(
            sentinel.client_id,
            authority=m_authority_builder.return_value,
            client_credential={
                "private_key": sentinel.client_cert_data,
                "thumbprint": sentinel.client_cert_thumbprint,
            },
        )
        self.assertEqual(
            auth_client.app, m_confidential_client_application.return_value
        )

    def test_ms_graph_auth_client_init_secret_case(
        self, m_authority_builder, m_azure_public, m_confidential_client_application
    ):
        config = MagicMock()
        config.tenant_id = sentinel.tenant_id
        config.use_certificate_auth = False
        config.client_id = sentinel.client_id
        config.client_secret = sentinel.client_secret

        auth_client = module.MSGraphAuthClient(config)

        m_authority_builder.assert_called_with(m_azure_public, sentinel.tenant_id)
        m_confidential_client_application.assert_called_with(
            sentinel.client_id,
            authority=m_authority_builder.return_value,
            client_credential=sentinel.client_secret,
        )
        self.assertEqual(
            auth_client.app, m_confidential_client_application.return_value
        )

    def test_msg_graph_auth_client_get_access_token(
        self, m_authority_builder, m_azure_public, m_confidential_client_application
    ):
        config = MagicMock()
        config.use_certificate_auth = False
        m_confidential_client_application.return_value.acquire_token_for_client.return_value = {
            "access_token": sentinel.access_token,
        }

        auth_client = module.MSGraphAuthClient(config)

        access_token = auth_client.get_access_token()

        m_confidential_client_application.return_value.acquire_token_for_client.assert_called_with(
            scopes=["https://graph.microsoft.com/.default"],
            force_refresh=False,
        )
        self.assertEqual(access_token, sentinel.access_token)

    def test_msg_graph_auth_client_get_access_token_error(
        self, m_authority_builder, m_azure_public, m_confidential_client_application
    ):
        config = MagicMock()
        config.use_certificate_auth = False
        m_confidential_client_application.return_value.acquire_token_for_client.return_value = {
            "error": "invalid_client",
            "error_description": "Full description leaking elements",
        }

        auth_client = module.MSGraphAuthClient(config)

        with self.assertRaises(module.AuthenticationError) as ctx:
            auth_client.get_access_token()

        self.assertIn("invalid_client", str(ctx.exception))
        m_confidential_client_application.return_value.acquire_token_for_client.assert_called_with(
            scopes=["https://graph.microsoft.com/.default"],
            force_refresh=False,
        )
