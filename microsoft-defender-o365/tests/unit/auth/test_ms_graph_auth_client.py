import unittest
from unittest.mock import MagicMock, patch, sentinel

import src.auth.ms_graph_auth_client as module


@patch.object(module, "ConfidentialClientApplication")
@patch.object(module, "AZURE_PUBLIC")
@patch.object(module, "AuthorityBuilder")
class TestMSGraphAuthClient(unittest.TestCase):
    @patch.object(module, "Path")
    def test_ms_graph_auth_client_init_cert_case(self, m_path, m_authority_builder, m_azure_public, m_confidential_client_application):
        config = MagicMock()
        config.tenant_id = sentinel.tenant_id
        config.use_certificate_auth = True
        config.client_id = sentinel.client_id
        config.client_cert_path = sentinel.client_cert_path
        config.client_cert_thumbprint = sentinel.client_cert_thumbprint

        m_path.return_value.exists.return_value = True
        m_path.return_value.read_text.return_value = sentinel.cert_text

        auth_client = module.MSGraphAuthClient(config)

        m_authority_builder.assert_called_with(m_azure_public, sentinel.tenant_id)
        m_confidential_client_application.assert_called_with(
            sentinel.client_id,
            authority=m_authority_builder.return_value,
            client_credential={
                "private_key": sentinel.cert_text,
                "thumbprint": sentinel.client_cert_thumbprint,
            }
        )
        self.assertEqual(auth_client.app, m_confidential_client_application.return_value)

    @patch.object(module, "Path")
    def test_ms_grapj_auth_client_init_cert_case_not_exist(self, m_path, m_authority_builder, m_azure_public, m_confidential_client_application):
        config = MagicMock()
        config.tenant_id = sentinel.tenant_id
        config.use_certificate_auth = True
        config.client_id = sentinel.client_id
        config.client_cert_path = sentinel.client_cert_path
        config.client_cert_thumbprint = sentinel.client_cert_thumbprint

        m_path.return_value.exists.return_value = False

        with self.assertRaises(module.AuthenticationError) as ctx:
            module.MSGraphAuthClient(config)
        
        self.assertIn("Certificate file does not exist at path", str(ctx.exception))

    def test_ms_graph_auth_client_init_secret_case(self, m_authority_builder, m_azure_public, m_confidential_client_application):
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
        self.assertEqual(auth_client.app, m_confidential_client_application.return_value)

    def test_msg_graph_auth_client_get_access_token(self, m_authority_builder, m_azure_public, m_confidential_client_application):
        config = MagicMock()
        config.use_certificate_auth = False
        m_confidential_client_application.return_value.acquire_token_for_client.return_value = {
            "access_token": sentinel.access_token,
        }

        auth_client = module.MSGraphAuthClient(config)

        access_token = auth_client.get_access_token()

        m_confidential_client_application.return_value.acquire_token_for_client.assert_called_with(
            scopes=["https://graph.microsoft.com/.default"],
        )
        self.assertEqual(access_token, sentinel.access_token)

    def test_msg_graph_auth_client_get_access_token_error(self, m_authority_builder, m_azure_public, m_confidential_client_application):
        config = MagicMock()
        config.use_certificate_auth = False
        m_confidential_client_application.return_value.acquire_token_for_client.return_value = {
            "error": "invalid_client",
            "error_description": "Full description leaking elements"
        }

        auth_client = module.MSGraphAuthClient(config)

        with self.assertRaises(module.AuthenticationError) as ctx:
            auth_client.get_access_token()

        self.assertIn("invalid_client", str(ctx.exception))
        m_confidential_client_application.return_value.acquire_token_for_client.assert_called_with(
            scopes=["https://graph.microsoft.com/.default"],
        )
