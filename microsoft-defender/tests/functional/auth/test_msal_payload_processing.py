import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import orjson
import src.auth.ms_graph_auth_client as module

access_payload_path = Path("./tests/functional/auth/access_token.json")
error_payload_path = Path("./tests/functional/auth/error_invalid_client.json")


@patch.object(module, "ConfidentialClientApplication")
@patch.object(module, "AZURE_PUBLIC")
@patch.object(module, "AuthorityBuilder")
class TestMSALPayloadProcessing(unittest.TestCase):
    def test_msg_graph_auth_client_get_access_token(
        self, m_authority_builder, m_azure_public, m_confidential_client_application
    ):
        config = MagicMock()
        config.use_certificate_auth = False
        auth_client = module.MSGraphAuthClient(config)

        access_payload = orjson.loads(access_payload_path.read_bytes())
        m_confidential_client_application.return_value.acquire_token_for_client.return_value = (
            access_payload
        )
        access_token = auth_client.get_access_token()

        self.assertIsInstance(access_token, str)

        error_payload = orjson.loads(error_payload_path.read_bytes())
        m_confidential_client_application.return_value.acquire_token_for_client.return_value = (
            error_payload
        )
        with self.assertRaises(module.AuthenticationError) as ctx:
            auth_client.get_access_token()

        self.assertIn("invalid_client", str(ctx.exception))
