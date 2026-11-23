import os
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

from pydantic import ValidationError
from tests.fixtures.crowdstrike_alerts_v2 import (
    GET_ALERTS_V2_SUCCESS_RESPONSE,
    QUERY_ALERTS_V2_SUCCESS_RESPONSE,
)
from tests.fixtures.defaults import get_default_logger

from crowdstrike.configuration.config_loader import ConfigLoader
from crowdstrike.configuration.crowdstrike_settings import CrowdstrikeSettings
from crowdstrike.crowdstrike_api_handler import CrowdstrikeApiHandler
from crowdstrike.crowdstrike_credentials import CrowdstrikeCredentials

UNAUTHORIZED_RESPONSE = {
    "status_code": 401,
    "body": {"errors": [{"code": 401, "message": "access denied"}], "resources": []},
}


class CredentialFilesTestCase(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.id_file = Path(directory.name) / "client_id"
        self.secret_file = Path(directory.name) / "client_secret"
        self.write("first_id", "first_secret")

    def write(self, client_id: str, client_secret: str):
        self.id_file.write_text(client_id + "\n", encoding="utf-8")
        self.secret_file.write_text(client_secret + "\n", encoding="utf-8")

    def file_credentials(self) -> CrowdstrikeCredentials:
        return CrowdstrikeCredentials(
            client_id_file=self.id_file, client_secret_file=self.secret_file
        )


class TestCrowdstrikeCredentials(CredentialFilesTestCase):
    def test_values_are_returned_as_given(self):
        credentials = CrowdstrikeCredentials(
            client_id="an_id", client_secret="a_secret"
        )

        self.assertEqual(("an_id", "a_secret"), credentials.read())

    def test_files_are_read_without_surrounding_whitespace(self):
        self.assertEqual(("first_id", "first_secret"), self.file_credentials().read())

    def test_files_are_read_again_on_each_call(self):
        credentials = self.file_credentials()
        credentials.read()
        self.write("second_id", "second_secret")

        self.assertEqual(("second_id", "second_secret"), credentials.read())

    def test_empty_file_is_refused(self):
        self.secret_file.write_text("\n", encoding="utf-8")

        with self.assertRaises(ValueError):
            self.file_credentials().read()

    def test_missing_file_is_refused(self):
        self.secret_file.unlink()

        with self.assertRaises(OSError):
            self.file_credentials().read()


@patch("crowdstrike.crowdstrike_api_handler.CsAlerts")
class TestCrowdstrikeApiHandlerRotation(CredentialFilesTestCase):
    def handler(self) -> CrowdstrikeApiHandler:
        return CrowdstrikeApiHandler(
            logger=get_default_logger(),
            credentials=self.file_credentials(),
            base_url="http://fake_crowdstrike_api_base_url",
        )

    @staticmethod
    def logged_in_as(mock_alerts) -> list[tuple[str, str]]:
        return [
            (call.kwargs["client_id"], call.kwargs["client_secret"])
            for call in mock_alerts.call_args_list
        ]

    def test_unchanged_credentials_keep_the_client(self, mock_alerts):
        mock_alerts.return_value.query_alerts_v2.return_value = (
            QUERY_ALERTS_V2_SUCCESS_RESPONSE
        )
        mock_alerts.return_value.get_alerts_v2.return_value = (
            GET_ALERTS_V2_SUCCESS_RESPONSE
        )
        handler = self.handler()

        handler.get_alerts_v2(datetime.now())
        handler.get_alerts_v2(datetime.now())

        self.assertEqual([("first_id", "first_secret")], self.logged_in_as(mock_alerts))

    def test_rotated_credentials_are_used_on_the_next_run(self, mock_alerts):
        mock_alerts.return_value.query_alerts_v2.return_value = (
            QUERY_ALERTS_V2_SUCCESS_RESPONSE
        )
        mock_alerts.return_value.get_alerts_v2.return_value = (
            GET_ALERTS_V2_SUCCESS_RESPONSE
        )
        handler = self.handler()
        self.write("second_id", "second_secret")

        handler.get_alerts_v2(datetime.now())

        self.assertEqual(
            [("first_id", "first_secret"), ("second_id", "second_secret")],
            self.logged_in_as(mock_alerts),
        )

    def test_unauthorized_query_is_retried_with_rotated_credentials(self, mock_alerts):
        old_client, new_client = MagicMock(), MagicMock()
        old_client.query_alerts_v2.return_value = UNAUTHORIZED_RESPONSE
        new_client.query_alerts_v2.return_value = QUERY_ALERTS_V2_SUCCESS_RESPONSE
        new_client.get_alerts_v2.return_value = GET_ALERTS_V2_SUCCESS_RESPONSE
        mock_alerts.side_effect = [old_client, new_client]
        handler = self.handler()
        # Rotated after the check at the start of the run
        rotated = iter([("first_id", "first_secret"), ("second_id", "second_secret")])
        handler.credentials = MagicMock(read=lambda: next(rotated))

        alerts = handler.get_alerts_v2(datetime.now())

        self.assertEqual(GET_ALERTS_V2_SUCCESS_RESPONSE["body"]["resources"], alerts)
        self.assertEqual(
            [("first_id", "first_secret"), ("second_id", "second_secret")],
            self.logged_in_as(mock_alerts),
        )
        new_client.query_alerts_v2.assert_called_once()

    def test_unauthorized_query_with_the_same_credentials_is_not_retried(
        self, mock_alerts
    ):
        mock_alerts.return_value.query_alerts_v2.return_value = UNAUTHORIZED_RESPONSE
        handler = self.handler()

        self.assertEqual([], handler.get_alerts_v2(datetime.now()))
        mock_alerts.return_value.query_alerts_v2.assert_called_once()

    def test_unreadable_file_keeps_the_current_credentials(self, mock_alerts):
        mock_alerts.return_value.query_alerts_v2.return_value = (
            QUERY_ALERTS_V2_SUCCESS_RESPONSE
        )
        mock_alerts.return_value.get_alerts_v2.return_value = (
            GET_ALERTS_V2_SUCCESS_RESPONSE
        )
        handler = self.handler()
        self.secret_file.unlink()

        alerts = handler.get_alerts_v2(datetime.now())

        self.assertEqual(GET_ALERTS_V2_SUCCESS_RESPONSE["body"]["resources"], alerts)
        self.assertEqual([("first_id", "first_secret")], self.logged_in_as(mock_alerts))


class TestCrowdstrikeSettings(unittest.TestCase):
    def test_values_are_accepted(self):
        settings = CrowdstrikeSettings(client_id="an_id", client_secret="a_secret")

        self.assertEqual("a_secret", settings.client_secret.get_secret_value())

    def test_files_are_accepted(self):
        settings = CrowdstrikeSettings(
            client_id_file="/run/secrets/id", client_secret_file="/run/secrets/secret"
        )

        self.assertEqual(Path("/run/secrets/secret"), settings.client_secret_file)

    def test_value_and_file_can_be_mixed(self):
        settings = CrowdstrikeSettings(
            client_id="an_id", client_secret_file="/run/secrets/secret"
        )

        self.assertIsNone(settings.client_secret)

    def test_missing_credential_is_refused(self):
        with self.assertRaisesRegex(ValidationError, "client_secret_file is required"):
            CrowdstrikeSettings(client_id="an_id")

    def test_value_and_file_for_the_same_credential_are_refused(self):
        with self.assertRaisesRegex(ValidationError, "not both"):
            CrowdstrikeSettings(
                client_id="an_id",
                client_secret="a_secret",
                client_secret_file="/run/secrets/secret",
            )

    def test_config_schema_requires_the_values_and_hides_the_files(self):
        schema = CrowdstrikeSettings.model_json_schema()

        self.assertEqual(["client_id", "client_secret"], schema["required"])
        self.assertNotIn("client_id_file", schema["properties"])
        self.assertNotIn("client_secret_file", schema["properties"])

    def test_empty_values_count_as_unset(self):
        settings = CrowdstrikeSettings(
            client_id="",
            client_secret="",
            client_id_file="/run/secrets/id",
            client_secret_file="/run/secrets/secret",
        )

        self.assertIsNone(settings.client_id)


class TestConfigLoader(unittest.TestCase):
    ENVIRONMENT = {
        "OPENAEV_URL": "http://fake_openaev_base_url",
        "OPENAEV_TOKEN": "openaev_uuid_token",
        "COLLECTOR_ID": "collector_uuid_identifier",
        "COLLECTOR_NAME": "CrowdStrike Endpoint Security",
    }

    def test_credential_files_are_read_from_the_environment(self):
        environment = self.ENVIRONMENT | {
            "CROWDSTRIKE_CLIENT_ID_FILE": "/run/secrets/id",
            "CROWDSTRIKE_CLIENT_SECRET_FILE": "/run/secrets/secret",
            "CROWDSTRIKE_CLIENT_SECRET": "",
        }
        with patch.dict(os.environ, environment, clear=True):
            configuration = ConfigLoader().to_daemon_config()

        self.assertEqual(
            "/run/secrets/id", configuration.get("crowdstrike_client_id_file")
        )
        self.assertEqual(
            "/run/secrets/secret", configuration.get("crowdstrike_client_secret_file")
        )
        self.assertIsNone(configuration.get("crowdstrike_client_secret"))

    def test_credential_values_are_read_from_the_environment(self):
        environment = self.ENVIRONMENT | {
            "CROWDSTRIKE_CLIENT_ID": "an_id",
            "CROWDSTRIKE_CLIENT_SECRET": "a_secret",
        }
        with patch.dict(os.environ, environment, clear=True):
            configuration = ConfigLoader().to_daemon_config()

        self.assertEqual("an_id", configuration.get("crowdstrike_client_id"))
        self.assertEqual("a_secret", configuration.get("crowdstrike_client_secret"))
        self.assertIsNone(configuration.get("crowdstrike_client_secret_file"))
