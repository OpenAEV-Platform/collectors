from unittest import TestCase
from unittest.mock import patch

from mitre_attack.configuration.config_loader import ConfigLoader
from pydantic import ValidationError

BASE_ENVIRONMENT = {
    "OPENAEV_URL": "http://localhost:8080",
    "OPENAEV_TOKEN": "super-token",
    "COLLECTOR_ID": "collector-42",
}


class OpenAEVMitreConfigurationTest(TestCase):

    @patch.dict("os.environ", BASE_ENVIRONMENT, clear=True)
    def test_batch_size_defaults_to_100(self):
        config = ConfigLoader().to_daemon_config()

        self.assertEqual(100, config.get("collector_batch_size"))
        self.assertEqual(7 * 24 * 3600, config.get("collector_period"))

    @patch.dict(
        "os.environ", {**BASE_ENVIRONMENT, "COLLECTOR_BATCH_SIZE": "250"}, clear=True
    )
    def test_batch_size_is_read_from_the_environment(self):
        config = ConfigLoader().to_daemon_config()

        self.assertEqual(250, config.get("collector_batch_size"))

    @patch.dict(
        "os.environ", {**BASE_ENVIRONMENT, "COLLECTOR_BATCH_SIZE": "0"}, clear=True
    )
    def test_batch_size_must_be_at_least_1(self):
        with self.assertRaises(ValidationError):
            ConfigLoader()
