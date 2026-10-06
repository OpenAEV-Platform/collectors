import unittest
from unittest.mock import MagicMock, sentinel

import microsoft_entra.configuration.collector_config_override as module


class TestCollectorConfigOverride(unittest.TestCase):
    def test_init_minimal(self):
        microsoft_entra_tenant_id = "my-microsoft_entra_tenant_id"
        microsoft_entra_client_id = "my-microsoft_entra_client_id"
        microsoft_entra_client_secret = "my-microsoft_entra_client_secret"

        config = module.CollectorConfigOverride(
            microsoft_entra_tenant_id=microsoft_entra_tenant_id,
            microsoft_entra_client_id=microsoft_entra_client_id,
            microsoft_entra_client_secret=microsoft_entra_client_secret,
        )

        self.assertEqual(config.id, "openaev_microsoft_entra")
        self.assertEqual(config.name, "Microsoft Entra")
        self.assertEqual(config.log_level, "error")
        self.assertEqual(config.period, module.timedelta(seconds=3600))
        self.assertEqual(
            config.icon_filepath, "microsoft_entra/img/icon-microsoft-entra.png"
        )
        self.assertIsNone(config.author)
        self.assertIsNone(config.platform_description)
        self.assertIsNone(config.platform_tags)
        self.assertEqual(config.microsoft_entra_tenant_id, microsoft_entra_tenant_id)
        self.assertEqual(config.microsoft_entra_client_id, microsoft_entra_client_id)
        self.assertFalse(config.microsoft_entra_use_certificate_auth)
        self.assertEqual(
            config.microsoft_entra_client_secret.get_secret_value(),
            microsoft_entra_client_secret,
        )
        self.assertIsNone(config.microsoft_entra_client_cert_data)
        self.assertIsNone(config.microsoft_entra_client_cert_thumbprint)
        self.assertIsNone(config.microsoft_entra_client_cert_passphrase)
        self.assertFalse(config.include_external)

    def test_init_full(self):
        config_id = "my-id"
        config_name = "my-name"
        config_log_level = "debug"
        config_icon_filepath = "my/file/path"
        config_author = "my-author"
        config_period = module.timedelta(seconds=1200)
        microsoft_entra_tenant_id = "my-microsoft_entra_tenant_id"
        microsoft_entra_client_id = "my-microsoft_entra_client_id"
        microsoft_entra_use_certificate_auth = True
        microsoft_entra_client_secret = "my-microsoft_entra_client_secret"
        microsoft_entra_client_cert_data = "my-cert_data"
        microsoft_entra_client_cert_thumbprint = (
            "634e2e0df68a53b88f2e6e1a44d2ed03fc586a6f"
        )
        microsoft_entra_client_cert_passphrase = "my-passphrase"
        config_include_external = True

        config = module.CollectorConfigOverride(
            id=config_id,
            name=config_name,
            log_level=config_log_level,
            icon_filepath=config_icon_filepath,
            author=config_author,
            period=config_period,
            microsoft_entra_tenant_id=microsoft_entra_tenant_id,
            microsoft_entra_client_id=microsoft_entra_client_id,
            microsoft_entra_use_certificate_auth=microsoft_entra_use_certificate_auth,
            microsoft_entra_client_secret=microsoft_entra_client_secret,
            microsoft_entra_client_cert_data=microsoft_entra_client_cert_data,
            microsoft_entra_client_cert_thumbprint=microsoft_entra_client_cert_thumbprint,
            microsoft_entra_client_cert_passphrase=microsoft_entra_client_cert_passphrase,
            include_external=config_include_external,
        )

        self.assertEqual(config.id, config_id)
        self.assertEqual(config.name, config_name)
        self.assertEqual(config.log_level, config_log_level)
        self.assertEqual(config.period, config_period)
        self.assertEqual(config.icon_filepath, config.icon_filepath)
        self.assertEqual(config.author, config_author)
        self.assertIsNone(config.platform_description)
        self.assertIsNone(config.platform_tags)
        self.assertEqual(config.microsoft_entra_tenant_id, microsoft_entra_tenant_id)
        self.assertEqual(config.microsoft_entra_client_id, microsoft_entra_client_id)
        self.assertTrue(config.microsoft_entra_use_certificate_auth)
        self.assertEqual(
            config.microsoft_entra_client_secret.get_secret_value(),
            microsoft_entra_client_secret,
        )
        self.assertEqual(
            config.microsoft_entra_client_cert_data.get_secret_value(),
            microsoft_entra_client_cert_data,
        )
        self.assertEqual(
            config.microsoft_entra_client_cert_thumbprint.get_secret_value(),
            microsoft_entra_client_cert_thumbprint.upper(),
        )
        self.assertEqual(
            config.microsoft_entra_client_cert_passphrase.get_secret_value(),
            microsoft_entra_client_cert_passphrase,
        )
        self.assertTrue(config.include_external)

    def test_normalize_client_cert_data_okay(self):
        input_data = "one\ntwo\nthree"

        output_data = module.CollectorConfigOverride._normalize_client_cert_data(
            input_data
        )

        self.assertEqual(output_data, input_data)

    def test_normalize_client_cert_data_replace(self):
        input_data = "one\\ntwo\\nthree"

        output_data = module.CollectorConfigOverride._normalize_client_cert_data(
            input_data
        )

        self.assertEqual(output_data, "one\ntwo\nthree")

    def test_normalize_client_cert_data_empty(self):
        input_data = "            "

        output_data = module.CollectorConfigOverride._normalize_client_cert_data(
            input_data
        )

        self.assertIsNone(output_data)

    def test_normalize_client_cert_data_none(self):
        input_data = None

        output_data = module.CollectorConfigOverride._normalize_client_cert_data(
            input_data
        )

        self.assertIsNone(output_data)

    def test_normalize_client_cert_thumbprint_okay(self):
        input_data = "634E2E0DF68A53B88F2E6E1A44D2ED03FC586A6F"

        output_data = module.CollectorConfigOverride._normalize_client_cert_thumbprint(
            input_data
        )

        self.assertEqual(output_data, input_data)

    def test_normalize_client_cert_thumbprint_lower(self):
        input_data = "634e2e0df68a53b88f2e6e1a44d2ed03fc586a6f"

        output_data = module.CollectorConfigOverride._normalize_client_cert_thumbprint(
            input_data
        )

        self.assertEqual(output_data, "634E2E0DF68A53B88F2E6E1A44D2ED03FC586A6F")

    def test_normalize_client_cert_thumbprint_replace(self):
        input_data = "634E:2E0d:F68A:53B8:8F2E:6E1A:44D2:ED03:FC58:6A6F"

        output_data = module.CollectorConfigOverride._normalize_client_cert_thumbprint(
            input_data
        )

        self.assertEqual(output_data, "634E2E0DF68A53B88F2E6E1A44D2ED03FC586A6F")

    def test_normalize_client_cert_thumbprint_empty(self):
        input_data = "            "

        output_data = module.CollectorConfigOverride._normalize_client_cert_thumbprint(
            input_data
        )

        self.assertIsNone(output_data)

    def test_normalize_client_cert_thumbprint_none(self):
        input_data = None

        output_data = module.CollectorConfigOverride._normalize_client_cert_thumbprint(
            input_data
        )

        self.assertIsNone(output_data)

    def test_validate_client_secret_requirement_passthrough(self):
        info = MagicMock()
        info.data = {"microsoft_entra_use_certificate_auth": True}
        input_data = sentinel.secret

        output_data = (
            module.CollectorConfigOverride._validate_client_secret_requirement(
                input_data, info
            )
        )

        self.assertEqual(output_data, sentinel.secret)

    def test_validate_client_secret_requirement_okay(self):
        info = MagicMock()
        info.data = {"microsoft_entra_use_certificate_auth": False}
        input_data = MagicMock()
        input_data.get_secret_value.return_value = "my-password"

        output_data = (
            module.CollectorConfigOverride._validate_client_secret_requirement(
                input_data, info
            )
        )

        self.assertEqual(output_data, input_data)

    def test_validate_client_secret_requirement_empty(self):
        info = MagicMock()
        info.data = {"microsoft_entra_use_certificate_auth": False}
        input_data = MagicMock()
        input_data.get_secret_value.return_value = "      "

        with self.assertRaises(ValueError):
            module.CollectorConfigOverride._validate_client_secret_requirement(
                input_data, info
            )

    def test_validate_client_secret_requirement_none(self):
        info = MagicMock()
        info.data = {"microsoft_entra_use_certificate_auth": False}
        input_data = None

        with self.assertRaises(ValueError):
            module.CollectorConfigOverride._validate_client_secret_requirement(
                input_data, info
            )

    def test_validate_certificate_requirements_no_cert_auth(self):
        microsoft_entra_tenant_id = "my-microsoft_entra_tenant_id"
        microsoft_entra_client_id = "my-microsoft_entra_client_id"
        microsoft_entra_client_secret = "my-microsoft_entra_client_secret"
        microsoft_entra_use_certificate_auth = False

        module.CollectorConfigOverride(
            microsoft_entra_tenant_id=microsoft_entra_tenant_id,
            microsoft_entra_client_id=microsoft_entra_client_id,
            microsoft_entra_client_secret=microsoft_entra_client_secret,
            microsoft_entra_use_certificate_auth=microsoft_entra_use_certificate_auth,
        )

    def test_validate_certificate_requirements_missing_cert_data(self):
        microsoft_entra_tenant_id = "my-microsoft_entra_tenant_id"
        microsoft_entra_client_id = "my-microsoft_entra_client_id"
        microsoft_entra_use_certificate_auth = True
        microsoft_entra_client_cert_data = None

        with self.assertRaises(ValueError):
            module.CollectorConfigOverride(
                microsoft_entra_tenant_id=microsoft_entra_tenant_id,
                microsoft_entra_client_id=microsoft_entra_client_id,
                microsoft_entra_use_certificate_auth=microsoft_entra_use_certificate_auth,
                microsoft_entra_client_cert_data=microsoft_entra_client_cert_data,
            )

    def test_validate_certificate_requirements_missing_cert_thumbprint(self):
        microsoft_entra_tenant_id = "my-microsoft_entra_tenant_id"
        microsoft_entra_client_id = "my-microsoft_entra_client_id"
        microsoft_entra_use_certificate_auth = True
        microsoft_entra_client_cert_data = "my-microsoft_entra_client_cert_data"
        microsoft_entra_client_cert_thumbprint = None

        with self.assertRaises(ValueError):
            module.CollectorConfigOverride(
                microsoft_entra_tenant_id=microsoft_entra_tenant_id,
                microsoft_entra_client_id=microsoft_entra_client_id,
                microsoft_entra_use_certificate_auth=microsoft_entra_use_certificate_auth,
                microsoft_entra_client_cert_data=microsoft_entra_client_cert_data,
                microsoft_entra_client_cert_thumbprint=microsoft_entra_client_cert_thumbprint,
            )

    def test_validate_certificate_requirements_invalid_cert_thumbprint(self):
        microsoft_entra_tenant_id = "my-microsoft_entra_tenant_id"
        microsoft_entra_client_id = "my-microsoft_entra_client_id"
        microsoft_entra_use_certificate_auth = True
        microsoft_entra_client_cert_data = "my-microsoft_entra_client_cert_data"
        microsoft_entra_client_cert_thumbprint = "f00bar"

        with self.assertRaises(ValueError):
            module.CollectorConfigOverride(
                microsoft_entra_tenant_id=microsoft_entra_tenant_id,
                microsoft_entra_client_id=microsoft_entra_client_id,
                microsoft_entra_use_certificate_auth=microsoft_entra_use_certificate_auth,
                microsoft_entra_client_cert_data=microsoft_entra_client_cert_data,
                microsoft_entra_client_cert_thumbprint=microsoft_entra_client_cert_thumbprint,
            )
