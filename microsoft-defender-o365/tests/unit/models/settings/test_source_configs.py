import unittest
from unittest.mock import MagicMock, sentinel

import src.models.settings.source_configs as module


class TestConfigLoaderSource(unittest.TestCase):
    def test_init_minimal(self):
        tenant_id = "my-tenant_id"
        client_id = "my-client_id"
        client_secret = "my-client_secret"

        config = module._ConfigLoaderSource(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
        )

        self.assertEqual(config.tenant_id, tenant_id)
        self.assertEqual(config.client_id, client_id)
        self.assertFalse(config.use_certificate_auth)
        self.assertEqual(config.client_secret.get_secret_value(), client_secret)
        self.assertIsNone(config.client_cert_data)
        self.assertIsNone(config.client_cert_thumbprint)
        self.assertIsNone(config.client_cert_passphrase)
        self.assertEqual(str(config.base_url), "https://graph.microsoft.com/v1.0")
        self.assertEqual(config.filter_service_source, "microsoftDefenderForOffice365")
        self.assertEqual(config.rate_limit_requests_per_minute, 150)
        self.assertEqual(config.max_fetch_retries, 5)

    def init_full(self):
        tenant_id = "my-tenant_id"
        client_id = "my-client_id"
        use_certificate_auth = True
        client_secret = "my-client_secret"
        client_cert_data = "my-cert_data"
        client_cert_thumbprint = "634e2e0df68a53b88f2e6e1a44d2ed03fc586a6f"
        client_cert_passphrase = "my-passphrase"
        base_url = "http://my.url"
        filter_service_source = "myFilter"
        rate_limit_request_per_minute = 42
        max_fetch_retries = 13

        config = module._ConfigLoaderSource(
            tenant_id=tenant_id,
            client_id=client_id,
            use_certificate_auth=use_certificate_auth,
            client_secret=client_secret,
            client_cert_data=client_cert_data,
            client_cert_thumbprint=client_cert_thumbprint,
            client_cert_passphrase=client_cert_passphrase,
            base_url=base_url,
            filter_service_source=filter_service_source,
            rate_limit_request_per_minute=rate_limit_request_per_minute,
            max_fetch_retries=max_fetch_retries,
        )

        self.assertEqual(config.tenant_id, tenant_id)
        self.assertEqual(config.client_id, client_id)
        self.assertTrue(config.use_certificate_auth)
        self.assertEqual(config.client_secret.get_secret_value(), client_secret)
        self.assertEqual(config.client_cert_data.get_secret_value(), client_cert_data)
        self.assertEqual(
            config.client_cert_thumbprint.get_secret_value(),
            client_cert_thumbprint.upper(),
        )
        self.assertEqual(
            config.client_cert_passphrase.get_secret_value(),
            client_cert_passphrase,
        )
        self.assertEqual(str(config.base_url), base_url)
        self.assertEqual(config.filter_service_source, filter_service_source)
        self.assertEqual(config.max_fetch_retries, max_fetch_retries)

    def test_normalize_client_cert_data_okay(self):
        input_data = "one\ntwo\nthree"

        output_data = module._ConfigLoaderSource._normalize_client_cert_data(input_data)

        self.assertEqual(output_data, input_data)

    def test_normalize_client_cert_data_replace(self):
        input_data = "one\\ntwo\\nthree"

        output_data = module._ConfigLoaderSource._normalize_client_cert_data(input_data)

        self.assertEqual(output_data, "one\ntwo\nthree")

    def test_normalize_client_cert_data_empty(self):
        input_data = "            "

        output_data = module._ConfigLoaderSource._normalize_client_cert_data(input_data)

        self.assertIsNone(output_data)

    def test_normalize_client_cert_data_none(self):
        input_data = None

        output_data = module._ConfigLoaderSource._normalize_client_cert_data(input_data)

        self.assertIsNone(output_data)

    def test_normalize_client_cert_thumbprint_okay(self):
        input_data = "634E2E0DF68A53B88F2E6E1A44D2ED03FC586A6F"

        output_data = module._ConfigLoaderSource._normalize_client_cert_thumbprint(
            input_data
        )

        self.assertEqual(output_data, input_data)

    def test_normalize_client_cert_thumbprint_lower(self):
        input_data = "634e2e0df68a53b88f2e6e1a44d2ed03fc586a6f"

        output_data = module._ConfigLoaderSource._normalize_client_cert_thumbprint(
            input_data
        )

        self.assertEqual(output_data, "634E2E0DF68A53B88F2E6E1A44D2ED03FC586A6F")

    def test_normalize_client_cert_thumbprint_replace(self):
        input_data = "634E:2E0d:F68A:53B8:8F2E:6E1A:44D2:ED03:FC58:6A6F"

        output_data = module._ConfigLoaderSource._normalize_client_cert_thumbprint(
            input_data
        )

        self.assertEqual(output_data, "634E2E0DF68A53B88F2E6E1A44D2ED03FC586A6F")

    def test_normalize_client_cert_thumbprint_empty(self):
        input_data = "            "

        output_data = module._ConfigLoaderSource._normalize_client_cert_thumbprint(
            input_data
        )

        self.assertIsNone(output_data)

    def test_normalize_client_cert_thumbprint_none(self):
        input_data = None

        output_data = module._ConfigLoaderSource._normalize_client_cert_thumbprint(
            input_data
        )

        self.assertIsNone(output_data)

    def test_validate_client_secret_passthrough(self):
        info = MagicMock()
        info.data = {"use_certificate_auth": True}
        input_data = sentinel.secret

        output_data = module._ConfigLoaderSource._validate_client_secret(
            input_data, info
        )

        self.assertEqual(output_data, sentinel.secret)

    def test_validate_client_secret_okay(self):
        info = MagicMock()
        info.data = {"use_certificate_auth": False}
        input_data = MagicMock()
        input_data.get_secret_value.return_value = "my-password"

        output_data = module._ConfigLoaderSource._validate_client_secret(
            input_data, info
        )

        self.assertEqual(output_data, input_data)

    def test_validate_client_secret_empty(self):
        info = MagicMock()
        info.data = {"use_certificate_auth": False}
        input_data = MagicMock()
        input_data.get_secret_value.return_value = "      "

        with self.assertRaises(ValueError):
            module._ConfigLoaderSource._validate_client_secret(input_data, info)

    def test_validate_client_secret_none(self):
        info = MagicMock()
        info.data = {"use_certificate_auth": False}
        input_data = None

        with self.assertRaises(ValueError):
            module._ConfigLoaderSource._validate_client_secret(input_data, info)

    def test_validate_certificate_requirements_no_cert_auth(self):
        tenant_id = "my-tenant_id"
        client_id = "my-client_id"
        client_secret = "my-client_secret"
        use_certificate_auth = False

        module._ConfigLoaderSource(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
            use_certificate_auth=use_certificate_auth,
        )

    def test_validate_certificate_requirements_missing_cert_data(self):
        tenant_id = "my-tenant_id"
        client_id = "my-client_id"
        use_certificate_auth = True
        client_cert_data = None

        with self.assertRaises(ValueError):
            module._ConfigLoaderSource(
                tenant_id=tenant_id,
                client_id=client_id,
                use_certificate_auth=use_certificate_auth,
                client_cert_data=client_cert_data,
            )

    def test_validate_certificate_requirements_missing_cert_thumbprint(self):
        tenant_id = "my-tenant_id"
        client_id = "my-client_id"
        use_certificate_auth = True
        client_cert_data = "my-client_cert_data"
        client_cert_thumbprint = None

        with self.assertRaises(ValueError):
            module._ConfigLoaderSource(
                tenant_id=tenant_id,
                client_id=client_id,
                use_certificate_auth=use_certificate_auth,
                client_cert_data=client_cert_data,
                client_cert_thumbprint=client_cert_thumbprint,
            )

    def test_validate_certificate_requirements_invalid_cert_thumbprint(self):
        tenant_id = "my-tenant_id"
        client_id = "my-client_id"
        use_certificate_auth = True
        client_cert_data = "my-client_cert_data"
        client_cert_thumbprint = "f00bar"

        with self.assertRaises(ValueError):
            module._ConfigLoaderSource(
                tenant_id=tenant_id,
                client_id=client_id,
                use_certificate_auth=use_certificate_auth,
                client_cert_data=client_cert_data,
                client_cert_thumbprint=client_cert_thumbprint,
            )
