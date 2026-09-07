"""End-to-end tests of the configuration chain, from environment to collector.

These exercise the exact path a deployment goes through: environment variables ->
``ConfigLoader`` -> flattened ``Configuration`` -> collector attributes. The client
secret scenario doubles as a regression guard: a deployment that never sets any
certificate variable must produce the same values as before certificate support
existed.
"""

import os

import pytest
from microsoft_azure.configuration.config_loader import ConfigLoader
from tests.conftest import (
    CLIENT_ID,
    CLIENT_SECRET,
    PRIVATE_KEY_PEM,
    SUBSCRIPTION_ID,
    TENANT_ID,
    THUMBPRINT,
    build_collector,
)

LEGACY_ENVIRONMENT = {
    "OPENAEV_URL": "http://localhost:3001",
    "OPENAEV_TOKEN": "00000000-0000-0000-0000-00000000000f",
    "COLLECTOR_ID": "openaev_microsoft_azure",
    "COLLECTOR_MICROSOFT_AZURE_TENANT_ID": TENANT_ID,
    "COLLECTOR_MICROSOFT_AZURE_CLIENT_ID": CLIENT_ID,
    "COLLECTOR_MICROSOFT_AZURE_CLIENT_SECRET": CLIENT_SECRET,
    "COLLECTOR_MICROSOFT_AZURE_SUBSCRIPTION_ID": SUBSCRIPTION_ID,
    "COLLECTOR_MICROSOFT_AZURE_RESOURCE_GROUPS": "",
}


@pytest.fixture
def clean_environment(monkeypatch):
    """Isolate the process environment so only the variables under test are visible."""
    monkeypatch.setattr(os, "environ", {})
    return os.environ


def load_configuration(environment):
    """Build the flattened daemon configuration from an environment mapping."""
    os.environ.update(environment)
    return ConfigLoader().to_daemon_config()


class TestLegacyDeployment:
    """A deployment predating certificate support must be unaffected."""

    def test_configuration_loads_without_any_certificate_variable(
        self, clean_environment
    ):
        configuration = load_configuration(LEGACY_ENVIRONMENT)

        assert configuration.get("microsoft_azure_client_secret") == CLIENT_SECRET
        assert configuration.get("microsoft_azure_tenant_id") == TENANT_ID
        assert configuration.get("microsoft_azure_client_id") == CLIENT_ID

    def test_certificate_settings_default_to_disabled_and_empty(
        self, clean_environment
    ):
        configuration = load_configuration(LEGACY_ENVIRONMENT)

        assert not configuration.get("microsoft_azure_use_certificate_auth")
        assert configuration.get("microsoft_azure_client_cert_data") is None
        assert configuration.get("microsoft_azure_client_cert_thumbprint") is None
        assert configuration.get("microsoft_azure_client_cert_passphrase") is None

    def test_collector_still_authenticates_with_the_client_secret(
        self, clean_environment
    ):
        configuration = load_configuration(LEGACY_ENVIRONMENT)
        values = {
            key: configuration.get(key)
            for key in [
                "microsoft_azure_tenant_id",
                "microsoft_azure_client_id",
                "microsoft_azure_client_secret",
                "microsoft_azure_use_certificate_auth",
                "microsoft_azure_client_cert_data",
                "microsoft_azure_client_cert_thumbprint",
                "microsoft_azure_client_cert_passphrase",
                "microsoft_azure_subscription_id",
                "microsoft_azure_resource_groups",
            ]
        }

        collector = build_collector(values)

        assert collector.use_certificate_auth is False
        assert collector._build_client_credential() == CLIENT_SECRET

    def test_an_empty_certificate_flag_is_treated_as_disabled(self, clean_environment):
        """Docker compose renders unset optional variables as empty strings."""
        configuration = load_configuration(
            {
                **LEGACY_ENVIRONMENT,
                "COLLECTOR_MICROSOFT_AZURE_CLIENT_CERT_DATA": "",
                "COLLECTOR_MICROSOFT_AZURE_CLIENT_CERT_THUMBPRINT": "",
                "COLLECTOR_MICROSOFT_AZURE_CLIENT_CERT_PASSPHRASE": "",
            }
        )

        assert not configuration.get("microsoft_azure_use_certificate_auth")
        assert configuration.get("microsoft_azure_client_secret") == CLIENT_SECRET


class TestCertificateDeployment:
    def test_escaped_pem_survives_the_whole_chain(self, clean_environment):
        escaped = (
            "-----BEGIN PRIVATE KEY-----\\nZmFrZS1rZXktbWF0ZXJpYWw=\\n"
            "-----END PRIVATE KEY-----"
        )
        environment = {
            **LEGACY_ENVIRONMENT,
            "COLLECTOR_MICROSOFT_AZURE_USE_CERTIFICATE_AUTH": "true",
            "COLLECTOR_MICROSOFT_AZURE_CLIENT_CERT_DATA": escaped,
            "COLLECTOR_MICROSOFT_AZURE_CLIENT_CERT_THUMBPRINT": THUMBPRINT.upper(),
        }
        environment.pop("COLLECTOR_MICROSOFT_AZURE_CLIENT_SECRET")

        configuration = load_configuration(environment)

        assert configuration.get("microsoft_azure_use_certificate_auth")
        assert configuration.get("microsoft_azure_client_cert_data") == PRIVATE_KEY_PEM
        assert configuration.get("microsoft_azure_client_cert_thumbprint") == THUMBPRINT
        assert configuration.get("microsoft_azure_client_secret") is None

    def test_collector_builds_the_certificate_credential(self, clean_environment):
        environment = {
            **LEGACY_ENVIRONMENT,
            "COLLECTOR_MICROSOFT_AZURE_USE_CERTIFICATE_AUTH": "true",
            "COLLECTOR_MICROSOFT_AZURE_CLIENT_CERT_DATA": PRIVATE_KEY_PEM,
            "COLLECTOR_MICROSOFT_AZURE_CLIENT_CERT_THUMBPRINT": THUMBPRINT,
        }
        environment.pop("COLLECTOR_MICROSOFT_AZURE_CLIENT_SECRET")
        configuration = load_configuration(environment)
        values = {
            key: configuration.get(key)
            for key in [
                "microsoft_azure_tenant_id",
                "microsoft_azure_client_id",
                "microsoft_azure_client_secret",
                "microsoft_azure_use_certificate_auth",
                "microsoft_azure_client_cert_data",
                "microsoft_azure_client_cert_thumbprint",
                "microsoft_azure_client_cert_passphrase",
                "microsoft_azure_subscription_id",
                "microsoft_azure_resource_groups",
            ]
        }

        collector = build_collector(values)

        assert collector._build_client_credential() == {
            "private_key": PRIVATE_KEY_PEM,
            "thumbprint": THUMBPRINT,
        }

    def test_missing_certificate_material_is_rejected_at_load_time(
        self, clean_environment
    ):
        environment = {
            **LEGACY_ENVIRONMENT,
            "COLLECTOR_MICROSOFT_AZURE_USE_CERTIFICATE_AUTH": "true",
        }
        environment.pop("COLLECTOR_MICROSOFT_AZURE_CLIENT_SECRET")

        with pytest.raises(Exception, match="microsoft_azure_client_cert_data"):
            load_configuration(environment)

    def test_missing_client_secret_is_rejected_at_load_time(self, clean_environment):
        environment = dict(LEGACY_ENVIRONMENT)
        environment.pop("COLLECTOR_MICROSOFT_AZURE_CLIENT_SECRET")

        with pytest.raises(Exception, match="microsoft_azure_client_secret"):
            load_configuration(environment)
