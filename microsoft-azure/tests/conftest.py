"""Shared fixtures for the Microsoft Azure collector tests."""

from unittest.mock import MagicMock, patch

import pytest
from microsoft_azure import openaev_microsoft_azure
from microsoft_azure.openaev_microsoft_azure import OpenAEVMicrosoftAzure

TENANT_ID = "11111111-1111-1111-1111-111111111111"
CLIENT_ID = "22222222-2222-2222-2222-222222222222"
SUBSCRIPTION_ID = "33333333-3333-3333-3333-333333333333"
CLIENT_SECRET = "super-secret-value"
THUMBPRINT = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"
PRIVATE_KEY_PEM = (
    "-----BEGIN PRIVATE KEY-----\nZmFrZS1rZXktbWF0ZXJpYWw=\n-----END PRIVATE KEY-----\n"
)


def secret_mode_values(**overrides):
    """Build the configuration values of a legacy, client-secret deployment.

    This mirrors what a collector configured before certificate authentication
    existed produces, so the tests can prove those deployments keep behaving
    identically.

    Args:
        **overrides: Values overriding the defaults.

    Returns:
        The configuration mapping consumed by the collector.

    """
    values = {
        "microsoft_azure_tenant_id": TENANT_ID,
        "microsoft_azure_client_id": CLIENT_ID,
        "microsoft_azure_client_secret": CLIENT_SECRET,
        "microsoft_azure_use_certificate_auth": False,
        "microsoft_azure_client_cert_data": None,
        "microsoft_azure_client_cert_thumbprint": None,
        "microsoft_azure_client_cert_passphrase": None,
        "microsoft_azure_subscription_id": SUBSCRIPTION_ID,
        "microsoft_azure_resource_groups": "",
    }
    values.update(overrides)
    return values


def certificate_mode_values(**overrides):
    """Build the configuration values of a certificate based deployment.

    Args:
        **overrides: Values overriding the defaults.

    Returns:
        The configuration mapping consumed by the collector.

    """
    values = {
        "microsoft_azure_client_secret": None,
        "microsoft_azure_use_certificate_auth": True,
        "microsoft_azure_client_cert_data": PRIVATE_KEY_PEM,
        "microsoft_azure_client_cert_thumbprint": THUMBPRINT,
    }
    values.update(overrides)
    return secret_mode_values(**values)


def build_collector(values):
    """Instantiate the collector against a stubbed daemon base class.

    ``CollectorDaemon.__init__`` registers the collector on a live OpenAEV platform,
    which is not available in tests. Replacing it keeps the collector's own
    ``__init__`` body executing for real.

    Args:
        values: The configuration mapping backing ``Configuration.get``.

    Returns:
        The instantiated collector.

    """
    configuration = MagicMock()
    configuration.get.side_effect = values.get

    def fake_daemon_init(self, *args, **kwargs):
        self._configuration = configuration
        self.logger = MagicMock()

    with patch.object(
        openaev_microsoft_azure.CollectorDaemon, "__init__", fake_daemon_init
    ):
        return OpenAEVMicrosoftAzure(configuration=configuration)


@pytest.fixture
def secret_collector():
    """Return a collector configured with a client secret."""
    return build_collector(secret_mode_values())


@pytest.fixture
def certificate_collector():
    """Return a collector configured with a client certificate."""
    return build_collector(certificate_mode_values())
