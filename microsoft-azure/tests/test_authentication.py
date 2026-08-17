"""Tests for the Microsoft Azure collector authentication paths.

The collector historically authenticated with a client secret only. Certificate
authentication is opt-in, so most of these tests exist to prove that deployments
which do not enable it keep producing exactly the same MSAL calls as before.
"""

import binascii
import json
from unittest.mock import MagicMock, patch

import pytest
from tests.conftest import (
    CLIENT_ID,
    CLIENT_SECRET,
    PRIVATE_KEY_PEM,
    TENANT_ID,
    THUMBPRINT,
    build_collector,
    certificate_mode_values,
    secret_mode_values,
)

AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPES = ["https://management.azure.com/.default"]


@pytest.fixture
def msal_app():
    """Patch MSAL and return the patched class along with its application instance."""
    with patch("msal.ConfidentialClientApplication") as app_cls:
        app = app_cls.return_value
        app.acquire_token_silent.return_value = None
        app.acquire_token_for_client.return_value = {"access_token": "a-token"}
        yield app_cls, app


class TestClientSecretBackwardCompatibility:
    """Guard the default authentication mode against regressions."""

    def test_certificate_auth_is_disabled_by_default(self):
        """A configuration without any certificate key stays in secret mode."""
        values = secret_mode_values()
        del values["microsoft_azure_use_certificate_auth"]
        del values["microsoft_azure_client_cert_data"]
        del values["microsoft_azure_client_cert_thumbprint"]
        del values["microsoft_azure_client_cert_passphrase"]

        collector = build_collector(values)

        assert collector.use_certificate_auth is False
        assert collector._build_client_credential() == CLIENT_SECRET

    def test_credential_is_the_raw_client_secret(self, secret_collector):
        """The credential handed to MSAL is the plain secret string, not a mapping."""
        credential = secret_collector._build_client_credential()

        assert credential == CLIENT_SECRET
        assert isinstance(credential, str)

    def test_msal_is_called_exactly_as_before(self, secret_collector, msal_app):
        """The MSAL call signature is unchanged for client secret deployments."""
        app_cls, _ = msal_app

        assert secret_collector._get_access_token() is True

        app_cls.assert_called_once_with(
            CLIENT_ID,
            authority=AUTHORITY,
            client_credential=CLIENT_SECRET,
        )

    def test_token_flow_is_unchanged(self, secret_collector, msal_app):
        """The silent lookup still runs first and falls back to the client flow."""
        _, app = msal_app

        assert secret_collector._get_access_token() is True

        app.acquire_token_silent.assert_called_once_with(SCOPES, account=None)
        app.acquire_token_for_client.assert_called_once_with(scopes=SCOPES)
        assert secret_collector.access_token == "a-token"

    def test_cached_token_skips_the_client_flow(self, secret_collector, msal_app):
        """A cached token short-circuits the client credentials request."""
        _, app = msal_app
        app.acquire_token_silent.return_value = {"access_token": "cached"}

        assert secret_collector._get_access_token() is True

        app.acquire_token_for_client.assert_not_called()
        assert secret_collector.access_token == "cached"

    def test_enabling_certificate_auth_is_required_to_change_behaviour(self):
        """Certificate material alone never switches a deployment away from secrets."""
        collector = build_collector(
            secret_mode_values(
                microsoft_azure_client_cert_data=PRIVATE_KEY_PEM,
                microsoft_azure_client_cert_thumbprint=THUMBPRINT,
            )
        )

        assert collector._build_client_credential() == CLIENT_SECRET


class TestCertificateAuthentication:
    """Cover the opt-in certificate mode."""

    def test_credential_is_the_msal_certificate_mapping(self, certificate_collector):
        assert certificate_collector._build_client_credential() == {
            "private_key": PRIVATE_KEY_PEM,
            "thumbprint": THUMBPRINT,
        }

    def test_passphrase_is_forwarded_when_set(self):
        collector = build_collector(
            certificate_mode_values(
                microsoft_azure_client_cert_passphrase="unlock-me",
            )
        )

        assert collector._build_client_credential() == {
            "private_key": PRIVATE_KEY_PEM,
            "thumbprint": THUMBPRINT,
            "passphrase": "unlock-me",
        }

    def test_msal_receives_the_certificate_mapping(
        self, certificate_collector, msal_app
    ):
        app_cls, _ = msal_app

        assert certificate_collector._get_access_token() is True

        app_cls.assert_called_once_with(
            CLIENT_ID,
            authority=AUTHORITY,
            client_credential={
                "private_key": PRIVATE_KEY_PEM,
                "thumbprint": THUMBPRINT,
            },
        )

    def test_client_secret_is_never_sent_in_certificate_mode(self):
        collector = build_collector(
            certificate_mode_values(microsoft_azure_client_secret=CLIENT_SECRET)
        )

        credential = collector._build_client_credential()

        assert CLIENT_SECRET not in credential.values()

    @pytest.mark.parametrize(
        "missing",
        ["microsoft_azure_client_cert_data", "microsoft_azure_client_cert_thumbprint"],
    )
    def test_incomplete_certificate_material_is_reported(self, missing):
        collector = build_collector(certificate_mode_values(**{missing: None}))

        with pytest.raises(ValueError, match="Certificate authentication requires"):
            collector._build_client_credential()

    def test_incomplete_certificate_material_fails_the_token_acquisition(
        self, msal_app
    ):
        """The runtime guard surfaces as a failed authentication, not a crash."""
        app_cls, _ = msal_app
        collector = build_collector(
            certificate_mode_values(microsoft_azure_client_cert_data=None)
        )

        assert collector._get_access_token() is False

        app_cls.assert_not_called()
        collector.logger.error.assert_called_once()


class TestTokenAcquisitionFailures:
    """Failure handling is shared by both authentication modes."""

    def test_token_error_is_logged_and_reported(self, secret_collector, msal_app):
        _, app = msal_app
        app.acquire_token_for_client.return_value = {
            "error_description": "AADSTS700027: certificate is not valid",
        }

        assert secret_collector._get_access_token() is False

        assert secret_collector.access_token is None
        message = secret_collector.logger.error.call_args[0][0]
        assert "AADSTS700027" in message

    def test_unexpected_exception_is_swallowed(self, secret_collector, msal_app):
        app_cls, _ = msal_app
        app_cls.side_effect = RuntimeError("boom")

        assert secret_collector._get_access_token() is False

        message = secret_collector.logger.error.call_args[0][0]
        assert "boom" in message


class TestCredentialAcceptedByRealMsal:
    """Validate the credential shapes against the real MSAL implementation.

    No Entra ID credentials are needed and no network call is made: a stub HTTP
    client serves the OIDC discovery document, which lets MSAL reach the code that
    parses and validates ``client_credential``. That is exactly where a malformed
    certificate mapping fails.
    """

    @staticmethod
    def _rsa_private_key_pem():
        pytest.importorskip("cryptography")
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()

    @staticmethod
    def _offline_http_client():
        """Return an MSAL HTTP client stub serving a canned OIDC discovery document."""
        payload = {
            "authorization_endpoint": f"{AUTHORITY}/oauth2/v2.0/authorize",
            "token_endpoint": f"{AUTHORITY}/oauth2/v2.0/token",
            "issuer": f"{AUTHORITY}/v2.0",
        }

        response = MagicMock()
        response.status_code = 200
        response.text = json.dumps(payload)
        response.json.return_value = payload

        http_client = MagicMock()
        http_client.get.return_value = response
        http_client.post.return_value = response
        return http_client

    def _build_app(self, credential):
        import msal

        return msal.ConfidentialClientApplication(
            CLIENT_ID,
            authority=AUTHORITY,
            client_credential=credential,
            http_client=self._offline_http_client(),
        )

    def test_certificate_mapping_is_accepted(self):
        collector = build_collector(
            certificate_mode_values(
                microsoft_azure_client_cert_data=self._rsa_private_key_pem()
            )
        )

        assert self._build_app(collector._build_client_credential()) is not None

    def test_client_secret_is_accepted(self, secret_collector):
        assert self._build_app(secret_collector._build_client_credential()) is not None

    def test_a_thumbprint_with_separators_would_be_rejected_by_msal(self):
        """Justifies normalizing the thumbprint before handing it over to MSAL."""
        collector = build_collector(
            certificate_mode_values(
                microsoft_azure_client_cert_data=self._rsa_private_key_pem(),
                microsoft_azure_client_cert_thumbprint="a1:b2:c3",
            )
        )

        with pytest.raises(binascii.Error):
            self._build_app(collector._build_client_credential())


class TestCollectorWiring:
    """The constructor keeps exposing the settings the rest of the collector uses."""

    def test_endpoints_are_derived_from_the_configuration(self, secret_collector):
        assert secret_collector.authority == AUTHORITY
        assert secret_collector.resource == "https://management.azure.com"
        assert secret_collector.base_url.endswith(
            "/subscriptions/33333333-3333-3333-3333-333333333333"
        )
        assert secret_collector.access_token is None

    def test_resource_groups_are_split_and_trimmed(self):
        collector = build_collector(
            secret_mode_values(microsoft_azure_resource_groups=" rg-one , rg-two ,")
        )

        assert collector.resource_groups_list == ["rg-one", "rg-two"]

    def test_certificate_settings_are_read_from_the_configuration(
        self, certificate_collector
    ):
        assert certificate_collector.use_certificate_auth is True
        assert certificate_collector.client_cert_data == PRIVATE_KEY_PEM
        assert certificate_collector.client_cert_thumbprint == THUMBPRINT
        assert certificate_collector.client_cert_passphrase is None

    def test_truthy_configuration_values_enable_certificate_auth(self):
        """pyoaev coerces booleans to integers when flattening the configuration."""
        collector = build_collector(
            certificate_mode_values(microsoft_azure_use_certificate_auth=1)
        )

        assert collector.use_certificate_auth is True

    def test_missing_flag_defaults_to_secret_mode(self):
        collector = build_collector(
            secret_mode_values(microsoft_azure_use_certificate_auth=None)
        )

        assert collector.use_certificate_auth is False


def test_session_is_created_once(secret_collector):
    """The collector keeps its own requests session."""
    assert secret_collector.session is not None
    assert isinstance(secret_collector.logger, MagicMock)
