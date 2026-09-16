"""Tests for the Microsoft Azure collector configuration model.

These tests focus on the guarantee that adding certificate authentication did not
tighten or loosen the requirements applying to existing client secret deployments.
"""

import pytest
from microsoft_azure.configuration.collector_config_override import (
    CollectorConfigOverride,
    normalize_pem,
    normalize_thumbprint,
)
from microsoft_azure.configuration.config_loader import _reveal
from pydantic import SecretStr, ValidationError
from tests.conftest import (
    CLIENT_ID,
    CLIENT_SECRET,
    SUBSCRIPTION_ID,
    TENANT_ID,
    THUMBPRINT,
)

PRIVATE_KEY_PEM = (
    "-----BEGIN PRIVATE KEY-----\nZmFrZS1rZXktbWF0ZXJpYWw=\n-----END PRIVATE KEY-----\n"
)


def base_config(**overrides):
    """Build the mandatory settings shared by every deployment."""
    values = {
        "id": "openaev_microsoft_azure",
        "name": "Microsoft Azure",
        "microsoft_azure_tenant_id": TENANT_ID,
        "microsoft_azure_client_id": CLIENT_ID,
        "microsoft_azure_subscription_id": SUBSCRIPTION_ID,
        "microsoft_azure_resource_groups": "",
    }
    values.update(overrides)
    return values


class TestClientSecretDeploymentsAreUnaffected:
    """A configuration written before this feature must keep validating."""

    def test_legacy_configuration_is_still_valid(self):
        config = CollectorConfigOverride(
            **base_config(microsoft_azure_client_secret=CLIENT_SECRET)
        )

        assert config.microsoft_azure_client_secret.get_secret_value() == CLIENT_SECRET
        assert config.microsoft_azure_use_certificate_auth is False
        assert config.microsoft_azure_client_cert_data is None
        assert config.microsoft_azure_client_cert_thumbprint is None
        assert config.microsoft_azure_client_cert_passphrase is None

    def test_client_secret_remains_mandatory(self):
        """Dropping the secret still fails, as it did when the field was required."""
        with pytest.raises(
            ValidationError, match="microsoft_azure_client_secret is required"
        ):
            CollectorConfigOverride(**base_config())

    @pytest.mark.parametrize("value", [None, ""])
    def test_blank_client_secret_is_rejected(self, value):
        with pytest.raises(
            ValidationError, match="microsoft_azure_client_secret is required"
        ):
            CollectorConfigOverride(**base_config(microsoft_azure_client_secret=value))

    def test_explicitly_disabling_certificate_auth_keeps_the_secret_mandatory(self):
        with pytest.raises(
            ValidationError, match="microsoft_azure_client_secret is required"
        ):
            CollectorConfigOverride(
                **base_config(microsoft_azure_use_certificate_auth=False)
            )


class TestCertificateConfiguration:
    def test_certificate_mode_does_not_require_a_client_secret(self):
        config = CollectorConfigOverride(
            **base_config(
                microsoft_azure_use_certificate_auth=True,
                microsoft_azure_client_cert_data=PRIVATE_KEY_PEM,
                microsoft_azure_client_cert_thumbprint=THUMBPRINT,
            )
        )

        assert config.microsoft_azure_client_secret is None
        assert config.microsoft_azure_use_certificate_auth is True

    @pytest.mark.parametrize(
        "missing",
        ["microsoft_azure_client_cert_data", "microsoft_azure_client_cert_thumbprint"],
    )
    def test_certificate_material_is_mandatory_in_certificate_mode(self, missing):
        values = {
            "microsoft_azure_use_certificate_auth": True,
            "microsoft_azure_client_cert_data": PRIVATE_KEY_PEM,
            "microsoft_azure_client_cert_thumbprint": THUMBPRINT,
        }
        values[missing] = None

        with pytest.raises(ValidationError, match=f"{missing} is required"):
            CollectorConfigOverride(**base_config(**values))

    def test_passphrase_is_optional(self):
        config = CollectorConfigOverride(
            **base_config(
                microsoft_azure_use_certificate_auth=True,
                microsoft_azure_client_cert_data=PRIVATE_KEY_PEM,
                microsoft_azure_client_cert_thumbprint=THUMBPRINT,
                microsoft_azure_client_cert_passphrase="unlock-me",
            )
        )

        assert (
            config.microsoft_azure_client_cert_passphrase.get_secret_value()
            == "unlock-me"
        )


class TestPemNormalization:
    def test_escaped_newlines_are_restored(self):
        escaped = (
            "-----BEGIN PRIVATE KEY-----\\nZmFrZS1rZXktbWF0ZXJpYWw=\\n"
            "-----END PRIVATE KEY-----"
        )

        assert normalize_pem(escaped) == PRIVATE_KEY_PEM

    def test_carriage_returns_are_normalized(self):
        escaped = (
            "-----BEGIN PRIVATE KEY-----\\r\\nZmFrZS1rZXktbWF0ZXJpYWw=\\r\\n"
            "-----END PRIVATE KEY-----"
        )

        assert normalize_pem(escaped) == PRIVATE_KEY_PEM

    def test_lone_escaped_carriage_return_is_normalized(self):
        escaped = (
            "-----BEGIN PRIVATE KEY-----\\rZmFrZS1rZXktbWF0ZXJpYWw=\\r"
            "-----END PRIVATE KEY-----"
        )

        assert normalize_pem(escaped) == PRIVATE_KEY_PEM

    def test_real_newlines_are_preserved(self):
        assert normalize_pem(PRIVATE_KEY_PEM) == PRIVATE_KEY_PEM

    def test_a_trailing_newline_is_always_present(self):
        assert normalize_pem("-----BEGIN PRIVATE KEY-----").endswith("\n")

    @pytest.mark.parametrize("value", [None, "", "   ", "\\n"])
    def test_blank_values_become_none(self, value):
        assert normalize_pem(value) is None

    def test_normalization_runs_through_the_model(self):
        escaped = (
            "-----BEGIN PRIVATE KEY-----\\nZmFrZS1rZXktbWF0ZXJpYWw=\\n"
            "-----END PRIVATE KEY-----"
        )
        config = CollectorConfigOverride(
            **base_config(
                microsoft_azure_use_certificate_auth=True,
                microsoft_azure_client_cert_data=escaped,
                microsoft_azure_client_cert_thumbprint=THUMBPRINT,
            )
        )

        assert (
            config.microsoft_azure_client_cert_data.get_secret_value()
            == PRIVATE_KEY_PEM
        )

    def test_secret_inputs_are_normalized_too(self):
        config = CollectorConfigOverride(
            **base_config(
                microsoft_azure_use_certificate_auth=True,
                microsoft_azure_client_cert_data=SecretStr(
                    "-----BEGIN PRIVATE KEY-----\\nZmFrZS1rZXktbWF0ZXJpYWw=\\n"
                    "-----END PRIVATE KEY-----"
                ),
                microsoft_azure_client_cert_thumbprint=SecretStr(THUMBPRINT),
            )
        )

        assert (
            config.microsoft_azure_client_cert_data.get_secret_value()
            == PRIVATE_KEY_PEM
        )
        assert (
            config.microsoft_azure_client_cert_thumbprint.get_secret_value()
            == THUMBPRINT
        )

    def test_empty_secret_inputs_become_none(self):
        with pytest.raises(
            ValidationError, match="microsoft_azure_client_cert_data is required"
        ):
            CollectorConfigOverride(
                **base_config(
                    microsoft_azure_use_certificate_auth=True,
                    microsoft_azure_client_cert_data=SecretStr("   "),
                    microsoft_azure_client_cert_thumbprint=THUMBPRINT,
                )
            )

    def test_non_string_values_are_left_to_pydantic(self):
        with pytest.raises(ValidationError):
            CollectorConfigOverride(
                **base_config(
                    microsoft_azure_use_certificate_auth=True,
                    microsoft_azure_client_cert_data=42,
                    microsoft_azure_client_cert_thumbprint=THUMBPRINT,
                )
            )


class TestThumbprintNormalization:
    """MSAL feeds the thumbprint to binascii.a2b_hex, which rejects separators."""

    @pytest.mark.parametrize(
        "value",
        [
            "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678",
            "a1:b2:c3:d4:e5:f6:07:18:29:3a:4b:5c:6d:7e:8f:90:12:34:56:78",
            "a1 b2 c3 d4 e5 f6 07 18 29 3a 4b 5c 6d 7e 8f 90 12 34 56 78",
            "a1-b2-c3-d4-e5-f6-07-18-29-3a-4b-5c-6d-7e-8f-90-12-34-56-78",
            f"  {THUMBPRINT}  ",
        ],
    )
    def test_common_renderings_are_accepted(self, value):
        assert normalize_thumbprint(value) == THUMBPRINT

    @pytest.mark.parametrize("value", [None, "", "   ", ": :"])
    def test_blank_values_become_none(self, value):
        assert normalize_thumbprint(value) is None

    def test_non_hexadecimal_values_are_rejected(self):
        with pytest.raises(ValueError, match="must be a hexadecimal SHA-1"):
            normalize_thumbprint("not-a-thumbprint!")

    def test_sha256_thumbprints_are_rejected_with_an_explicit_message(self):
        with pytest.raises(ValueError, match="do not support"):
            normalize_thumbprint("ab" * 32)

    def test_truncated_thumbprints_are_rejected(self):
        with pytest.raises(ValueError, match="40 character SHA-1"):
            normalize_thumbprint("abcdef")

    def test_normalization_runs_through_the_model(self):
        config = CollectorConfigOverride(
            **base_config(
                microsoft_azure_use_certificate_auth=True,
                microsoft_azure_client_cert_data=PRIVATE_KEY_PEM,
                microsoft_azure_client_cert_thumbprint=THUMBPRINT.upper(),
            )
        )

        assert (
            config.microsoft_azure_client_cert_thumbprint.get_secret_value()
            == THUMBPRINT
        )

    def test_invalid_thumbprints_surface_as_validation_errors(self):
        with pytest.raises(ValidationError, match="must be a hexadecimal SHA-1"):
            CollectorConfigOverride(
                **base_config(
                    microsoft_azure_use_certificate_auth=True,
                    microsoft_azure_client_cert_data=PRIVATE_KEY_PEM,
                    microsoft_azure_client_cert_thumbprint="zzzz",
                )
            )

    def test_non_string_values_are_left_to_pydantic(self):
        with pytest.raises(ValidationError):
            CollectorConfigOverride(
                **base_config(
                    microsoft_azure_use_certificate_auth=True,
                    microsoft_azure_client_cert_data=PRIVATE_KEY_PEM,
                    microsoft_azure_client_cert_thumbprint=1234,
                )
            )


class TestSecretReveal:
    def test_none_stays_none(self):
        assert _reveal(None) is None

    def test_secret_is_unwrapped(self):
        assert _reveal(SecretStr("value")) == "value"
