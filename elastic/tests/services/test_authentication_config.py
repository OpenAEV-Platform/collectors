"""Tests for the Elastic authentication settings and the inferred method."""

import base64
import tempfile
from pathlib import Path
from unittest.mock import Mock

import pytest
from pydantic import ValidationError
from src.models.configs.elastic_configs import (
    AuthenticationType,
    _ConfigLoaderElastic,
)
from src.services.client_api import ElasticClientAPI

CERT_PEM = "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n"
KEY_PEM = "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n"


def _b64(pem: str) -> str:
    """Encode a PEM file the way ELASTIC_CLIENT_CERT/ELASTIC_CLIENT_KEY expect it."""
    return base64.b64encode(pem.encode()).decode()


@pytest.fixture(autouse=True)
def isolated_auth_env(monkeypatch, tmp_path):
    """Drop credentials from the environment and write the PKI files in tmp_path.

    The settings are also read by field name, so a host ``USERNAME`` counts as
    a username. The client certificate and key are written to the temporary
    directory, redirected to tmp_path.
    """
    for name in (
        "AUTHENTICATION_TYPE",
        "API_KEY",
        "USERNAME",
        "PASSWORD",
        "CLIENT_CERT",
        "CLIENT_KEY",
    ):
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(f"ELASTIC_{name}", raising=False)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))


def test_client_certificate_alone_is_accepted():
    """A certificate and key are enough to configure the authentication."""
    config = _ConfigLoaderElastic(
        ELASTIC_CLIENT_CERT=_b64(CERT_PEM), ELASTIC_CLIENT_KEY=_b64(KEY_PEM)
    )

    assert config.authentication_type is None  # noqa: S101
    assert config.resolve_authentication_type() == AuthenticationType.PKI  # noqa: S101
    assert config.client_cert_pem == CERT_PEM  # noqa: S101
    assert config.client_key_pem == KEY_PEM  # noqa: S101


def test_configuration_writes_no_file(tmp_path):
    """Loading the configuration never writes the certificate or key to disk."""
    _ConfigLoaderElastic(
        ELASTIC_CLIENT_CERT=_b64(CERT_PEM), ELASTIC_CLIENT_KEY=_b64(KEY_PEM)
    )

    assert list(tmp_path.iterdir()) == []  # noqa: S101


def test_invalid_client_certificate_is_rejected_when_pki_is_used():
    """A client certificate that is not a base64 PEM fails the validation."""
    with pytest.raises(ValidationError, match="ELASTIC_CLIENT_CERT"):
        _ConfigLoaderElastic(
            ELASTIC_CLIENT_CERT="not base64!", ELASTIC_CLIENT_KEY=_b64(KEY_PEM)
        )


@pytest.mark.parametrize(
    "credentials",
    [
        pytest.param(
            {"ELASTIC_AUTHENTICATION_TYPE": "API_KEY", "ELASTIC_API_KEY": "key"},
            id="pinned_api_key",
        ),
        pytest.param({"ELASTIC_API_KEY": "key"}, id="inferred_api_key"),
        pytest.param(
            {"ELASTIC_USERNAME": "user", "ELASTIC_PASSWORD": "password"},
            id="inferred_user_password",
        ),
    ],
)
def test_stale_pki_settings_are_ignored_by_other_methods(credentials):
    """PKI settings are not checked when another method is in effect."""
    config = _ConfigLoaderElastic(
        ELASTIC_CLIENT_CERT="not base64!",
        ELASTIC_CLIENT_KEY="not base64!",
        **credentials,
    )

    assert config.resolve_authentication_type() != AuthenticationType.PKI  # noqa: S101


def test_missing_authentication_is_rejected():
    """Without any credentials the configuration is rejected."""
    with pytest.raises(
        ValidationError, match="ELASTIC_CLIENT_CERT and ELASTIC_CLIENT_KEY"
    ):
        _ConfigLoaderElastic()


def test_client_infers_pki_from_client_certificate(tmp_path):
    """With only a certificate and key, the session presents the certificate."""
    config = Mock()
    config.elastic = _ConfigLoaderElastic(
        ELASTIC_CLIENT_CERT=_b64(CERT_PEM), ELASTIC_CLIENT_KEY=_b64(KEY_PEM)
    )

    client = ElasticClientAPI(config=config)

    cert_path, key_path = client.session.cert
    assert tmp_path in Path(cert_path).parents  # noqa: S101
    assert Path(cert_path).read_text() == CERT_PEM  # noqa: S101
    assert Path(key_path).read_text() == KEY_PEM  # noqa: S101
    assert client.session.auth is None  # noqa: S101
    assert "Authorization" not in client.session.headers  # noqa: S101
    assert client.session.headers["Content-Type"] == "application/json"  # noqa: S101


@pytest.mark.parametrize(
    "key_pem",
    [
        pytest.param(
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIF\n"
            "-----END ENCRYPTED PRIVATE KEY-----\n",
            id="pkcs8",
        ),
        pytest.param(
            "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n"
            "DEK-Info: AES-256-CBC,0123456789ABCDEF0123456789ABCDEF\n\nMIIE\n"
            "-----END RSA PRIVATE KEY-----\n",
            id="traditional_openssl",
        ),
    ],
)
def test_encrypted_client_key_is_rejected(key_pem):
    """An encrypted private key fails the validation, whatever its format."""
    with pytest.raises(ValidationError, match="must be unencrypted"):
        _ConfigLoaderElastic(
            ELASTIC_CLIENT_CERT=_b64(CERT_PEM), ELASTIC_CLIENT_KEY=_b64(key_pem)
        )


def test_unencrypted_rsa_client_key_is_accepted():
    """A traditional, unencrypted RSA private key is accepted."""
    key_pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----\n"

    config = _ConfigLoaderElastic(
        ELASTIC_CLIENT_CERT=_b64(CERT_PEM), ELASTIC_CLIENT_KEY=_b64(key_pem)
    )

    assert config.client_key_pem == key_pem  # noqa: S101
