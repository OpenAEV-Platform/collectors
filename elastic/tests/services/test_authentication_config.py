"""Tests for the Elastic authentication settings and the inferred method."""

import base64
from unittest.mock import Mock

import pytest
from pydantic import ValidationError
from src.models.configs.elastic_configs import (
    DEFAULT_CLIENT_CERT_PATH,
    DEFAULT_CLIENT_KEY_PATH,
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
    a username. The client certificate and key are written relative to the
    working directory.
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


def test_client_certificate_alone_is_accepted():
    """A certificate and key are enough to configure the authentication."""
    config = _ConfigLoaderElastic(
        ELASTIC_CLIENT_CERT=_b64(CERT_PEM), ELASTIC_CLIENT_KEY=_b64(KEY_PEM)
    )

    assert config.authentication_type is None  # noqa: S101
    assert DEFAULT_CLIENT_CERT_PATH.read_text() == CERT_PEM  # noqa: S101
    assert DEFAULT_CLIENT_KEY_PATH.read_text() == KEY_PEM  # noqa: S101


def test_missing_authentication_is_rejected():
    """Without any credentials the configuration is rejected."""
    with pytest.raises(
        ValidationError, match="ELASTIC_CLIENT_CERT and ELASTIC_CLIENT_KEY"
    ):
        _ConfigLoaderElastic()


def test_client_infers_pki_from_client_certificate():
    """With only a certificate and key, the session presents the certificate."""
    config = Mock()
    config.elastic = _ConfigLoaderElastic(
        ELASTIC_CLIENT_CERT=_b64(CERT_PEM), ELASTIC_CLIENT_KEY=_b64(KEY_PEM)
    )

    client = ElasticClientAPI(config=config)

    assert client.session.cert == (  # noqa: S101
        DEFAULT_CLIENT_CERT_PATH,
        DEFAULT_CLIENT_KEY_PATH,
    )
    assert client.session.auth is None  # noqa: S101
    assert "Authorization" not in client.session.headers  # noqa: S101
    assert client.session.headers["Content-Type"] == "application/json"  # noqa: S101
