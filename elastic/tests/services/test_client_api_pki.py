"""Tests for Elasticsearch PKI (client certificate) authentication."""

import pytest
from pydantic import SecretStr, ValidationError
from src.models.configs.config_loader import ConfigLoader
from src.models.configs.elastic_configs import _ConfigLoaderElastic
from src.services.client_api import ElasticClientAPI
from tests.services.fixtures.factories import create_test_config

BASE_URL = "https://test-elastic.example.com:9200"


@pytest.fixture
def pki_files(tmp_path):
    """Provide dummy PEM files for the client certificate, key and CA.

    Args:
        tmp_path: Pytest temporary directory fixture.

    Returns:
        Tuple of (cert, key, ca) paths.

    """
    paths = []
    for name in ("client.crt", "client.key", "ca.crt"):
        path = tmp_path / name
        path.write_text("dummy")
        paths.append(path)
    return tuple(paths)


def _elastic_settings(**overrides) -> _ConfigLoaderElastic:
    """Build Elastic settings with all auth fields explicitly unset by default.

    Args:
        **overrides: Settings values to override.

    Returns:
        _ConfigLoaderElastic instance.

    """
    values = {
        "base_url": BASE_URL,
        "api_key": None,
        "username": None,
        "password": None,
        "client_cert": None,
        "client_key": None,
        "ca_cert": None,
    }
    values.update(overrides)
    return _ConfigLoaderElastic(**values)


def _pki_config(cert, key=None, ca=None):
    """Create a test config that authenticates only with a client certificate.

    Args:
        cert: Client certificate path.
        key: Optional private key path.
        ca: Optional CA bundle path.

    Returns:
        ConfigLoader instance configured for PKI authentication.

    """
    config = create_test_config()
    config.elastic.username = None
    config.elastic.password = None
    config.elastic.client_cert = cert
    config.elastic.client_key = key
    config.elastic.ca_cert = ca
    return config


class TestPKIConfigValidation:
    """Validation rules for the PKI settings."""

    def test_client_cert_alone_is_valid_auth(self, pki_files):
        """A client certificate without secrets satisfies the auth requirement."""
        cert, _, _ = pki_files
        settings = _elastic_settings(client_cert=cert)
        assert settings.client_cert == cert  # noqa: S101

    def test_no_auth_raises(self):
        """Missing every authentication method is rejected."""
        with pytest.raises(ValidationError, match="ELASTIC_CLIENT_CERT"):
            _elastic_settings()

    def test_missing_cert_file_raises(self, tmp_path):
        """A client certificate path that does not exist is rejected."""
        with pytest.raises(ValidationError):
            _elastic_settings(client_cert=tmp_path / "missing.crt")

    def test_key_without_cert_raises(self, pki_files):
        """A private key without its certificate is rejected."""
        _, key, _ = pki_files
        with pytest.raises(ValidationError, match="requires ELASTIC_CLIENT_CERT"):
            _elastic_settings(client_key=key, api_key=SecretStr("key"))

    def test_cert_requires_https(self, pki_files):
        """PKI authentication over plain HTTP is rejected."""
        cert, _, _ = pki_files
        with pytest.raises(ValidationError, match="https://"):
            _elastic_settings(base_url="http://elastic:9200", client_cert=cert)


class TestPKISession:
    """Session configuration for PKI authentication."""

    def test_session_with_cert_and_key(self, pki_files):
        """The certificate/key pair is presented and no credentials are sent."""
        cert, key, _ = pki_files

        client = ElasticClientAPI(config=_pki_config(cert, key))

        assert client.session.cert == (str(cert), str(key))  # noqa: S101
        assert client.session.auth is None  # noqa: S101
        assert "Authorization" not in client.session.headers  # noqa: S101

    def test_session_with_combined_pem(self, pki_files):
        """A certificate file bundling its key is passed as a single path."""
        cert, _, _ = pki_files

        client = ElasticClientAPI(config=_pki_config(cert))

        assert client.session.cert == str(cert)  # noqa: S101

    def test_session_uses_ca_bundle(self, pki_files):
        """A configured CA bundle is used to verify the server certificate."""
        cert, key, ca = pki_files

        client = ElasticClientAPI(config=_pki_config(cert, key, ca))

        assert client.session.verify == str(ca)  # noqa: S101

    def test_ca_bundle_ignored_when_verify_disabled(self, pki_files):
        """Disabling TLS verification takes precedence over the CA bundle."""
        cert, key, ca = pki_files
        config = _pki_config(cert, key, ca)
        config.elastic.verify_ssl = False

        client = ElasticClientAPI(config=config)

        assert client.session.verify is False  # noqa: S101

    def test_api_key_takes_precedence_over_cert(self, pki_files):
        """With an API key set, it authenticates and the cert is still presented."""
        cert, key, _ = pki_files
        config = _pki_config(cert, key)
        config.elastic.api_key = SecretStr("my-api-key")

        client = ElasticClientAPI(config=config)

        assert (  # noqa: S101
            client.session.headers["Authorization"] == "ApiKey my-api-key"
        )
        assert client.session.cert == (str(cert), str(key))  # noqa: S101

    def test_to_daemon_config_exposes_paths(self, pki_files):
        """The PKI paths are flattened as strings for the daemon config."""
        cert, key, ca = pki_files
        config = _pki_config(cert, key, ca)

        daemon_config = config.to_daemon_config()

        assert daemon_config.get("elastic_client_cert") == str(cert)  # noqa: S101
        assert daemon_config.get("elastic_client_key") == str(key)  # noqa: S101
        assert daemon_config.get("elastic_ca_cert") == str(ca)  # noqa: S101

    def test_config_loaded_from_environment(self, pki_files, monkeypatch):
        """PKI settings are read from the ELASTIC_* environment variables."""
        cert, key, ca = pki_files
        for var in ("ELASTIC_API_KEY", "ELASTIC_USERNAME", "ELASTIC_PASSWORD"):
            monkeypatch.delenv(var, raising=False)
        monkeypatch.setenv("OPENAEV_URL", "https://test-openaev.example.com")
        monkeypatch.setenv("OPENAEV_TOKEN", "test-token")
        monkeypatch.setenv("ELASTIC_BASE_URL", BASE_URL)
        monkeypatch.setenv("ELASTIC_CLIENT_CERT", str(cert))
        monkeypatch.setenv("ELASTIC_CLIENT_KEY", str(key))
        monkeypatch.setenv("ELASTIC_CA_CERT", str(ca))

        client = ElasticClientAPI(config=ConfigLoader())

        assert client.session.cert == (str(cert), str(key))  # noqa: S101
        assert client.session.verify == str(ca)  # noqa: S101
        assert client.session.auth is None  # noqa: S101
