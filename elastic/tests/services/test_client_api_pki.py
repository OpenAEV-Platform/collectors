"""Tests for Elasticsearch PKI (client certificate) authentication."""

import pytest
from pydantic import SecretStr, ValidationError
from src.models.configs.config_loader import ConfigLoader
from src.models.configs.elastic_configs import (
    ElasticAuthType,
    _ConfigLoaderElastic,
)
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


class TestAuthTypeConfig:
    """Explicit selection of the authentication method."""

    @pytest.mark.parametrize("raw", ["PKI", "pki", " Pki "])
    def test_auth_type_is_case_insensitive(self, pki_files, raw):
        """The auth type accepts any casing and surrounding whitespace."""
        cert, _, _ = pki_files
        settings = _elastic_settings(auth_type=raw, client_cert=cert)
        assert settings.auth_type is ElasticAuthType.PKI  # noqa: S101

    def test_invalid_auth_type_raises(self):
        """An unknown auth type is rejected."""
        with pytest.raises(ValidationError):
            _elastic_settings(auth_type="OAUTH", api_key=SecretStr("key"))

    @pytest.mark.parametrize(
        ("auth_type", "missing"),
        [
            ("API_KEY", "ELASTIC_API_KEY"),
            ("PASSWORD", "ELASTIC_USERNAME"),
            ("PKI", "ELASTIC_CLIENT_CERT"),
        ],
    )
    def test_auth_type_requires_its_credentials(self, pki_files, auth_type, missing):
        """Each auth type fails when its own credentials are missing."""
        cert, _, _ = pki_files
        credentials = {
            "api_key": SecretStr("key"),
            "username": "user",
            "password": SecretStr("pass"),
            "client_cert": cert,
        }
        credentials.pop(
            {"API_KEY": "api_key", "PASSWORD": "username", "PKI": "client_cert"}[
                auth_type
            ]
        )
        with pytest.raises(ValidationError, match=missing):
            _elastic_settings(auth_type=auth_type, **credentials)

    @pytest.mark.parametrize(
        ("credentials", "expected"),
        [
            ({"api_key": SecretStr("key")}, ElasticAuthType.API_KEY),
            (
                {"username": "user", "password": SecretStr("pass")},
                ElasticAuthType.PASSWORD,
            ),
        ],
    )
    def test_auth_type_inferred_when_unset(self, credentials, expected):
        """Without an explicit auth type, it is inferred from the credentials."""
        settings = _elastic_settings(**credentials)
        assert settings.resolved_auth_type() is expected  # noqa: S101

    def test_auth_type_inferred_as_pki(self, pki_files):
        """A client certificate alone is inferred as PKI."""
        cert, _, _ = pki_files
        settings = _elastic_settings(client_cert=cert)
        assert settings.resolved_auth_type() is ElasticAuthType.PKI  # noqa: S101


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

    def test_explicit_pki_ignores_other_credentials(self, pki_files):
        """With AUTH_TYPE=PKI, configured API key and password are not sent."""
        cert, key, _ = pki_files
        config = _pki_config(cert, key)
        config.elastic.auth_type = ElasticAuthType.PKI
        config.elastic.api_key = SecretStr("my-api-key")
        config.elastic.username = "user"
        config.elastic.password = SecretStr("pass")

        client = ElasticClientAPI(config=config)

        assert "Authorization" not in client.session.headers  # noqa: S101
        assert client.session.auth is None  # noqa: S101
        assert client.session.cert == (str(cert), str(key))  # noqa: S101

    def test_explicit_password_ignores_api_key(self):
        """With AUTH_TYPE=PASSWORD, basic auth is used even if an API key is set."""
        config = create_test_config()
        config.elastic.auth_type = ElasticAuthType.PASSWORD
        config.elastic.api_key = SecretStr("my-api-key")

        client = ElasticClientAPI(config=config)

        assert client.session.auth == ("test-user", "test-password")  # noqa: S101
        assert "Authorization" not in client.session.headers  # noqa: S101

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
        monkeypatch.setenv("ELASTIC_AUTH_TYPE", "pki")
        monkeypatch.setenv("ELASTIC_CLIENT_CERT", str(cert))
        monkeypatch.setenv("ELASTIC_CLIENT_KEY", str(key))
        monkeypatch.setenv("ELASTIC_CA_CERT", str(ca))

        client = ElasticClientAPI(config=ConfigLoader())

        assert client.session.cert == (str(cert), str(key))  # noqa: S101
        assert client.session.verify == str(ca)  # noqa: S101
        assert client.session.auth is None  # noqa: S101
        assert client.auth_type is ElasticAuthType.PKI  # noqa: S101
        assert (  # noqa: S101
            ConfigLoader().to_daemon_config().get("elastic_auth_type") == "PKI"
        )
