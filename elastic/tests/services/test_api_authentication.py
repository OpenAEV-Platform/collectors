"""Tests for the Elasticsearch API authentication providers."""

import pytest
import requests
from src.services.api_authentication import (
    ApiKeyAuthentication,
    PKIAuthentication,
    UserPasswordAuthentication,
)


@pytest.fixture
def pki_files(tmp_path):
    """Create temporary PKI certificate and key files."""
    pki_dir = tmp_path / "pki"
    pki_dir.mkdir()

    cert_file = pki_dir / "pki-client.crt"
    key_file = pki_dir / "pki-client.key"

    # Create dummy certificate and key files
    cert_file.write_text(
        "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"
    )
    key_file.write_text(
        "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----"
    )

    yield cert_file, key_file


class TestApiKeyAuthentication:
    """Tests for ApiKeyAuthentication."""

    def test_init_stores_api_key(self):
        """The API key is stored during initialization."""
        api_key = "my-api-key-123"
        auth = ApiKeyAuthentication(api_key)
        assert auth._api_key == api_key

    def test_get_session_returns_requests_session(self):
        """get_session returns a requests.Session instance."""
        auth = ApiKeyAuthentication("test-key")
        session = auth.get_session()
        assert isinstance(session, requests.Session)

    def test_get_session_sets_authorization_header(self):
        """get_session sets the Authorization header with ApiKey prefix."""
        api_key = "test-key-456"
        auth = ApiKeyAuthentication(api_key)
        session = auth.get_session()
        assert session.headers["Authorization"] == f"ApiKey {api_key}"

    def test_get_session_creates_new_session_each_call(self):
        """Each call to get_session returns a new session instance."""
        auth = ApiKeyAuthentication("test-key")
        session1 = auth.get_session()
        session2 = auth.get_session()
        assert session1 is not session2


class TestUserPasswordAuthentication:
    """Tests for UserPasswordAuthentication."""

    def test_init_stores_credentials(self):
        """Username and password are stored during initialization."""
        username = "testuser"
        password = "testpass"
        auth = UserPasswordAuthentication(username, password)
        assert auth._username == username
        assert auth._password == password

    def test_get_session_returns_requests_session(self):
        """get_session returns a requests.Session instance."""
        auth = UserPasswordAuthentication("user", "pass")
        session = auth.get_session()
        assert isinstance(session, requests.Session)

    def test_get_session_sets_basic_auth(self):
        """get_session sets the auth tuple with username and password."""
        username = "testuser"
        password = "testpass"
        auth = UserPasswordAuthentication(username, password)
        session = auth.get_session()
        assert session.auth == (username, password)

    def test_get_session_creates_new_session_each_call(self):
        """Each call to get_session returns a new session instance."""
        auth = UserPasswordAuthentication("user", "pass")
        session1 = auth.get_session()
        session2 = auth.get_session()
        assert session1 is not session2


class TestPKIAuthentication:
    """Tests for PKIAuthentication."""

    def test_init_with_custom_paths(self, pki_files):
        """Custom certificate paths are stored during initialization."""
        cert_path, key_path = pki_files
        auth = PKIAuthentication(cert_path, key_path)
        assert auth._client_cert_path == cert_path
        assert auth._client_key_path == key_path

    def test_init_with_default_paths(self, pki_files):
        """Default certificate paths are used when not provided."""
        cert_path, key_path = pki_files
        # Rename to default paths
        pki_dir = cert_path.parent
        default_cert = pki_dir / "pki-client.crt"
        default_key = pki_dir / "pki-client.key"
        cert_path.rename(default_cert)
        key_path.rename(default_key)

        auth = PKIAuthentication(default_cert, default_key)
        assert auth._client_cert_path == default_cert
        assert auth._client_key_path == default_key

    def test_init_raises_if_cert_file_not_found(self, pki_files):
        """FileNotFoundError is raised if the certificate file does not exist."""
        _, key_path = pki_files
        nonexistent_cert = key_path.parent / "nonexistent.crt"

        with pytest.raises(
            FileNotFoundError, match="Client certificate file not found"
        ):
            PKIAuthentication(nonexistent_cert, key_path)

    def test_init_raises_if_key_file_not_found(self, pki_files):
        """FileNotFoundError is raised if the key file does not exist."""
        cert_path, _ = pki_files
        nonexistent_key = cert_path.parent / "nonexistent.key"

        with pytest.raises(FileNotFoundError, match="Client key file not found"):
            PKIAuthentication(cert_path, nonexistent_key)

    def test_get_session_returns_requests_session(self, pki_files):
        """get_session returns a requests.Session instance."""
        cert_path, key_path = pki_files
        auth = PKIAuthentication(cert_path, key_path)
        session = auth.get_session()
        assert isinstance(session, requests.Session)

    def test_get_session_sets_cert_tuple(self, pki_files):
        """get_session sets the cert attribute with both certificate paths."""
        cert_path, key_path = pki_files
        auth = PKIAuthentication(cert_path, key_path)
        session = auth.get_session()
        assert session.cert == (cert_path, key_path)

    def test_get_session_creates_new_session_each_call(self, pki_files):
        """Each call to get_session returns a new session instance."""
        cert_path, key_path = pki_files
        auth = PKIAuthentication(cert_path, key_path)
        session1 = auth.get_session()
        session2 = auth.get_session()
        assert session1 is not session2
