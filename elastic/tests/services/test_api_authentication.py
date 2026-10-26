"""Tests for the Elasticsearch API authentication providers."""

import os
import stat
import tempfile

import pytest
import requests
from src.services.api_authentication import (
    ApiKeyAuthentication,
    PKIAuthentication,
    UserPasswordAuthentication,
    _write_private_file,
)

CERT_PEM = "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n"
KEY_PEM = "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n"


@pytest.fixture
def pki_auth(monkeypatch, tmp_path):
    """Build a PKIAuthentication writing its files under tmp_path."""
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    auth = PKIAuthentication(CERT_PEM, KEY_PEM)
    yield auth
    auth.cleanup()


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

    def test_init_writes_certificate_and_key(self, pki_auth):
        """The certificate and key are written to files."""
        assert pki_auth._client_cert_path.read_text() == CERT_PEM
        assert pki_auth._client_key_path.read_text() == KEY_PEM

    def test_init_uses_a_private_temporary_directory(self, pki_auth, tmp_path):
        """The files live in a new temporary directory only the owner can access."""
        directory = pki_auth._client_cert_path.parent
        assert directory.parent == tmp_path
        assert directory.name.startswith("openaev-elastic-pki-")
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700

    def test_init_creates_files_readable_by_owner_only(self, pki_auth):
        """The certificate and key files are created with mode 0600."""
        for path in (pki_auth._client_cert_path, pki_auth._client_key_path):
            assert stat.S_IMODE(path.stat().st_mode) == 0o600

    def test_init_adds_a_missing_final_newline(self, monkeypatch, tmp_path):
        """A PEM content without a final newline is written with one."""
        monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
        auth = PKIAuthentication(CERT_PEM.rstrip("\n"), KEY_PEM.rstrip("\n"))
        assert auth._client_cert_path.read_text() == CERT_PEM
        assert auth._client_key_path.read_text() == KEY_PEM
        auth.cleanup()

    def test_each_instance_uses_its_own_directory(
        self, pki_auth, monkeypatch, tmp_path
    ):
        """Two providers never share, nor overwrite, the same files."""
        monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
        other = PKIAuthentication(CERT_PEM, KEY_PEM)
        assert other._client_cert_path.parent != pki_auth._client_cert_path.parent
        other.cleanup()

    def test_write_refuses_a_symlink(self, tmp_path):
        """An existing symlink at the target path is not followed."""
        target = tmp_path / "target"
        target.write_text("untouched")
        link = tmp_path / "client.key"
        os.symlink(target, link)

        with pytest.raises(FileExistsError):
            _write_private_file(link, KEY_PEM)
        assert target.read_text() == "untouched"

    def test_cleanup_removes_the_directory(self, pki_auth):
        """cleanup removes the temporary directory and its files."""
        directory = pki_auth._client_cert_path.parent

        pki_auth.cleanup()

        assert not directory.exists()

    def test_get_session_returns_requests_session(self, pki_auth):
        """get_session returns a requests.Session instance."""
        session = pki_auth.get_session()
        assert isinstance(session, requests.Session)

    def test_get_session_sets_cert_tuple(self, pki_auth):
        """get_session sets the cert attribute with both file paths."""
        session = pki_auth.get_session()
        assert session.cert == (
            str(pki_auth._client_cert_path),
            str(pki_auth._client_key_path),
        )
        assert session.auth is None
        assert "Authorization" not in session.headers

    def test_get_session_creates_new_session_each_call(self, pki_auth):
        """Each call to get_session returns a new session instance."""
        session1 = pki_auth.get_session()
        session2 = pki_auth.get_session()
        assert session1 is not session2
