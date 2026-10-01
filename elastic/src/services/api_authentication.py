from typing import Protocol
from pathlib import Path

import requests

class AuthenticationProvider(Protocol):
    """Provides an HTTP session carrying the credentials for Elasticsearch.

    Implementations only attach their credentials; common headers and TLS
    verification are applied by :class:`ElasticClientAPI`.
    """

    def get_session(self) -> requests.Session:
        """Return a new session authenticated with this provider's credentials."""
        ...


class ApiKeyAuthentication:
    """Authenticate with an ``Authorization: ApiKey <key>`` header."""

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

    def get_session(self) -> requests.Session:
        """Return a session sending the API key in the Authorization header."""
        session = requests.Session()
        session.headers["Authorization"] = f"ApiKey {self._api_key}"
        return session


class UserPasswordAuthentication:
    """Authenticate with HTTP basic authentication."""

    def __init__(self, username: str, password: str) -> None:
        self._username = username
        self._password = password

    def get_session(self) -> requests.Session:
        """Return a session using HTTP basic authentication."""
        session = requests.Session()
        session.auth = (self._username, self._password)
        return session

class PKIAuthentication:
    """Authenticate with an X.509 client certificate (Elasticsearch PKI realm).

    The certificate is presented during the TLS handshake and no Authorization
    header is sent: Elasticsearch maps the certificate subject to roles through
    its PKI realm.

    ELASTIC_CLIENT_CERT / ELASTIC_CLIENT_KEY should have been written to disk by the configuration manager before the collector starts. The default paths are ``pki/pki-client.crt`` and ``pki/pki-client.key``.
    """

    def __init__(self, client_cert_path: Path = Path("pki/pki-client.crt"), client_key_path: Path = Path("pki/pki-client.key")) -> None:
        # check that the files exist and are readable; requests will raise a less clear error if they don't
        if not client_cert_path.is_file():
            raise FileNotFoundError(f"Client certificate file not found: {client_cert_path}")
        if not client_key_path.is_file():
            raise FileNotFoundError(f"Client key file not found: {client_key_path}")
        
        self._client_cert_path = client_cert_path
        self._client_key_path = client_key_path

    def get_session(self) -> requests.Session:
        """Return a session using HTTP basic authentication."""
        session = requests.Session()
        session.cert = (self._client_cert_path, self._client_key_path)
        return session
