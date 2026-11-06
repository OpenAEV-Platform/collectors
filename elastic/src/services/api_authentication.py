import atexit
import os
import shutil
import tempfile
from pathlib import Path
from typing import Protocol

import requests

# O_NOFOLLOW only exists on POSIX systems; O_EXCL already refuses an existing
# path, symlinks included.
_PRIVATE_FILE_FLAGS = (
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
)


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

    ``requests`` only loads a client certificate and key from files, so both
    are written to a private temporary directory (mode ``0700``, files mode
    ``0600``), removed by :meth:`cleanup` or when the interpreter exits.
    """

    def __init__(self, client_cert_pem: str, client_key_pem: str) -> None:
        self._directory = Path(tempfile.mkdtemp(prefix="openaev-elastic-pki-"))
        atexit.register(self.cleanup)
        self._client_cert_path = _write_private_file(
            self._directory / "client.crt", client_cert_pem
        )
        self._client_key_path = _write_private_file(
            self._directory / "client.key", client_key_pem
        )

    def get_session(self) -> requests.Session:
        """Return a session presenting the client certificate during the TLS handshake."""
        session = requests.Session()
        session.cert = (str(self._client_cert_path), str(self._client_key_path))
        return session

    def cleanup(self) -> None:
        """Remove the temporary directory holding the certificate and key."""
        shutil.rmtree(self._directory, ignore_errors=True)


def _write_private_file(path: Path, content: str) -> Path:
    """Create ``path`` readable by its owner only, then write ``content``.

    The mode is set when the file is created, so the content is never readable
    by other users, and an existing file or symlink at ``path`` is refused.

    Returns:
        The path of the written file.

    """
    fd = os.open(path, _PRIVATE_FILE_FLAGS, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(content if content.endswith("\n") else f"{content}\n")
    return path
