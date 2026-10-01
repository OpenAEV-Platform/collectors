"""Fixtures for the Elasticsearch integration tests."""

import subprocess
from pathlib import Path

import pytest

from tests_integration.settings import ENV_FILE, IntegrationSettings


@pytest.fixture(scope="session")
def settings() -> IntegrationSettings:
    """Load the cluster parameters from ``integration_test.env``."""
    if not ENV_FILE.is_file():
        pytest.fail(
            f"{ENV_FILE} not found: copy {ENV_FILE.name}.sample next to it and fill it in."
        )
    return IntegrationSettings()


@pytest.fixture(scope="session")
def untrusted_client_cert(tmp_path_factory) -> tuple[Path, Path]:
    """Create a self-signed client certificate and key that no cluster CA trusts."""
    directory = tmp_path_factory.mktemp("untrusted-client")
    cert_path = directory / "client.crt"
    key_path = directory / "client.key"
    subprocess.run(  # noqa: S603
        [  # noqa: S607
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=untrusted-client",
            "-keyout",
            str(key_path),
            "-out",
            str(cert_path),
        ],
        check=True,
        capture_output=True,
    )
    return cert_path, key_path
