"""Integration tests for the Elasticsearch authentication providers.

Each provider sends a GET to ``ELASTIC_SEARCH_URL`` over HTTPS, verifying the
cluster certificate with ``CA_CERT_PATH``: valid credentials must get a
``200`` and invalid ones must be rejected.

These tests send real requests, so they are kept out of the unit test run:
``poetry run pytest`` only collects ``tests/`` and deselects the
``integration`` marker. Copy ``integration_test.env.sample`` to
``integration_test.env``, fill it in, then run from the ``elastic/``
directory::

    poetry run pytest tests_integration -m integration -v
"""

import base64

import pytest
import requests

from src.services.api_authentication import (
    ApiKeyAuthentication,
    AuthenticationProvider,
    PKIAuthentication,
    UserPasswordAuthentication,
)
from tests_integration.settings import IntegrationSettings

pytestmark = pytest.mark.integration

REQUEST_TIMEOUT_SECONDS = 30
# Well-formed encoded key (base64 of "id:api_key") that the cluster never issued.
UNKNOWN_API_KEY = base64.b64encode(b"unknown-id:unknown-api-key").decode()


def _get(
    provider: AuthenticationProvider, settings: IntegrationSettings
) -> requests.Response:
    """GET ``ELASTIC_SEARCH_URL`` with the provider's session."""
    with provider.get_session() as session:
        session.verify = str(settings.ca_cert_path)
        return session.get(settings.elastic_search_url, timeout=REQUEST_TIMEOUT_SECONDS)


@pytest.mark.parametrize(
    "make_provider",
    [
        pytest.param(
            lambda s: ApiKeyAuthentication(s.elastic_api_key.get_secret_value()),
            id="api_key",
        ),
        pytest.param(
            lambda s: UserPasswordAuthentication(
                s.elastic_user, s.elastic_password.get_secret_value()
            ),
            id="user_password",
        ),
        pytest.param(
            lambda s: PKIAuthentication(s.elastic_cert_path, s.elastic_key_path),
            id="pki",
        ),
    ],
)
def test_valid_credentials_return_200(make_provider, settings):
    """Elasticsearch accepts a request sent with valid credentials."""
    response = _get(make_provider(settings), settings)

    assert response.status_code == 200, response.text


@pytest.mark.parametrize(
    "make_provider",
    [
        pytest.param(lambda s: ApiKeyAuthentication(UNKNOWN_API_KEY), id="api_key"),
        pytest.param(
            lambda s: UserPasswordAuthentication(
                s.elastic_user, s.elastic_password.get_secret_value() + "-invalid"
            ),
            id="user_password",
        ),
    ],
)
def test_invalid_credentials_return_4xx(make_provider, settings):
    """Elasticsearch answers a request sent with invalid credentials with a 4XX."""
    response = _get(make_provider(settings), settings)

    assert 400 <= response.status_code < 500, response.text


def test_untrusted_client_certificate_is_refused(untrusted_client_cert, settings):
    """Elasticsearch ends the TLS handshake for a certificate no trusted CA signed.

    The rejection happens before any HTTP exchange, so there is no status code
    to check: the server's TLS alert (e.g. ``SSLV3_ALERT_CERTIFICATE_UNKNOWN``)
    surfaces as an ``SSLError``. Matching ``_ALERT_`` tells it apart from a
    local failure to verify the cluster certificate (``CERTIFICATE_VERIFY_FAILED``).
    """
    provider = PKIAuthentication(*untrusted_client_cert)

    with pytest.raises(requests.exceptions.SSLError, match="_ALERT_"):
        _get(provider, settings)
