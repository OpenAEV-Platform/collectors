"""Tests of the OVHcloud API client: signature, authentication headers and retries."""

import hashlib
from unittest.mock import MagicMock, patch

import pytest
from ovhcloud import client as client_module
from ovhcloud.client import OvhApiError, OvhClient, compute_signature


def _response(status, payload=None, headers=None, text=""):
    response = MagicMock()
    response.status_code = status
    response.json.return_value = payload
    response.headers = headers or {}
    response.text = text
    response.content = b"x" if payload is not None else b""
    return response


def test_signature_matches_the_documented_scheme():
    url = "https://eu.api.ovh.com/1.0/dedicated/server"
    signature = compute_signature("secret", "consumer", "get", url, "", 1366560945)
    expected = hashlib.sha1(
        b"secret+consumer+GET+https://eu.api.ovh.com/1.0/dedicated/server++1366560945"
    ).hexdigest()
    assert signature == f"$1${expected}"


def test_signature_known_vector():
    # Reference value computed independently for the documented example of the
    # OVHcloud "first steps with the API" guide.
    assert (
        compute_signature(
            "EXEgWIz07P0HYwtQDs7cNIqCiQaWSuHF",
            "MtSwSrPpNjqfVSmJhLbPyr2i45lSDPHw",
            "GET",
            "https://eu.api.ovh.com/1.0/auth/currentCredential",
            "",
            1366560945,
        )
        == "$1$"
        + hashlib.sha1(
            b"EXEgWIz07P0HYwtQDs7cNIqCiQaWSuHF+MtSwSrPpNjqfVSmJhLbPyr2i45lSDPHw+GET+"
            b"https://eu.api.ovh.com/1.0/auth/currentCredential++1366560945"
        ).hexdigest()
    )


def test_incomplete_credentials_are_refused():
    with pytest.raises(ValueError, match="incomplete"):
        OvhClient(application_key="ak", application_secret="as")


def test_unknown_endpoint_is_refused():
    with pytest.raises(ValueError, match="Unknown OVHcloud endpoint"):
        OvhClient(endpoint="ovh-mars", client_id="id", client_secret="secret")


def test_signed_get_uses_server_time_and_signs_the_query_string():
    session = MagicMock()
    session.request.side_effect = [
        _response(200, 1_000_100),  # /auth/time
        _response(200, ["ns1.ip-1-2-3.eu"]),
    ]
    client = OvhClient(
        application_key="ak",
        application_secret="as",
        consumer_key="ck",
        session=session,
    )
    with patch.object(client_module.time, "time", return_value=1_000_000):
        result = client.get("/dedicated/server", {"iamTags": "x"})

    assert result == ["ns1.ip-1-2-3.eu"]
    method, url = session.request.call_args_list[1].args
    headers = session.request.call_args_list[1].kwargs["headers"]
    assert method == "GET"
    assert url == "https://eu.api.ovh.com/1.0/dedicated/server?iamTags=x"
    assert headers["X-Ovh-Application"] == "ak"
    assert headers["X-Ovh-Consumer"] == "ck"
    assert headers["X-Ovh-Timestamp"] == "1000100"
    assert headers["X-Ovh-Signature"] == compute_signature(
        "as", "ck", "GET", url, "", 1_000_100
    )


def test_oauth2_token_is_fetched_once_and_sent_as_bearer():
    session = MagicMock()
    session.post.return_value = _response(
        200, {"access_token": "tok", "expires_in": 3600}
    )
    session.request.return_value = _response(200, [])
    client = OvhClient(
        endpoint="ovh-ca", client_id="id", client_secret="secret", session=session
    )
    client.get("/vps")
    client.get("/vps")

    assert session.post.call_count == 1
    assert session.post.call_args.args[0] == "https://ca.ovh.com/auth/oauth2/token"
    assert session.post.call_args.kwargs["data"]["grant_type"] == "client_credentials"
    headers = session.request.call_args.kwargs["headers"]
    assert headers == {"Authorization": "Bearer tok"}
    assert session.request.call_args.args[1] == "https://ca.api.ovh.com/1.0/vps"


def test_throttling_and_server_errors_are_retried():
    session = MagicMock()
    session.post.return_value = _response(200, {"access_token": "tok"})
    session.request.side_effect = [
        _response(429, headers={"Retry-After": "0"}),
        _response(503),
        _response(200, ["ok"]),
    ]
    client = OvhClient(
        client_id="id", client_secret="secret", session=session, backoff_seconds=0
    )
    with patch.object(client_module.time, "sleep") as sleep:
        assert client.get("/vps") == ["ok"]
    assert session.request.call_count == 3
    assert sleep.call_count == 2


def test_retries_are_bounded():
    session = MagicMock()
    session.post.return_value = _response(200, {"access_token": "tok"})
    session.request.return_value = _response(503, text="unavailable")
    client = OvhClient(
        client_id="id",
        client_secret="secret",
        session=session,
        max_retries=2,
        backoff_seconds=0,
    )
    with patch.object(client_module.time, "sleep"):
        with pytest.raises(OvhApiError) as err:
            client.get("/vps")
    assert err.value.status_code == 503
    assert session.request.call_count == 3


def test_client_errors_are_not_retried():
    session = MagicMock()
    session.post.return_value = _response(200, {"access_token": "tok"})
    session.request.return_value = _response(403, text="This call has not been granted")
    client = OvhClient(client_id="id", client_secret="secret", session=session)
    with pytest.raises(OvhApiError) as err:
        client.get("/dedicated/server")
    assert err.value.status_code == 403
    assert session.request.call_count == 1
