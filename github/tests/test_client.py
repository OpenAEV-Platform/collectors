"""Tests of the read-only GitHub client: pagination, ETags and rate limits."""

from unittest.mock import MagicMock

import pytest

from github_collector.client import GitHubApiError, GitHubClient, next_page_url


def _response(status, body=None, headers=None, text=""):
    response = MagicMock()
    response.status_code = status
    response.json.return_value = body
    response.headers = headers or {}
    response.text = text
    return response


def _client(responses, **kwargs):
    session = MagicMock()
    session.headers = {}
    session.get.side_effect = responses
    sleeps = []
    client = GitHubClient(
        token="t",
        session=session,
        sleep=sleeps.append,
        clock=lambda: 1000.0,
        logger=MagicMock(),
        **kwargs,
    )
    return client, session, sleeps


def test_next_page_url_reads_the_link_header():
    link = (
        '<https://api.github.com/orgs/acme/repos?page=2>; rel="next", '
        '<https://api.github.com/orgs/acme/repos?page=5>; rel="last"'
    )
    assert next_page_url(link) == "https://api.github.com/orgs/acme/repos?page=2"
    assert next_page_url('<https://x?page=1>; rel="prev"') is None
    assert next_page_url(None) is None


def test_headers_are_read_only_and_versioned():
    client, session, _ = _client([])
    assert session.headers["Authorization"] == "Bearer t"
    assert session.headers["X-GitHub-Api-Version"] == "2022-11-28"


def test_paginate_follows_every_page():
    client, session, _ = _client(
        [
            _response(
                200, [{"n": 1}], {"Link": '<https://api.github.com/p2>; rel="next"'}
            ),
            _response(200, [{"n": 2}]),
        ]
    )
    assert [item["n"] for item in client.paginate("/orgs/acme/repos")] == [1, 2]
    first_url = session.get.call_args_list[0].args[0]
    assert first_url == "https://api.github.com/orgs/acme/repos?per_page=100"
    # Only GET is ever called on the session.
    assert not session.post.called and not session.patch.called


def test_items_key_reads_wrapped_lists():
    client, _, _ = _client(
        [_response(200, {"total_count": 1, "workflows": [{"id": 1}]})]
    )
    assert list(client.repository_workflows("acme/api")) == [{"id": 1}]


def test_a_304_reuses_the_cached_page_and_sends_the_etag():
    client, session, _ = _client(
        [_response(200, [{"n": 1}], {"ETag": '"abc"'}), _response(304)]
    )
    assert list(client.paginate("/orgs/acme/repos")) == [{"n": 1}]
    assert list(client.paginate("/orgs/acme/repos")) == [{"n": 1}]
    second_headers = session.get.call_args_list[1].kwargs["headers"]
    assert second_headers == {"If-None-Match": '"abc"'}


def test_primary_rate_limit_waits_for_the_reset():
    client, _, sleeps = _client(
        [
            _response(
                403, headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1030"}
            ),
            _response(200, {"ok": True}),
        ]
    )
    assert client.get("/rate") == {"ok": True}
    assert sleeps == [31.0]


def test_secondary_rate_limit_honours_retry_after():
    client, _, sleeps = _client(
        [_response(429, headers={"Retry-After": "5"}), _response(200, {"ok": True})]
    )
    assert client.get("/x") == {"ok": True}
    assert sleeps == [5.0]


def test_server_errors_back_off_exponentially_then_give_up():
    client, _, sleeps = _client([_response(502)] * 3, max_retries=2)
    with pytest.raises(GitHubApiError) as err:
        client.get("/x")
    assert err.value.status_code == 502
    assert sleeps == [2.0, 4.0]


def test_a_rate_limit_beyond_the_allowed_wait_fails_fast():
    client, _, sleeps = _client(
        [
            _response(
                403,
                headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "99999"},
            )
        ],
        max_rate_limit_wait_seconds=60,
    )
    with pytest.raises(GitHubApiError, match="rate limited"):
        client.get("/x")
    assert sleeps == []


def test_a_plain_403_is_not_retried():
    client, _, sleeps = _client([_response(403, text="Resource not accessible")])
    with pytest.raises(GitHubApiError) as err:
        client.get("/x")
    assert err.value.status_code == 403
    assert sleeps == []


def test_enterprise_server_url_is_used_as_the_base():
    client, session, _ = _client(
        [_response(200, [])], api_url="https://github.example.com/api/v3/"
    )
    list(client.organization_repositories("acme"))
    url = session.get.call_args.args[0]
    assert url.startswith("https://github.example.com/api/v3/orgs/acme/repos?")
