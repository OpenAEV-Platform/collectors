"""Unit tests for the XTM One read client.

These tests exercise only ``xtm_one.client`` (which depends solely on
``requests``) so they remain independent of the pyoaev AI domain support that the
collector daemon relies on.
"""

from unittest.mock import MagicMock

import pytest
from xtm_one.client import XtmOneClient


def _build_client(**overrides):
    config = {
        "base_url": "https://xtm-one.example.test",
        "token": "fcp-secret",
    }
    config.update(overrides)
    return XtmOneClient(config["base_url"], config["token"])


def _mock_session(payload):
    response = MagicMock()
    response.json.return_value = payload
    response.raise_for_status.return_value = None
    session = MagicMock()
    session.get.return_value = response
    return session


def test_requires_base_url():
    client = _build_client(base_url=None)
    with pytest.raises(ValueError, match="url"):
        client.list_agents()


@pytest.mark.parametrize(
    "bad_url",
    ["xtm-one.example.test", "ftp://xtm-one.example.test", "https://"],
)
def test_rejects_invalid_url(bad_url):
    client = _build_client(base_url=bad_url)
    with pytest.raises(ValueError, match="http"):
        client.list_agents()


@pytest.mark.parametrize("missing_token", [None, ""])
def test_requires_token(missing_token):
    client = _build_client(token=missing_token)
    with pytest.raises(ValueError, match="token"):
        client.list_agents()


def test_list_agents_filters_unusable_agents():
    client = _build_client()
    client.session = _mock_session(
        [
            {"slug": "triage", "name": "Triage", "enabled": True},
            {"slug": "disabled", "name": "Disabled", "enabled": False},
            {
                "slug": "no-chat",
                "name": "No Chat",
                "enabled": True,
                "disable_chat": True,
            },
            {"slug": None, "name": "No Slug", "enabled": True},
        ]
    )

    agents = client.list_agents()

    assert [a["slug"] for a in agents] == ["triage"]


@pytest.mark.parametrize("unexpected_payload", [None, "oops", 42])
def test_list_agents_tolerates_unexpected_payload_types(unexpected_payload):
    client = _build_client()
    client.logger = MagicMock()
    client.session = _mock_session(unexpected_payload)

    assert client.list_agents() == []
    client.logger.warning.assert_called_once()


def test_list_agents_skips_non_dict_entries():
    client = _build_client()
    client.session = _mock_session(
        ["not-a-dict", {"slug": "triage", "name": "Triage", "enabled": True}]
    )

    agents = client.list_agents()

    assert [a["slug"] for a in agents] == ["triage"]


def test_list_agents_supports_items_envelope():
    client = _build_client()
    client.session = _mock_session(
        {"items": [{"slug": "triage", "name": "Triage", "enabled": True}]}
    )

    agents = client.list_agents()

    assert [a["slug"] for a in agents] == ["triage"]


def test_list_agents_sends_bearer_token():
    client = _build_client()
    client.session = _mock_session([])

    client.list_agents()

    args, kwargs = client.session.get.call_args
    assert args[0] == "https://xtm-one.example.test/api/v1/agents"
    assert kwargs["headers"]["Authorization"] == "Bearer fcp-secret"


def test_list_bare_models_excludes_agents_and_copilot():
    client = _build_client()
    client.session = _mock_session(
        {
            "data": [
                {"id": "gpt-4o", "owned_by": "openai"},
                {"id": "claude-3-5-sonnet", "owned_by": "anthropic"},
                {"id": "agent:triage", "owned_by": "copilot"},
                {"id": "my-agent", "owned_by": "copilot"},
            ]
        }
    )

    models = client.list_bare_models()

    assert [m["id"] for m in models] == ["gpt-4o", "claude-3-5-sonnet"]


def test_list_bare_models_handles_empty_payload():
    client = _build_client()
    client.session = _mock_session({})

    assert client.list_bare_models() == []


def test_list_bare_models_skips_non_dict_entries():
    client = _build_client()
    client.session = _mock_session(
        {"data": ["not-a-dict", {"id": "gpt-4o", "owned_by": "openai"}]}
    )

    models = client.list_bare_models()

    assert [m["id"] for m in models] == ["gpt-4o"]


def _mock_paginated_session(pages):
    responses = []
    for page in pages:
        response = MagicMock()
        response.json.return_value = page
        response.raise_for_status.return_value = None
        responses.append(response)
    session = MagicMock()
    session.get.side_effect = responses
    return session


def test_list_security_events_sends_security_filters():
    client = _build_client()
    client.session = _mock_session(
        {"items": [{"id": "a", "details": {"message_preview": "x"}}], "total": 1}
    )

    events = client.list_security_events(date_from="2026-07-15T00:00:00+00:00")

    assert [e["id"] for e in events] == ["a"]
    args, kwargs = client.session.get.call_args
    assert args[0] == "https://xtm-one.example.test/api/v1/audit-logs"
    assert kwargs["params"]["action"] == "security_alert"
    assert kwargs["params"]["entity_type"] == "security"
    assert kwargs["params"]["date_from"] == "2026-07-15T00:00:00+00:00"


def test_list_security_events_skips_non_dict_items():
    client = _build_client()
    client.session = _mock_session({"items": ["oops", {"id": "a"}], "total": 2})

    events = client.list_security_events()

    assert [e["id"] for e in events] == ["a"]


def test_list_security_events_paginates_until_page_not_full():
    client = _build_client()
    first_page = {"items": [{"id": str(i)} for i in range(200)], "total": 250}
    second_page = {"items": [{"id": str(i)} for i in range(200, 250)], "total": 250}
    client.session = _mock_paginated_session([first_page, second_page])

    events = client.list_security_events()

    assert len(events) == 250
    assert client.session.get.call_count == 2
