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
