"""Unit tests for the Cisco AI Defense client verdict mapping.

These tests exercise only ``cisco_ai_defense.client`` (which depends solely on
``requests``) so they remain independent of the pyoaev AI domain support that the
collector daemon relies on.
"""

from unittest.mock import MagicMock

import pytest
from cisco_ai_defense.client import CiscoAiDefenseClient


def _build_client(**overrides):
    config = {
        "cisco_base_url": "https://example.test",
        "cisco_api_key": "secret-key",
        "cisco_auth_header": "X-Cisco-AI-Defense-Api-Key",
    }
    config.update(overrides)
    return CiscoAiDefenseClient(config)


def _mock_session(payload):
    response = MagicMock()
    response.json.return_value = payload
    response.raise_for_status.return_value = None
    session = MagicMock()
    session.post.return_value = response
    return session


def test_scan_requires_base_url():
    client = _build_client(cisco_base_url=None)
    with pytest.raises(ValueError, match="base_url"):
        client.scan("payload")


@pytest.mark.parametrize(
    "bad_base_url",
    ["example.test", "example.test/api", "ftp://example.test", "https://"],
)
def test_scan_rejects_base_url_without_valid_scheme(bad_base_url):
    client = _build_client(cisco_base_url=bad_base_url)
    with pytest.raises(ValueError, match="http"):
        client.scan("payload")


def test_scan_safe_response_is_not_flagged():
    client = _build_client()
    client.session = _mock_session({"is_safe": True})

    verdict = client.scan("payload")

    assert verdict.flagged is False
    assert verdict.blocked is False


def test_scan_unsafe_without_block_is_detection_only():
    client = _build_client()
    client.session = _mock_session({"is_safe": False})

    verdict = client.scan("payload")

    assert verdict.flagged is True
    assert verdict.blocked is False


def test_scan_block_action_is_prevention():
    client = _build_client()
    client.session = _mock_session({"is_safe": False, "action": "BLOCK"})

    verdict = client.scan("payload")

    assert verdict.flagged is True
    assert verdict.blocked is True


def test_scan_classification_without_block_is_detection_only():
    client = _build_client()
    client.session = _mock_session(
        {"is_safe": True, "classifications": [{"classification": "PROMPT_INJECTION"}]}
    )

    verdict = client.scan("payload")

    assert verdict.flagged is True
    assert verdict.blocked is False
    assert verdict.detail == "PROMPT_INJECTION"


def test_scan_uses_rules_fallback_for_detail():
    client = _build_client()
    client.session = _mock_session(
        {"is_safe": True, "rules": [{"rule_name": "jailbreak"}]}
    )

    verdict = client.scan("payload")

    assert verdict.flagged is True
    assert verdict.detail == "jailbreak"


def test_scan_handles_non_dict_classification_entries():
    client = _build_client()
    client.session = _mock_session({"is_safe": False, "classifications": ["jailbreak"]})

    verdict = client.scan("payload")

    assert verdict.flagged is True
    assert verdict.detail == "jailbreak"


def test_scan_default_detail_when_no_classification():
    client = _build_client()
    client.session = _mock_session({"is_safe": False})

    verdict = client.scan("payload")

    assert verdict.detail == "Cisco AI Defense classification"


def test_scan_sends_auth_header_and_ordered_messages():
    client = _build_client()
    client.session = _mock_session({"is_safe": True})

    client.scan("hello", system_prompt="stay safe")

    args, kwargs = client.session.post.call_args
    assert args[0] == "https://example.test/api/v1/inspect/prompt"
    assert kwargs["headers"]["X-Cisco-AI-Defense-Api-Key"] == "secret-key"
    assert kwargs["json"]["messages"] == [
        {"role": "system", "content": "stay safe"},
        {"role": "user", "content": "hello"},
    ]
