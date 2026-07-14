"""Unit tests for the collector upsert logic.

These tests exercise the idempotency core of ``OpenAEVXtmOne``: existing AI
targets are matched on their stable external reference and updated in place,
while unknown references trigger a creation. The daemon is built without its
``__init__`` (which registers against a live OpenAEV) so only the pyoaev import
is required.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

pytest.importorskip("pyoaev")

from pyoaev.configuration import Configuration  # noqa: E402
from xtm_one.openaev_xtm_one import OpenAEVXtmOne  # noqa: E402


def _build_configuration(**overrides):
    hints = {
        "openaev_url": {"data": "http://localhost:3001"},
        "openaev_token": {"data": "token"},
        "openaev_tenant_id": {"data": None},
        "collector_id": {"data": "collector-uuid"},
        "collector_name": {"data": "XTM One"},
        "collector_log_level": {"data": "error"},
        "xtm_one_url": {"data": "https://xtm-one.example.test/"},
        "xtm_one_token": {"data": "fcp-secret"},
        "xtm_one_api_key_variable": {"data": "XTM_ONE_API_KEY"},
        "include_bare_models": {"data": False},
        "agent_tags": {"data": None},
    }
    for key, value in overrides.items():
        hints[key] = {"data": value}
    return Configuration(config_hints=hints)


def _build_collector():
    collector = OpenAEVXtmOne.__new__(OpenAEVXtmOne)
    collector.api = MagicMock()
    collector.api.tag.upsert.return_value = {"tag_id": "tag-uuid"}
    collector.logger = MagicMock()
    collector.xtm_one_url = "https://xtm-one.example.test"
    collector.api_key_variable = "XTM_ONE_API_KEY"
    collector.include_bare_models = False
    collector.agent_tags = set()
    collector._tag_cache = {}
    return collector


def test_init_normalizes_configuration():
    collector = OpenAEVXtmOne(
        configuration=_build_configuration(agent_tags="Prod, RED-team")
    )

    assert collector.xtm_one_url == "https://xtm-one.example.test"
    assert collector._endpoint == "https://xtm-one.example.test/v1"
    assert collector.agent_tags == {"prod", "red-team"}
    assert collector.include_bare_models is False
    assert collector.api_key_variable == "XTM_ONE_API_KEY"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (None, set()),
        ("", set()),
        ("Prod", {"prod"}),
        ("a, B ,, c ", {"a", "b", "c"}),
    ],
)
def test_parse_tags(raw, expected):
    assert OpenAEVXtmOne._parse_tags(raw) == expected


def test_agent_in_scope_matches_tags_case_insensitively():
    collector = _build_collector()
    collector.agent_tags = {"prod"}

    assert collector._agent_in_scope({"tags": ["PROD", "other"]})
    assert not collector._agent_in_scope({"tags": ["other"]})
    assert not collector._agent_in_scope({})


def test_agent_in_scope_accepts_all_when_unscoped():
    collector = _build_collector()

    assert collector._agent_in_scope({"tags": []})


def test_resolve_tag_caches_and_tolerates_errors():
    collector = _build_collector()

    first = collector._resolve_tag("source:xtm-one", "#0ea5e9")
    second = collector._resolve_tag("source:xtm-one", "#0ea5e9")

    assert first == second == "tag-uuid"
    collector.api.tag.upsert.assert_called_once()

    collector.api.tag.upsert.side_effect = RuntimeError("boom")
    assert collector._resolve_tag("other", "#6366f1") is None
    collector.logger.warning.assert_called_once()


def test_agent_payload_external_reference_and_model():
    collector = _build_collector()

    payload = collector._agent_payload({"slug": "triage", "name": "Triage"})

    assert payload["asset_external_reference"] == "xtm-one:agent:triage"
    assert payload["ai_target_model"] == "agent:triage"
    assert payload["ai_target_endpoint"] == "https://xtm-one.example.test/v1"
    assert payload["ai_target_api_key_variable"] == "XTM_ONE_API_KEY"


def test_agent_payload_normalizes_mirrored_tags():
    collector = _build_collector()

    collector._agent_payload(
        {"slug": "triage", "name": "Triage", "tags": ["Prod", " prod ", "RED-team", ""]}
    )

    upserted = [
        call.args[0]["tag_name"] for call in collector.api.tag.upsert.call_args_list
    ]
    assert upserted == ["source:xtm-one", "type:agent", "prod", "red-team"]


def test_model_payload_external_reference_and_model():
    collector = _build_collector()

    payload = collector._model_payload({"id": "gpt-4o"})

    assert payload["asset_external_reference"] == "xtm-one:model:gpt-4o"
    assert payload["ai_target_model"] == "gpt-4o"
    assert payload["ai_target_endpoint"] == "https://xtm-one.example.test/v1"


def test_existing_targets_keeps_only_xtm_one_references():
    collector = _build_collector()
    collector.api.ai_target.list.return_value = [
        SimpleNamespace(
            asset_external_reference="xtm-one:agent:triage", asset_id="id-1"
        ),
        SimpleNamespace(
            asset_external_reference="xtm-one:model:gpt-4o", asset_id="id-2"
        ),
        SimpleNamespace(asset_external_reference="other:ref", asset_id="id-3"),
        SimpleNamespace(asset_external_reference=None, asset_id="id-4"),
    ]

    mapping = collector._existing_targets()

    assert mapping == {
        "xtm-one:agent:triage": "id-1",
        "xtm-one:model:gpt-4o": "id-2",
    }


def test_existing_targets_returns_empty_mapping_on_error():
    collector = _build_collector()
    collector.api.ai_target.list.side_effect = RuntimeError("boom")

    assert collector._existing_targets() == {}


def test_upsert_updates_existing_target_in_place():
    collector = _build_collector()
    payload = collector._agent_payload({"slug": "triage", "name": "Triage"})

    collector._upsert(payload, {"xtm-one:agent:triage": "id-1"})

    collector.api.ai_target.update.assert_called_once_with("id-1", payload)
    collector.api.ai_target.create.assert_not_called()


def test_upsert_creates_target_when_absent():
    collector = _build_collector()
    payload = collector._model_payload({"id": "gpt-4o"})

    collector._upsert(payload, {"xtm-one:agent:triage": "id-1"})

    collector.api.ai_target.create.assert_called_once_with(payload)
    collector.api.ai_target.update.assert_not_called()


def test_upsert_swallows_api_errors():
    collector = _build_collector()
    collector.api.ai_target.create.side_effect = RuntimeError("boom")
    payload = collector._agent_payload({"slug": "triage", "name": "Triage"})

    collector._upsert(payload, {})

    collector.logger.error.assert_called_once()


def test_process_message_upserts_agents_and_models():
    collector = _build_collector()
    collector.include_bare_models = True
    collector.agent_tags = {"prod"}
    collector.client = MagicMock()
    collector.client.list_agents.return_value = [
        {"slug": "triage", "name": "Triage", "tags": ["prod"]},
        {"slug": "ignored", "name": "Ignored", "tags": ["dev"]},
    ]
    collector.client.list_bare_models.return_value = [{"id": "gpt-4o"}]
    collector.api.ai_target.list.return_value = [
        SimpleNamespace(
            asset_external_reference="xtm-one:agent:triage", asset_id="id-1"
        ),
    ]

    collector._process_message()

    collector.api.ai_target.update.assert_called_once()
    assert (
        collector.api.ai_target.update.call_args[0][1]["asset_external_reference"]
        == "xtm-one:agent:triage"
    )
    collector.api.ai_target.create.assert_called_once()
    assert (
        collector.api.ai_target.create.call_args[0][0]["asset_external_reference"]
        == "xtm-one:model:gpt-4o"
    )


def test_process_message_aborts_when_agents_cannot_be_fetched():
    collector = _build_collector()
    collector.client = MagicMock()
    collector.client.list_agents.side_effect = RuntimeError("boom")

    collector._process_message()

    collector.logger.error.assert_called_once()
    collector.api.ai_target.list.assert_not_called()


def test_process_message_tolerates_model_listing_failure():
    collector = _build_collector()
    collector.include_bare_models = True
    collector.client = MagicMock()
    collector.client.list_agents.return_value = []
    collector.client.list_bare_models.side_effect = RuntimeError("boom")
    collector.api.ai_target.list.return_value = []

    collector._process_message()

    collector.logger.error.assert_called_once()
    collector.api.ai_target.create.assert_not_called()
