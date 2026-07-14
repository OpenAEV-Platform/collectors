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

from xtm_one.openaev_xtm_one import OpenAEVXtmOne  # noqa: E402


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


def test_agent_payload_external_reference_and_model():
    collector = _build_collector()

    payload = collector._agent_payload({"slug": "triage", "name": "Triage"})

    assert payload["asset_external_reference"] == "xtm-one:agent:triage"
    assert payload["ai_target_model"] == "agent:triage"
    assert payload["ai_target_endpoint"] == "https://xtm-one.example.test/v1"
    assert payload["ai_target_api_key_variable"] == "XTM_ONE_API_KEY"


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
