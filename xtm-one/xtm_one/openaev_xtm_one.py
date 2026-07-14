"""Import XTM One agents (and optionally bare LLM models) as OpenAEV AI targets.

On each run the collector reads the XTM One agents catalog (optionally scoped to a
set of tags) and upserts one OpenAEV ``AiTarget`` per agent, wired to XTM One's
OpenAI-compatible proxy (``{xtm_one_url}/v1`` with model ``agent:<slug>``). When
``include_bare_models`` is enabled it additionally mirrors the bare LLM models
exposed by the proxy. Targets are matched on a stable external reference so the
collector is idempotent and updates existing targets in place.

The credential the AI red team injector uses at execution time is never stored on
the target: only the name of the injector environment variable holding it
(``xtm_one_api_key_variable``) is recorded, matching the AI target contract.
"""

from pyoaev.configuration import Configuration
from pyoaev.daemons import CollectorDaemon
from xtm_one.client import XtmOneClient
from xtm_one.configuration.config_loader import ConfigLoader

PROVIDER = "OPENAI_COMPATIBLE"
SOURCE_TAG = "source:xtm-one"
AGENT_TAG = "type:agent"
MODEL_TAG = "type:model"
SOURCE_TAG_COLOR = "#0ea5e9"
KIND_TAG_COLOR = "#6366f1"


class OpenAEVXtmOne(CollectorDaemon):
    def __init__(self, configuration: Configuration):
        super().__init__(
            configuration=configuration,
            callback=self._process_message,
            collector_type="openaev_xtm_one",
        )
        self.collector_id = self._configuration.get("collector_id")
        self.xtm_one_url = (self._configuration.get("xtm_one_url") or "").rstrip("/")
        self.api_key_variable = self._configuration.get("xtm_one_api_key_variable")
        self.include_bare_models = bool(self._configuration.get("include_bare_models"))
        self.agent_tags = self._parse_tags(self._configuration.get("agent_tags"))
        self.client = XtmOneClient(
            self.xtm_one_url,
            self._configuration.get("xtm_one_token"),
            self.logger,
        )
        self._tag_cache: dict[str, str] = {}

    @staticmethod
    def _parse_tags(raw) -> set[str]:
        if not raw:
            return set()
        return {t.strip().lower() for t in str(raw).split(",") if t.strip()}

    @property
    def _endpoint(self) -> str:
        """OpenAI-compatible proxy base; the AI red team injector appends
        ``/chat/completions`` itself."""
        return f"{self.xtm_one_url}/v1"

    def _resolve_tag(self, name: str, color: str) -> str | None:
        if name in self._tag_cache:
            return self._tag_cache[name]
        try:
            result = self.api.tag.upsert({"tag_name": name, "tag_color": color})
            tag_id = result.get("tag_id")
        except Exception as exc:  # noqa: BLE001
            self.logger.warning(f"Failed to upsert tag {name}: {exc}")
            return None
        if tag_id:
            self._tag_cache[name] = tag_id
        return tag_id

    def _resolve_tags(self, names: list[str]) -> list[str]:
        ids = []
        for name in names:
            color = SOURCE_TAG_COLOR if name == SOURCE_TAG else KIND_TAG_COLOR
            tag_id = self._resolve_tag(name, color)
            if tag_id:
                ids.append(tag_id)
        return ids

    def _agent_in_scope(self, agent: dict) -> bool:
        if not self.agent_tags:
            return True
        agent_tags = {str(t).strip().lower() for t in (agent.get("tags") or [])}
        return bool(agent_tags & self.agent_tags)

    def _agent_payload(self, agent: dict) -> dict:
        slug = agent.get("slug")
        name = agent.get("name") or slug
        tag_ids = self._resolve_tags(
            [SOURCE_TAG, AGENT_TAG] + list(agent.get("tags") or [])
        )
        return {
            "asset_name": f"{name} (XTM One agent)",
            "asset_description": agent.get("description")
            or "XTM One agent exposed through the OpenAI-compatible proxy.",
            "asset_external_reference": f"xtm-one:agent:{slug}",
            "asset_tags": tag_ids,
            "ai_target_provider": PROVIDER,
            "ai_target_endpoint": self._endpoint,
            "ai_target_model": f"agent:{slug}",
            "ai_target_modality": "TEXT",
            "ai_target_api_key_variable": self.api_key_variable,
            "ai_target_configuration": {
                "source": "xtm-one",
                "xtm_one_kind": "agent",
                "xtm_one_slug": slug,
            },
        }

    def _model_payload(self, model: dict) -> dict:
        model_id = model.get("id")
        tag_ids = self._resolve_tags([SOURCE_TAG, MODEL_TAG])
        return {
            "asset_name": f"{model_id} (XTM One model)",
            "asset_description": "Bare LLM model exposed through the XTM One "
            "OpenAI-compatible proxy.",
            "asset_external_reference": f"xtm-one:model:{model_id}",
            "asset_tags": tag_ids,
            "ai_target_provider": PROVIDER,
            "ai_target_endpoint": self._endpoint,
            "ai_target_model": model_id,
            "ai_target_modality": "TEXT",
            "ai_target_api_key_variable": self.api_key_variable,
            "ai_target_configuration": {
                "source": "xtm-one",
                "xtm_one_kind": "model",
                "xtm_one_model": model_id,
            },
        }

    def _existing_targets(self) -> dict[str, str]:
        """Map ``asset_external_reference`` -> ``asset_id`` for previously
        imported targets so runs are idempotent."""
        mapping: dict[str, str] = {}
        try:
            targets = self.api.ai_target.list()
        except Exception as exc:  # noqa: BLE001
            self.logger.warning(f"Could not list existing AI targets: {exc}")
            return mapping
        for target in targets:
            ref = getattr(target, "asset_external_reference", None)
            asset_id = getattr(target, "asset_id", None)
            if ref and asset_id and str(ref).startswith("xtm-one:"):
                mapping[ref] = asset_id
        return mapping

    def _upsert(self, payload: dict, existing: dict[str, str]) -> None:
        ref = payload["asset_external_reference"]
        try:
            if ref in existing:
                self.api.ai_target.update(existing[ref], payload)
                self.logger.info(f"Updated AI target {ref}")
            else:
                self.api.ai_target.create(payload)
                self.logger.info(f"Created AI target {ref}")
        except Exception as exc:  # noqa: BLE001
            self.logger.error(f"Failed to upsert AI target {ref}: {exc}")

    def _process_message(self) -> None:
        try:
            agents = self.client.list_agents()
        except Exception as exc:  # noqa: BLE001
            self.logger.error(f"Could not fetch XTM One agents: {exc}")
            return

        existing = self._existing_targets()

        for agent in agents:
            if not self._agent_in_scope(agent):
                continue
            self._upsert(self._agent_payload(agent), existing)

        if self.include_bare_models:
            try:
                models = self.client.list_bare_models()
            except Exception as exc:  # noqa: BLE001
                self.logger.error(f"Could not fetch XTM One models: {exc}")
                models = []
            for model in models:
                self._upsert(self._model_payload(model), existing)


if __name__ == "__main__":
    OpenAEVXtmOne(configuration=ConfigLoader().to_daemon_config()).start()
