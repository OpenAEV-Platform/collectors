import logging
import time

import requests
from mitre_atlas.configuration.config_loader import ConfigLoader
from pyoaev.configuration import Configuration
from pyoaev.daemons import CollectorDaemon
from pyoaev.exceptions import OpenAEVUpdateError

# MITRE ATLAS (Adversarial Threat Landscape for AI Systems) STIX 2.1 bundle. ATLAS publishes an
# ATT&CK-compatible STIX representation (x-mitre-tactic objects, attack-pattern objects with
# kill_chain_phases, and subtechnique-of relationships) so the same ingestion logic as the
# mitre-attack collector applies - only the kill chain name and source name differ.
DEFAULT_ATLAS_STIX_URI = "https://raw.githubusercontent.com/mitre-atlas/atlas-navigator-data/main/dist/stix-atlas.json"

KILL_CHAIN_NAME = "mitre-atlas"
ATLAS_SOURCE_NAME = "mitre-atlas"

# Canonical ATLAS matrix tactic order, keyed by tactic short name. Both the current "ai-" and the
# legacy "ml-" short names are mapped so ordering is stable across ATLAS releases. Sent as
# phase_order so the platform renders the ATLAS matrix left-to-right in the canonical sequence.
ATLAS_TACTIC_ORDER = {
    "reconnaissance": 0,
    "resource-development": 1,
    "initial-access": 2,
    "ai-model-access": 3,
    "ml-model-access": 3,
    "execution": 4,
    "persistence": 5,
    "privilege-escalation": 6,
    "defense-evasion": 7,
    "credential-access": 8,
    "discovery": 9,
    "lateral-movement": 10,
    "collection": 11,
    "ai-attack-staging": 12,
    "ml-attack-staging": 12,
    "command-and-control": 13,
    "exfiltration": 14,
    "impact": 15,
}

# Tactics absent from ATLAS_TACTIC_ORDER (e.g. introduced by a future ATLAS release) are
# ordered after all known tactics instead of at the front (order 0), so the canonical
# ordering of the known phases is preserved.
UNKNOWN_TACTIC_ORDER = max(ATLAS_TACTIC_ORDER.values()) + 1

# The platform answers 409 while another attack pattern upsert runs for the tenant, and
# when a concurrent kill chain phase or attack pattern write wins a database race
CONFLICT_MAX_ATTEMPTS = 5
# Doubled after each attempt: 10, 20, 40 then 80 seconds
CONFLICT_RETRY_BASE_DELAY_SECONDS = 10


class OpenAEVAtlas(CollectorDaemon):
    def __init__(
        self,
        configuration: Configuration,
    ):
        super().__init__(
            configuration=configuration,
            callback=self._process_message,
            collector_type="openaev_mitre_atlas",
        )
        self.session = requests.Session()
        self.stix_url = (
            self._configuration.get("collector_atlas_stix_url")
            or DEFAULT_ATLAS_STIX_URI
        )

    def _kill_chain_phases(self, tactics):
        kill_chain_phases = []
        for tactic in tactics:
            phase_stix_id = tactic.get("id")
            phase_shortname = tactic.get("x_mitre_shortname")
            phase_name = tactic.get("name")
            phase_description = tactic.get("description")
            phase_external_id = ""
            for external_reference in tactic.get("external_references", []):
                if external_reference.get("source_name") == ATLAS_SOURCE_NAME:
                    phase_external_id = external_reference.get("external_id")
            kill_chain_phase = {
                "phase_kill_chain_name": KILL_CHAIN_NAME,
                "phase_stix_id": phase_stix_id,
                "phase_external_id": phase_external_id,
                "phase_shortname": phase_shortname,
                "phase_name": phase_name,
                "phase_description": phase_description,
                "phase_order": ATLAS_TACTIC_ORDER.get(
                    phase_shortname, UNKNOWN_TACTIC_ORDER
                ),
            }
            kill_chain_phases.append(kill_chain_phase)
        return self._upsert(self.api.kill_chain_phase.upsert, kill_chain_phases)

    def _attack_patterns(self, attacks, kill_chain_phases, relationships):
        # Pre-index subtechnique-of relationships (source -> parent target) so parent
        # resolution is O(1) per attack pattern instead of scanning the full list.
        parent_by_source = {
            relationship["source_ref"]: relationship["target_ref"]
            for relationship in relationships
        }
        attack_patterns = []
        for attack in attacks:
            stix_id = attack.get("id")
            attack_pattern_name = attack.get("name")
            attack_pattern_description = attack.get("description")
            attack_pattern_platforms = attack.get("x_mitre_platforms", [])
            attack_pattern_permissions_required = attack.get(
                "x_mitre_permissions_required", []
            )
            attack_pattern_kill_chain_phases_short_names = [
                chain.get("phase_name")
                for chain in attack.get("kill_chain_phases", [])
                if chain.get("kill_chain_name") == KILL_CHAIN_NAME
            ]
            attack_pattern_external_id = ""
            for external_reference in attack.get("external_references", []):
                if external_reference.get("source_name") == ATLAS_SOURCE_NAME:
                    attack_pattern_external_id = external_reference.get("external_id")
            # Resolve a possible parent (sub-technique -> parent technique).
            attack_pattern_parent = parent_by_source.get(stix_id)
            attack_pattern_kill_chain_phases_ids = [
                x.get("phase_id")
                for x in kill_chain_phases
                if x.get("phase_shortname")
                in attack_pattern_kill_chain_phases_short_names
            ]
            attack_pattern = {
                "attack_pattern_name": attack_pattern_name,
                "attack_pattern_stix_id": stix_id,
                "attack_pattern_external_id": attack_pattern_external_id,
                "attack_pattern_description": attack_pattern_description,
                "attack_pattern_platforms": attack_pattern_platforms,
                "attack_pattern_permissions_required": attack_pattern_permissions_required,
                "attack_pattern_kill_chain_phases": attack_pattern_kill_chain_phases_ids,
                "attack_pattern_parent": attack_pattern_parent,
            }
            attack_patterns.append(attack_pattern)
        # Parents first: the platform resolves a sub-technique's parent by STIX id
        # and each batch is a separate transaction
        attack_patterns.sort(key=lambda ap: ap["attack_pattern_parent"] is not None)
        batch_size = self._configuration.get("collector_batch_size")
        if not batch_size:  # 0 sends every attack pattern in one call
            batch_size = max(len(attack_patterns), 1)
        for start in range(0, len(attack_patterns), batch_size):
            self._upsert(
                self.api.attack_pattern.upsert,
                attack_patterns[start : start + batch_size],
            )

    def _upsert(self, upsert, items):
        for attempt in range(1, CONFLICT_MAX_ATTEMPTS + 1):
            try:
                return upsert(items)
            except OpenAEVUpdateError as err:
                if err.response_code != 409 or attempt == CONFLICT_MAX_ATTEMPTS:
                    raise
                delay = CONFLICT_RETRY_BASE_DELAY_SECONDS * 2 ** (attempt - 1)
                self.logger.warning(
                    f"OpenAEV answered 409 (conflict with a concurrent import), "
                    f"retrying in {delay} seconds "
                    f"(attempt {attempt}/{CONFLICT_MAX_ATTEMPTS})"
                )
                time.sleep(delay)

    def _process_message(self) -> None:
        response = self.session.get(url=self.stix_url, timeout=60)
        response.raise_for_status()
        # response.text decodes the entire (large) STIX bundle, so only do the
        # debug formatting/body decode when DEBUG logging is actually enabled.
        if self.logger.local_logger.isEnabledFor(logging.DEBUG):
            self.logger.debug(str.format("Response headers: {}", response.headers))
            self.logger.debug(str.format("Response raw: {}", response.text[:200]))

        atlas = response.json()
        objects = atlas.get("objects", [])
        tactics = []
        attack_patterns = []
        relationships = []
        for item in objects:
            object_type = item.get("type")
            if object_type == "attack-pattern" and not item.get("revoked"):
                attack_patterns.append(item)
            if object_type == "x-mitre-tactic":
                tactics.append(item)
            if (
                object_type == "relationship"
                and item.get("relationship_type") == "subtechnique-of"
            ):
                relationships.append(item)
        # Sync kill chain phases (ATLAS tactics) first so techniques can reference them
        kill_chain_phases = self._kill_chain_phases(tactics)
        # Sync attack patterns (ATLAS techniques and sub-techniques)
        self._attack_patterns(attack_patterns, kill_chain_phases, relationships)


def main():
    OpenAEVAtlas(configuration=ConfigLoader().to_daemon_config()).start()
