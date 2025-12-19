import requests
from pyoaev.configuration import Configuration
from pyoaev.daemons import CollectorDaemon

from mitre_attack.configuration.config_loader import ConfigLoader

ENTERPRISE_ATTACK_URI = (
    "https://github.com/mitre/cti/raw/master/enterprise-attack/enterprise-attack.json"
)

class OpenAEVMitre(CollectorDaemon):
    def __init__(self,
                 configuration: Configuration,
        ):
        super().__init__(
            configuration=configuration,
            callback=self._process_message,
            collector_type="openaev_mitre_attack"
        )
        self.session = requests.Session()

    def _kill_chain_phases(self, tactics):
        kill_chain_name = "mitre-attack"
        kill_chain_phases = []
        for tactic in tactics:
            phase_stix_id = tactic.get("id")
            phase_shortname = tactic.get("x_mitre_shortname")
            phase_name = tactic.get("name")
            phase_description = tactic.get("description")
            phase_external_id = ""
            external_references = tactic.get("external_references")
            for external_reference in external_references:
                if external_reference.get("source_name") == "mitre-attack":
                    phase_external_id = external_reference.get("external_id")
            kill_chain_phase = {
                "phase_kill_chain_name": kill_chain_name,
                "phase_stix_id": phase_stix_id,
                "phase_external_id": phase_external_id,
                "phase_shortname": phase_shortname,
                "phase_name": phase_name,
                "phase_description": phase_description,
            }
            kill_chain_phases.append(kill_chain_phase)
        result = self.api.kill_chain_phase.upsert(kill_chain_phases)
        return result

    def _attack_patterns(self, attacks, kill_chain_phases, relationships):
        attack_patterns = []
        for attack in attacks:
            stix_id = attack.get("id")
            attack_pattern_name = attack.get("name")
            attack_pattern_description = attack.get("description")
            attack_pattern_platforms = attack.get("x_mitre_platforms", [])
            attack_pattern_permissions_required = attack.get(
                "x_mitre_permissions_required", []
            )
            attack_pattern_kill_chain_phases_short_names = list(
                map(
                    lambda chain: chain.get("phase_name"),
                    attack.get("kill_chain_phases", []),
                )
            )
            attack_pattern_external_id = ""
            external_references = attack.get("external_references")
            for external_reference in external_references:
                if external_reference.get("source_name") == "mitre-attack":
                    attack_pattern_external_id = external_reference.get("external_id")
            # Find a possible parent in relationships
            attack_pattern_parent = None
            for relationship in relationships:
                if relationship["source_ref"] == stix_id:  # subtechnique-of
                    attack_pattern_parent = relationship["target_ref"]
                    break
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
        # print(attack_patterns)
        self.api.attack_pattern.upsert(attack_patterns)

    def _process_message(self) -> None:
        response = self.session.get(url=ENTERPRISE_ATTACK_URI)

        self.logger.debug(
            str.format("Response headers: {}", response.headers)
        )
        self.logger.debug(
            str.format("Response raw: {}", response.text[:200])
        )

        enterprise_attack = response.json()
        objects = enterprise_attack.get("objects")
        tactics = []
        attack_patterns = []
        relationships = []
        # Generate items
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
        # Sync kill chain phases
        kill_chain_phases = self._kill_chain_phases(tactics)
        # Sync attack patterns
        self._attack_patterns(attack_patterns, kill_chain_phases, relationships)

if __name__ == "__main__":
    OpenAEVMitre(configuration=ConfigLoader().to_daemon_config()).start()

