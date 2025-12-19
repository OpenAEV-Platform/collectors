import os
import re

import requests
import yaml
from pyoaev.helpers import OpenAEVCollectorHelper, OpenAEVConfigHelper
from pyoaev.configuration import Configuration
from pyoaev.daemons import CollectorDaemon
from atomic_red_team.configuration.config_loader import ConfigLoader

ATOMIC_RED_TEAM_INDEX = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/Indexes/index.yaml"

# Ignore payloads copied and verified to OpenAEV Payloads Repository
IGNORED_PAYLOADS = [
    "aa6cb8c4-b582-4f8e-b677-37733914abda",
    "cab413d8-9e4a-4b8d-9b84-c985bd73a442",
    "78e95057-d429-4e66-8f82-0f060c1ac96f",
    "13f09b91-c953-438e-845b-b585e51cac9b",
    "17538258-5699-4ff1-92d1-5ac9b0dc21f5",
    "728eca7b-0444-4f6f-ac36-437e3d751dc0",
    "695eed40-e949-40e5-b306-b4031e4154bd",
    "99747561-ed8d-47f2-9c91-1e5fde1ed6e0",
    "114ccff9-ae6d-4547-9ead-4cd69f687306",
    "0315bdff-4178-47e9-81e4-f31a6d23f7e4",
    "02a91c34-8a5b-4bed-87af-501103eb5357",
    "dd4b4421-2e25-4593-90ae-7021947ad12e",
    "6aa58451-1121-4490-a8e9-1dada3f1c68c",
    "b854eb97-bf9b-45ab-a1b5-b94e4880c56b",
    "4ff64f0b-aaf2-4866-b39d-38d9791407cc",
]

PLATFORMS = {
    "windows": "Windows",
    "linux": "Linux",
    "macos": "MacOS",
    "azure-ad": "Windows",
    "office-365": "Windows",
    "containers": "Linux",
    "iaas:aws": ["Windows", "Linux", "MacOS"],
    "iaas:gcp": ["Windows", "Linux", "MacOS"],
    "iaas:azure": "Windows",
    "google-workspace": ["Windows", "Linux", "MacOS"],
}

ALL_ARCHITECTURES = "ALL_ARCHITECTURES"

EXECUTORS = {
    "powershell": "psh",
    "command_prompt": "cmd",
    "bash": "bash",
    "sh": "sh",
    "manual": "manual",
}

UNVERIFIED = "UNVERIFIED"

VERIFIED = "VERIFIED"

COMMUNITY = "COMMUNITY"


def flatten_chain(matrix):
    if matrix == []:
        return matrix
    if isinstance(matrix[0], list):
        return flatten_chain(matrix[0]) + flatten_chain(matrix[1:])
    return matrix[:1] + flatten_chain(matrix[1:])


def _normalize_path(path):
    return path.replace("\\", "/")


def get_argument_name_by_path(arguments, fullpath):
    file_name = os.path.basename(fullpath)

    for ar in arguments:
        default_value_file_name = os.path.basename(str(ar["default_value"]))
        if (
            isinstance(ar["default_value"], str)
            and file_name == default_value_file_name
            and "http" not in ar["default_value"]
        ):

            return ar["key"]

    path_without_prefix = fullpath.replace("PathToAtomicsFolder", "").replace("$", "")
    new_key = f"{file_name.replace('.', '_')}_atomicredteam_path"
    new_argument = {
        "type": "text",
        "key": new_key,
        "default_value": "./ExternalPayloads" + _normalize_path(path_without_prefix),
    }
    arguments.append(new_argument)

    return new_key


def handle_resources(platforms, prerequisites, fullpath, arg_name):
    file_name = os.path.basename(fullpath)
    path_without_prefix = fullpath.replace("PathToAtomicsFolder", "").replace("$", "")

    for pr in prerequisites:
        if file_name in pr["get_command"]:
            return

    if "Windows" in platforms:
        command_line = [
            'New-Item -Type Directory (split-path "#{'
            + arg_name
            + '}") -ErrorAction ignore | Out-Null',
            'Invoke-WebRequest "https://github.com/redcanaryco/atomic-red-team/raw/master/atomics'
            + _normalize_path(path_without_prefix)
            + '" -OutFile "#{'
            + arg_name
            + '}"',
        ]
        # On windows
        prerequisite_command = {
            "executor": "psh",
            "description": "",
            "get_command": "\n".join(command_line),
            "check_command": "if (Test-Path '#{"
            + arg_name
            + "}') {exit 0} else {exit 1}",
        }
        prerequisites.append(prerequisite_command)
    else:
        command_line = [
            'mkdir -p "$(dirname "#{' + arg_name + '}")"',
            'curl -L -o "#{'
            + arg_name
            + '}" "https://github.com/redcanaryco/atomic-red-team/raw/master/atomics'
            + _normalize_path(path_without_prefix)
            + '"',
        ]
        prerequisite_command = {
            "executor": "bash",
            "description": "",
            "get_command": "\n".join(command_line),
            "check_command": '[ -f "#{' + arg_name + '}" ] && exit 0 || exit 1',
        }
        prerequisites.append(prerequisite_command)

    return


def _catch_atomic_folder_paths(string_to_analyse, handle_match_callback):
    regex = re.compile(r'\s*(\$?PathToAtomicsFolder(?:\\[^\\ \n"]+)+)')
    matches = regex.findall(string_to_analyse)
    for match in matches:
        string_to_analyse = handle_match_callback(string_to_analyse, match)
    return string_to_analyse


def _format_command(string_to_analyse, arguments, platforms, prerequisites):
    def handle_match_callback(string, match):
        if os.path.basename(match) == "ExternalPayloads":
            return string
        else:
            arg_name = get_argument_name_by_path(arguments, match)
            handle_resources(platforms, prerequisites, match, arg_name)
            return string.replace(match, f"#{{{arg_name}}}")

    return _catch_atomic_folder_paths(string_to_analyse, handle_match_callback)


def _format_prerequisite(string_to_analyse, arguments):
    folder_name = ""
    arg_name = ""

    def handle_match_callback(string, match):
        nonlocal folder_name, arg_name
        if os.path.basename(match) == "ExternalPayloads":
            folder_name = match
            return string
        else:
            arg_name = get_argument_name_by_path(arguments, match)
            return string.replace(match, f"#{{{arg_name}}}")

    string_to_analyse = _catch_atomic_folder_paths(
        string_to_analyse, handle_match_callback
    )

    if folder_name:
        string_to_analyse = string_to_analyse.replace(
            folder_name, f"#{{{arg_name}}}/../"
        )

    return string_to_analyse


def _format_generic_command(string_to_analyse, arguments):
    def handle_match_callback(string, match):
        arg_name = get_argument_name_by_path(arguments, match)
        return string.replace(match, f"#{{{arg_name}}}")

    return (
        _catch_atomic_folder_paths(string_to_analyse, handle_match_callback)
        if string_to_analyse
        else string_to_analyse
    )


class OpenAEVAtomicRedTeam(CollectorDaemon):
    def __init__(self,
                 configuration: Configuration,
                 ):
        super().__init__(
            configuration=configuration,
            callback=self._process_message,
            collector_type="openaev_atomic_red_team"
        )
        self.session = requests.Session()

    def _create_or_get_tag(self, tag_name, tag_color="#6b7280"):
        """Create or get a tag and return its ID."""
        try:
            tag_data = {"tag_name": tag_name, "tag_color": tag_color}
            result = self.api.tag.upsert(tag_data)
            return result.get("tag_id")
        except Exception as e:
            self.logger.warning(
                f"Failed to upsert tag {tag_name}: {e}"
            )
            return None

    def _process_message(self) -> None:
        response = self.session.get(url=ATOMIC_RED_TEAM_INDEX)
        art_index = yaml.safe_load(response.text)
        payload_external_ids = []
        for kill_chain_phase in art_index:
            self.logger.info(
                "Importing kill chain phase " + kill_chain_phase
            )
            for attack_pattern in art_index[kill_chain_phase]:
                self.logger.info(
                    "Importing attack pattern " + attack_pattern
                )
                for atomic_test in art_index[kill_chain_phase][attack_pattern][
                    "atomic_tests"
                ]:
                    if atomic_test["auto_generated_guid"] in IGNORED_PAYLOADS:
                        continue
                    arguments = []
                    if (
                        "input_arguments" in atomic_test
                        and atomic_test["input_arguments"] is not None
                    ):
                        for input_argument in atomic_test["input_arguments"]:
                            atomic_input_argument = atomic_test["input_arguments"][
                                input_argument
                            ]
                            argument = {
                                "type": "text",
                                "key": input_argument,
                                "default_value": atomic_input_argument["default"],
                            }
                            arguments.append(argument)
                    prerequisites = []
                    if (
                        "dependencies" in atomic_test
                        and atomic_test["dependencies"] is not None
                    ):
                        for dependency in atomic_test["dependencies"]:
                            prerequisite = {
                                "executor": EXECUTORS[
                                    atomic_test.get(
                                        "dependency_executor_name",
                                        atomic_test["executor"]["name"],
                                    )
                                ],
                                "description": dependency["description"],
                                "get_command": _format_prerequisite(
                                    dependency["get_prereq_command"], arguments
                                ),
                                "check_command": _format_generic_command(
                                    dependency["prereq_command"], arguments
                                ),
                            }
                            prerequisites.append(prerequisite)
                    if (
                        "executor" in atomic_test
                        and "command" in atomic_test["executor"]
                        and atomic_test["executor"]["command"] is not None
                    ):
                        self.logger.info(
                            "Importing atomic test " + atomic_test["name"]
                        )
                        platforms = list(
                            dict.fromkeys(
                                flatten_chain(
                                    [
                                        PLATFORMS[platform]
                                        for platform in atomic_test[
                                            "supported_platforms"
                                        ]
                                    ]
                                )
                            )
                        )
                        platforms.sort()
                        cleanup_command = atomic_test["executor"].get("cleanup_command")
                        cleanup_command = (
                            None if cleanup_command == "" else cleanup_command
                        )

                        # Prepare tags for the payload
                        tag_ids = []
                        tag_colors = {
                            "source": "#ef4444",  # Red
                            "attack-pattern": "#3b82f6",  # Blue
                            "platform": "#10b981",  # Green
                            "executor": "#8b5cf6",  # Purple
                        }

                        # Add collector source tag
                        source_tag_name = "source:atomic-red-team"
                        source_tag_id = self._create_or_get_tag(
                            source_tag_name, tag_colors["source"]
                        )
                        if source_tag_id:
                            tag_ids.append(source_tag_id)

                        # Add attack pattern tag
                        if attack_pattern:
                            pattern_tag_name = f"technique:{attack_pattern.lower()}"
                            pattern_tag_id = self._create_or_get_tag(
                                pattern_tag_name, tag_colors["attack-pattern"]
                            )
                            if pattern_tag_id:
                                tag_ids.append(pattern_tag_id)

                        # Add platform tags
                        for platform in platforms:
                            platform_tag_name = f"platform:{platform.lower()}"
                            platform_tag_id = self._create_or_get_tag(
                                platform_tag_name, tag_colors["platform"]
                            )
                            if platform_tag_id:
                                tag_ids.append(platform_tag_id)

                        # Add executor tag
                        if atomic_test["executor"]["name"]:
                            executor_tag_name = (
                                f"executor:{atomic_test['executor']['name']}"
                            )
                            executor_tag_id = self._create_or_get_tag(
                                executor_tag_name, tag_colors["executor"]
                            )
                            if executor_tag_id:
                                tag_ids.append(executor_tag_id)

                        payload = {
                            "payload_source": COMMUNITY,
                            "payload_execution_arch": ALL_ARCHITECTURES,
                            "payload_status": UNVERIFIED,
                            "payload_external_id": atomic_test["auto_generated_guid"],
                            "payload_type": "Command",
                            "payload_collector": self._configuration.get("collector_id"),
                            "payload_name": atomic_test["name"],
                            "payload_description": atomic_test["description"],
                            "payload_platforms": platforms,
                            "payload_attack_patterns": [attack_pattern],
                            "payload_arguments": arguments,
                            "payload_expectations": ["PREVENTION", "DETECTION"],
                            "command_executor": EXECUTORS[
                                atomic_test["executor"]["name"]
                            ],
                            "command_content": _format_command(
                                atomic_test["executor"]["command"],
                                arguments,
                                platforms,
                                prerequisites,
                            ),
                            "payload_cleanup_command": _format_generic_command(
                                cleanup_command, arguments
                            ),
                            "payload_cleanup_executor": (
                                EXECUTORS[atomic_test["executor"]["name"]]
                                if cleanup_command
                                else None
                            ),
                            "payload_elevation_required": atomic_test["executor"].get(
                                "elevation_required", False
                            ),
                            "payload_prerequisites": prerequisites,
                        }

                        # Add tags if we have any
                        if tag_ids:
                            payload["payload_tags"] = tag_ids

                        self.api.payload.upsert(payload)
                        payload_external_ids.append(payload["payload_external_id"])
        self.api.payload.deprecate(
            {
                "collector_id": self.config.get("collector_id"),
                "payload_external_ids": payload_external_ids,
            }
        )

if __name__ == "__main__":
    OpenAEVAtomicRedTeam(configuration=ConfigLoader().to_daemon_config()).start()
