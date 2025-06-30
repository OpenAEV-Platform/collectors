import io
import mimetypes
import zipfile

import requests
from pyobas.helpers import OpenBASCollectorHelper, OpenBASConfigHelper


class OpenBASOpenBAS:
    def __init__(self):
        self.session = requests.Session()
        self.config = OpenBASConfigHelper(
            __file__,
            {
                # API information
                "openbas_url": {"env": "OPENBAS_URL", "file_path": ["openbas", "url"]},
                "openbas_token": {
                    "env": "OPENBAS_TOKEN",
                    "file_path": ["openbas", "token"],
                },
                # Config information
                "collector_id": {
                    "env": "COLLECTOR_ID",
                    "file_path": ["collector", "id"],
                },
                "collector_name": {
                    "env": "COLLECTOR_NAME",
                    "file_path": ["collector", "name"],
                    "default": "OpenBAS Datasets",
                },
                "collector_type": {
                    "env": "COLLECTOR_TYPE",
                    "file_path": ["collector", "type"],
                    "default": "openbas_openbas",
                },
                "collector_log_level": {
                    "env": "COLLECTOR_LOG_LEVEL",
                    "file_path": ["collector", "log_level"],
                    "default": "error",
                },
                "collector_period": {
                    "env": "COLLECTOR_PERIOD",
                    "file_path": ["collector", "period"],
                    "default": 604800,
                },
                # OpenBAS Datasets
                "openbas_generated_url_prefix": {
                    "env": "OPENBAS_URL_PREFIX",
                    "file_path": ["openbas", "url_prefix"],
                },
                "openbas_import_only_native": {
                    "env": "OPENBAS_IMPORT_ONLY_NATIVE",
                    "file_path": ["openbas", "import_only_native"],
                },
            },
        )
        self.helper = OpenBASCollectorHelper(
            self.config, "openbas/img/icon-openbas.png"
        )

    def _process_message(self) -> None:
        openbas_import_only_native = self.config.get_conf(
            "openbas_import_only_native",
            default=True,
        )
        openbas_url_prefix = self.config.get_conf(
            "openbas_url_prefix",
            default="https://raw.githubusercontent.com/OpenBAS-Platform/payloads/refs/heads/main/",
        )
        response = self.session.get(url=openbas_url_prefix + "manifest.json")
        payloads = response.json()
        payload_external_ids = []

        for payload in payloads:

            # Only native, continue
            if openbas_import_only_native and (
                "native_collection" not in payload or not payload["native_collection"]
            ):
                continue

            payload_information = payload.get("payload_information")
            self.helper.collector_logger.info(
                "Importing payload " + payload_information["payload_name"]
            )

            # Create tags
            tags_mapping = {}
            tags = payload.get("payload_tags", [])
            for tag in tags:
                new_tag = self.helper.api.tag.upsert(tag)
                tags_mapping[tag["tag_id"]] = new_tag["tag_id"]

            # Create attack patterns
            attack_patterns = payload.get("payload_attack_patterns", [])
            if len(attack_patterns) > 0:
                self.helper.api.attack_pattern.upsert(attack_patterns, True)

            # Create document
            new_document = None
            document = payload.get("payload_document", None)
            if document is not None and "document_path" in document:
                # Upload the document
                new_tags = []
                for tag_id in document.get("document_tags", []):
                    if tag_id in tags_mapping:
                        new_tags.append(tags_mapping[tag_id])
                document["document_tags"] = new_tags

                zip_url = openbas_url_prefix + document["document_path"]
                zip_response = self.session.get(zip_url)
                zip_response.raise_for_status()
                with io.BytesIO(zip_response.content) as zip_buffer:
                    with zipfile.ZipFile(zip_buffer) as z:
                        file_names = z.namelist()
                        if not file_names:
                            raise Exception(f"No file found in zip at {zip_url}")
                        file_name = file_names[0]
                        with z.open(file_name, pwd=b"infected") as unzipped_file:
                            file_content = unzipped_file.read()
                            mime_type, _ = mimetypes.guess_type(
                                document["document_name"]
                            )
                            if mime_type is None:
                                mime_type = "application/octet-stream"
                            file_handle = io.BytesIO(file_content)
                            file = (document["document_name"], file_handle, mime_type)
                            new_document = self.helper.api.document.upsert(
                                document=document, file=file
                            )

            # Upsert payload
            payload_information["payload_collector"] = self.helper.config.get(
                "collector_id"
            )

            new_tags = []
            for tag_id in payload_information.get("payload_tags", []):
                if tag_id in tags_mapping:
                    new_tags.append(tags_mapping[tag_id])
            payload_information["payload_tags"] = new_tags

            new_attack_patterns = []
            for attack_pattern in payload_information.get(
                "payload_attack_patterns", []
            ):
                new_attack_patterns.append(attack_pattern["attack_pattern_external_id"])
            payload_information["payload_attack_patterns"] = new_attack_patterns

            if "executable_file" in payload_information and new_document is not None:
                payload_information["executable_file"] = new_document["document_id"]
            elif "file_drop_file" in payload_information and new_document is not None:
                payload_information["file_drop_file"] = new_document["document_id"]

            self.helper.api.payload.upsert(payload_information)
            payload_external_ids.append(payload_information["payload_external_id"])
            self.helper.collector_logger.info(
                "Payload " + payload_information["payload_name"] + " imported"
            )

        self.helper.api.payload.deprecate(
            {
                "collector_id": self.helper.config.get("collector_id"),
                "payload_external_ids": payload_external_ids,
            }
        )

    # Start the main loop
    def start(self):
        period = self.config.get_conf(
            "collector_period", default=604800, is_number=True
        )  # 7 days
        self.helper.schedule(message_callback=self._process_message, delay=period)


if __name__ == "__main__":
    openBASAtomicRedTeam = OpenBASOpenBAS()
    openBASAtomicRedTeam.start()
