import io
import mimetypes
import zipfile

import requests
from pyoaev.helpers import OpenAEVCollectorHelper, OpenAEVConfigHelper
from pyoaev.configuration import Configuration
from pyoaev.daemons import CollectorDaemon
from openaev.configuration.config_loader import ConfigLoader


class OpenAEVOpenAEV(CollectorDaemon):
    def __init__(self,
            configuration: Configuration,
        ):
        super().__init__(
            configuration=configuration,
            callback=self._process_message,
            collector_type="openaev_openaev",
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
        openaev_import_only_native = self._configuration.get(
            "openaev_import_only_native"
        )
        openaev_url_prefix = self._configuration.get(
            "openaev_url_prefix"
        )
        response = self.session.get(url=openaev_url_prefix + "manifest.json")
        payloads = response.json()
        payload_external_ids = []

        for payload in payloads:

            # Only native, continue
            if openaev_import_only_native and (
                "native_collection" not in payload or not payload["native_collection"]
            ):
                continue

            payload_information = payload.get("payload_information")
            self.logger.info(
                "Importing payload " + payload_information["payload_name"]
            )

            # Create tags
            tags_mapping = {}
            tags = payload.get("payload_tags", [])
            for tag in tags:
                new_tag = self.api.tag.upsert(tag)
                tags_mapping[tag["tag_id"]] = new_tag["tag_id"]

            # Create attack patterns
            attack_patterns = payload.get("payload_attack_patterns", [])
            if len(attack_patterns) > 0:
                self.api.attack_pattern.upsert(attack_patterns, True)

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

                zip_url = openaev_url_prefix + document["document_path"]
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
                            new_document = self.api.document.upsert(
                                document=document, file=file
                            )

            # Upsert payload
            payload_information["payload_collector"] = self._configuration.get(
                "collector_id"
            )

            new_tags = []
            for tag_id in payload_information.get("payload_tags", []):
                if tag_id in tags_mapping:
                    new_tags.append(tags_mapping[tag_id])

            # Add collector source tag
            source_tag_name = "source:openaev-datasets"
            source_tag_id = self._create_or_get_tag(source_tag_name, "#ef4444")  # Red
            if source_tag_id:
                new_tags.append(source_tag_id)

            # Add native/community tag if applicable
            if payload.get("native_collection", False):
                native_tag_name = "type:native"
                native_tag_id = self._create_or_get_tag(
                    native_tag_name, "#10b981"
                )  # Green
                if native_tag_id:
                    new_tags.append(native_tag_id)

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

            self.api.payload.upsert(payload_information)
            payload_external_ids.append(payload_information["payload_external_id"])
            self.logger.info(
                "Payload " + payload_information["payload_name"] + " imported"
            )

        self.api.payload.deprecate(
            {
                "collector_id": self._configuration.get("collector_id"),
                "payload_external_ids": payload_external_ids,
            }
        )

if __name__ == "__main__":
    OpenAEVOpenAEV(configuration=ConfigLoader().to_daemon_config()).start()
