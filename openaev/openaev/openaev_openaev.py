import io
import mimetypes
import zipfile

import json_api_doc
import requests
from pyoaev.configuration import Configuration
from pyoaev.daemons import CollectorDaemon

from openaev.configuration.config_loader import ConfigLoader


class OpenAEVOpenAEV(CollectorDaemon):
    def __init__(
        self,
        configuration: Configuration,
    ):
        super().__init__(
            configuration=configuration,
            callback=self._process_message,
            collector_type="openaev_openaev",
        )
        self.session = requests.Session()
        self.openaev_url_prefix = self._configuration.get("openaev_url_prefix")

    def _create_or_get_tag(self, tag_name, tag_color="#6b7280"):
        """Create or get a tag and return its ID."""
        try:
            tag_data = {"tag_name": tag_name, "tag_color": tag_color}
            result = self.api.tag.upsert(tag_data)
            return result.get("tag_id")
        except Exception as e:
            self.logger.warning(f"Failed to upsert tag {tag_name}: {e}")
            return None

    def _process_payload_tags(self, payload):
        tags_mapping = {}
        payload_tags = payload.get("payload_tags", [])
        for tag in payload_tags:
            tag = {
                key: value
                for key, value in tag.items()
                if key in ["tag_id", "tag_name", "tag_color"]
            }
            new_tag = self.api.tag.upsert(tag)
            tags_mapping[tag["tag_id"]] = new_tag["tag_id"]

        new_tags = [
            tags_mapping[tag["tag_id"]]
            for tag in payload_tags
            if tag["tag_id"] in tags_mapping
        ]

        # Add collector source tag
        source_tag_name = "source:openaev-datasets"
        source_tag_id = self._create_or_get_tag(source_tag_name, "#ef4444")  # Red
        if source_tag_id:
            new_tags.append(source_tag_id)

        # Add native/community tag if applicable
        if payload.get("native_collection", False):
            native_tag_name = "type:native"
            native_tag_id = self._create_or_get_tag(native_tag_name, "#10b981")  # Green
            if native_tag_id:
                new_tags.append(native_tag_id)

        return tags_mapping, new_tags

    def _process_payload_attack_patterns(self, payload):
        attack_patterns = payload.get("payload_attack_patterns", [])

        for idx in range(len(attack_patterns)):
            if "id" in attack_patterns[idx]:
                del attack_patterns[idx]["id"]
            if "type" in attack_patterns[idx]:
                del attack_patterns[idx]["type"]

        if len(attack_patterns) > 0:
            self.api.attack_pattern.upsert(attack_patterns, True)

        attack_patterns = [
            attack["attack_pattern_external_id"] for attack in attack_patterns
        ]
        return attack_patterns

    def _process_document(self, payload, document_key, tags_mapping):
        new_document = None
        payload_document = payload.get(document_key, {})

        if "id" in payload_document:
            del payload_document["id"]
        if "type" in payload_document:
            del payload_document["type"]
        if payload_document.get("document_tags", []):
            if payload_document["document_tags"] and isinstance(
                payload_document["document_tags"][0], dict
            ):
                payload_document["document_tags"] = [
                    tag["tag_id"] for tag in payload_document.get("document_tags", [])
                ]

        if payload_document.get("document_path", ""):
            # Upload the document
            payload_document["document_tags"] = [
                tags_mapping[tag_id]
                for tag_id in payload_document.get("document_tags", [])
                if tag_id in tags_mapping
            ]

            zip_url = self.openaev_url_prefix + payload_document["document_path"]
            zip_response = self.session.get(zip_url)
            zip_response.raise_for_status()
            # could using ziphyr be more efficient here?
            with io.BytesIO(zip_response.content) as zip_buffer:
                with zipfile.ZipFile(zip_buffer) as z:
                    file_names = z.namelist()
                    if not file_names:
                        raise Exception(f"No file found in zip at {zip_url}")
                    file_name = file_names[0]
                    with z.open(file_name, pwd=b"infected") as unzipped_file:
                        file_content = unzipped_file.read()
                        mime_type, _ = mimetypes.guess_type(
                            payload_document["document_name"]
                        )
                        if mime_type is None:
                            mime_type = "application/octet-stream"
                        file_handle = io.BytesIO(file_content)
                        file = (
                            payload_document["document_name"],
                            file_handle,
                            mime_type,
                        )
                        new_document = self.api.document.upsert(
                            document=payload_document, file=file
                        )

        return payload_document, new_document

    def _is_valid_json_api(self, payload):
        """check if the JSON data is in the JSON:API format"""
        return "data" in payload.keys()

    def _is_valid_json_flat(self, payload):
        """check if the JSON data is in the legacy flat JSON payload format"""
        return "payload_information" in payload.keys()

    def _process_jsonapi_payload(self, payload):
        """processing a single JSON:API payload"""
        flat_payload = json_api_doc.deserialize(payload)
        self.logger.info("Importing payload " + flat_payload["payload_name"])

        # Create tags
        tags_mapping, new_tags = self._process_payload_tags(flat_payload)
        flat_payload["payload_tags"] = new_tags

        # Create attack patterns
        payload_attack_patterns = self._process_payload_attack_patterns(flat_payload)
        flat_payload["payload_attack_patterns"] = payload_attack_patterns

        # Create document
        file_key = "payload_document"
        file_lookup = [
            key
            for key in flat_payload
            if isinstance(flat_payload[key], dict)
            and flat_payload[key].get("type") == "documents"
        ]
        if len(file_lookup) > 1:
            self.logger.warning(
                "Warning, more than one file detected as attachment, fallback to first found"
            )
        if file_lookup:
            file_key = file_lookup[0]

        payload_document, new_document = self._process_document(
            flat_payload, file_key, tags_mapping
        )

        if file_lookup:
            del flat_payload[file_key]
        flat_payload["payload_document"] = payload_document

        for key in ["executable_file", "file_drop_file"]:
            if key in flat_payload and new_document is not None:
                flat_payload[key] = new_document["document_id"]

        # align flat JSON:API with legacy flat JSON (domains)
        flat_payload["payload_domains"] = [
            {
                "domain_name": domain["domain_name"],
                "domain_color": domain["domain_color"],
            }
            for domain in flat_payload.get("payload_domains", [])
        ]

        # align flat JSON:API with legacy flat JSON (external ID)
        if (
            "payload_external_id" not in flat_payload
            or flat_payload["payload_external_id"] is None
        ):
            flat_payload["payload_external_id"] = flat_payload["payload_id"]

        # align flat JSON:API with legacy flat JSON (leftovers)
        for key in [
            "id",
            "type",
            "payload_id",
            "payload_collector",
            "payload_collector_type",
        ]:
            if key in flat_payload:
                del flat_payload[key]

        # Upsert payload
        flat_payload["payload_collector"] = self._configuration.get("collector_id")
        self.api.payload.upsert(flat_payload)
        self.logger.info("Payload " + flat_payload["payload_name"] + " imported")

        return flat_payload["payload_external_id"]

    def _process_jsonflat_payload(self, payload):
        """processing a single legacy flat JSON payload"""
        payload_information = payload.get("payload_information")
        self.logger.info("Importing payload " + payload_information["payload_name"])

        # Create tags
        tags_mapping, new_tags = self._process_payload_tags(payload)
        payload_information["payload_tags"] = new_tags

        # Create attack patterns
        payload_attack_patterns = self._process_payload_attack_patterns(payload)
        payload_information["payload_attack_patterns"] = payload_attack_patterns

        # Create document
        file_key = "payload_document"
        payload_document, new_document = self._process_document(
            payload, file_key, tags_mapping
        )

        for key in ["executable_file", "file_drop_file"]:
            if key in payload_information and new_document is not None:
                payload_information[key] = new_document["document_id"]

        # Upsert payload
        payload_information["payload_collector"] = self._configuration.get(
            "collector_id"
        )
        self.api.payload.upsert(payload_information)
        self.logger.info("Payload " + payload_information["payload_name"] + " imported")

        return payload_information["payload_external_id"]

    def _process_single_payload(self, payload):
        if self._is_valid_json_api(payload):  # new format
            return self._process_jsonapi_payload(payload)
        if self._is_valid_json_flat(payload):  # legacy format
            return self._process_jsonflat_payload(payload)

        self.logger.warning(
            "Skipping a payload that didn't match JSON:API format nor flat legacy format"
        )  # should it be a logger.error / a raise Exception?
        return

    def _process_message(self) -> None:
        openaev_import_only_native = self._configuration.get(
            "openaev_import_only_native"
        )
        # unsure if the prefix needs to be refreshed to follow hot changes in the configuration
        self.openaev_url_prefix = self._configuration.get("openaev_url_prefix")
        # TODO cookie-less session + retry mechanism + url builder using urllib.urlparse
        response = self.session.get(url=self.openaev_url_prefix + "manifest.json")
        payloads = response.json()
        payload_external_ids = []

        for payload in payloads:
            # Only native, continue
            if openaev_import_only_native and (
                "native_collection" not in payload or not payload["native_collection"]
            ):
                continue

            payload_external_id = self._process_single_payload(payload)
            payload_external_ids.append(payload_external_id)

        self.api.payload.deprecate(
            {
                "collector_id": self._configuration.get("collector_id"),
                "payload_external_ids": payload_external_ids,
            }
        )


if __name__ == "__main__":
    OpenAEVOpenAEV(configuration=ConfigLoader().to_daemon_config()).start()
