import json_api_doc

from openaev.processors.common_processor import CommonProcessor


class JsonApiProcessor(CommonProcessor):
    def _process_payload(self, payload: dict) -> dict:
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

        return flat_payload
