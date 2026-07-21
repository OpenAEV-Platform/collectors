from openaev.processors.common_processor import CommonProcessor


class JsonFlatProcessor(CommonProcessor):
    def _process_payload(self, payload: dict) -> dict:
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

        return payload_information
