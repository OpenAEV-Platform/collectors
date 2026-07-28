import unittest
from unittest.mock import MagicMock, patch

import openaev.processors.json_api_processor as module


class TestJsonApiProcessor(unittest.TestCase):
    @patch.object(module.JsonApiProcessor, "_apply_default_expected_security_platforms")
    @patch.object(module.JsonApiProcessor, "_process_document")
    @patch.object(module.JsonApiProcessor, "_process_payload_attack_patterns")
    @patch.object(module.JsonApiProcessor, "_process_payload_tags")
    @patch.object(module, "json_api_doc")
    def test_json_api_processor_process_payload(
        self,
        m_json_api_doc,
        m_process_payload_tags,
        m_process_payload_attack_patterns,
        m_process_document,
        m_apply_default_expected_security_platforms,
    ):
        api = MagicMock()
        logger = MagicMock()
        payload_path = "test/payload.json"
        github_crawler = MagicMock()

        japiprocessor = module.JsonApiProcessor(
            api=api,
            logger=logger,
            payload_path=payload_path,
            github_crawler=github_crawler,
        )

        payload = MagicMock()
        flat_payload = {
            "id": "json-api-uuid",
            "type": "payloads",
            "payload_id": "payload-uuid",
            "payload_name": "payload name",
            "dropper": {"type": "documents"},
            "payload_domains": [
                {
                    "domain_name": "domain name",
                    "domain_color": "domain color",
                    "type": "domains",
                    "id": "domain-uuid",
                }
            ],
            "file_drop_file": MagicMock(),
        }
        m_json_api_doc.deserialize.return_value = flat_payload
        tags_mapping = MagicMock()
        new_tags = MagicMock()
        m_process_payload_tags.return_value = tags_mapping, new_tags
        payload_document = MagicMock()
        new_document = {
            "document_id": "my-document-uuid",
        }
        m_process_document.return_value = payload_document, new_document

        output_payload = japiprocessor._process_payload(payload)

        m_json_api_doc.deserialize.assert_called_with(payload)
        logger.info.assert_called_with("Importing payload payload name")
        m_process_payload_tags.assert_called_with(flat_payload)
        self.assertEqual(output_payload["payload_tags"], new_tags)
        m_process_payload_attack_patterns.assert_called_with(flat_payload)
        self.assertEqual(
            output_payload["payload_attack_patterns"],
            m_process_payload_attack_patterns.return_value,
        )
        m_process_document.assert_called_with(flat_payload, "dropper", tags_mapping)
        self.assertIsNone(output_payload.get("dropper"))
        self.assertEqual(output_payload["payload_document"], payload_document)
        self.assertEqual(output_payload["file_drop_file"], new_document["document_id"])
        self.assertEqual(
            output_payload["payload_domains"],
            [{"domain_name": "domain name", "domain_color": "domain color"}],
        )
        self.assertIsNone(output_payload.get("id"))
        self.assertIsNone(output_payload.get("type"))
        self.assertIsNone(output_payload.get("payload_id"))
        m_apply_default_expected_security_platforms.assert_called_with(flat_payload)
