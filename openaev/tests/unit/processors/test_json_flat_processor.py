import unittest
from unittest.mock import MagicMock, patch, sentinel

import openaev.processors.json_flat_processor as module


class TestJsonFlatProcessor(unittest.TestCase):
    @patch.object(
        module.JsonFlatProcessor, "_apply_default_expected_security_platforms"
    )
    @patch.object(module.JsonFlatProcessor, "_process_document")
    @patch.object(module.JsonFlatProcessor, "_process_payload_attack_patterns")
    @patch.object(module.JsonFlatProcessor, "_process_payload_tags")
    def test_json_flat_processor_process_payload(
        self,
        m_process_payload_tags,
        m_process_payload_attack_patterns,
        m_process_document,
        m_apply_default_expected_security_platforms,
    ):
        api = MagicMock()
        logger = MagicMock()
        payload_path = "test/payload.json"
        github_crawler = MagicMock()

        jflatprocessor = module.JsonFlatProcessor(
            api=api,
            logger=logger,
            payload_path=payload_path,
            github_crawler=github_crawler,
        )

        payload_information = {
            "payload_external_id": sentinel.payload_external_id,
            "payload_name": "payload name",
            "executable_file": MagicMock(),
        }
        payload = {
            "payload_information": payload_information,
        }
        tags_mapping = MagicMock()
        new_tags = MagicMock()
        m_process_payload_tags.return_value = tags_mapping, new_tags
        payload_document = MagicMock()
        new_document = {
            "document_id": "my-document-uuid",
        }
        m_process_document.return_value = payload_document, new_document

        output_payload = jflatprocessor._process_payload(payload)

        logger.info.assert_called_with("Importing payload payload name")
        m_process_payload_tags.assert_called_with(payload)
        self.assertEqual(output_payload["payload_tags"], new_tags)
        m_process_payload_attack_patterns.assert_called_with(payload)
        self.assertEqual(
            output_payload["payload_attack_patterns"],
            m_process_payload_attack_patterns.return_value,
        )
        m_process_document.assert_called_with(payload, "payload_document", tags_mapping)
        self.assertEqual(
            output_payload["executable_file"],
            new_document["document_id"],
        )
        m_apply_default_expected_security_platforms.assert_called_with(
            payload_information
        )
