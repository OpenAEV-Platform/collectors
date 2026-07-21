import unittest
from unittest.mock import MagicMock, patch, sentinel

import openaev.processors .common_processor as module


@patch.object(module, "requests")
class TestCommonProcessor(unittest.TestCase):
    def test_common_processor_init(self, m_requests):
        api = MagicMock()
        logger = MagicMock()
        payload_path = MagicMock()
        github_crawler = MagicMock()

        cprocessor = module.CommonProcessor(
            api=api,
            logger=logger,
            payload_path=payload_path,
            github_crawler=github_crawler
        )

        self.assertEqual(cprocessor.api, api)
        self.assertEqual(cprocessor.logger, logger)
        self.assertEqual(cprocessor.payload_path, payload_path)
        self.assertEqual(cprocessor.github_crawler, github_crawler)
        self.assertEqual(cprocessor.session, m_requests.Session.return_value)

    def test_common_processor_create_or_get_tag(self, m_requests):
        api = MagicMock()
        logger = MagicMock()
        payload_path = MagicMock()
        github_crawler = MagicMock()

        cprocessor = module.CommonProcessor(
            api=api,
            logger=logger,
            payload_path=payload_path,
            github_crawler=github_crawler
        )

        tag_name = "my-tag-name"
        tag_color = "#deadad"

        cprocessor._create_or_get_tag(tag_name, tag_color)
        api.tag.upsert.return_value = {"tag_id": sentinel.tag_id}

        api.tag.upsert.assert_called_with({"tag_name": tag_name, "tag_color": tag_color})
