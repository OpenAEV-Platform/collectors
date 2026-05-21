import unittest
from pathlib import Path
from unittest.mock import MagicMock

import orjson

import openaev.openaev_openaev as module

daemon_config_data = {
    "openaev_url": "http://fake.url",
    "openaev_token": "my_awesome_token",
    "openaev_url_prefix": "https://raw.githubusercontent.com/OpenAEV-Platform/payloads/refs/heads/main/",
    "collector_id": "collector-id",
}
old_format_path = Path("./tests/functional/old_format.json")
new_format_path = Path("./tests/functional/new_format.json")


def fake_upsert_tag(data):
    return {"tag_id": f"id-{data.get('tag_name')}"}


class TestProcessingFunctions(unittest.TestCase):
    def test_compare_process_results(self):
        _configuration = daemon_config_data
        api = MagicMock()
        api.tag.upsert.side_effect = fake_upsert_tag
        session = MagicMock()

        collector = module.OpenAEVOpenAEV(_configuration)
        collector.api = api
        collector.session = session

        old_payload = orjson.loads(old_format_path.read_bytes())
        new_payload = orjson.loads(new_format_path.read_bytes())

        old_payload_processed = collector._process_jsonflat_payload(old_payload)
        new_payload_processed = collector._process_jsonapi_payload(new_payload)

        self.assertTrue(
            all(
                key in new_payload_processed
                for key in old_payload_processed
                if old_payload_processed[key]
            )
        )
        self.assertTrue(
            all(
                key in old_payload_processed
                for key in new_payload_processed
                if new_payload_processed[key]
            )
        )

        self.assertTrue(
            all(
                type(old_payload_processed[key]) == type(new_payload_processed[key])
                for key in old_payload_processed
                if old_payload_processed[key]
            )
        )
        self.assertTrue(
            all(
                type(old_payload_processed[key]) == type(new_payload_processed[key])
                for key in new_payload_processed
                if new_payload_processed[key]
            )
        )

        exclusion_list = ["payload_created_at", "payload_updated_at"]
        for key in old_payload_processed:
            if old_payload_processed[key] and key not in exclusion_list:
                if isinstance(old_payload_processed[key], dict):
                    self.assertEqual(
                        old_payload_processed[key], new_payload_processed[key]
                    )
                elif isinstance(old_payload_processed[key], list):
                    try:
                        self.assertEqual(
                            sorted(old_payload_processed[key]),
                            sorted(new_payload_processed[key]),
                        )
                    except TypeError:
                        self.assertTrue(
                            all(
                                element in new_payload_processed[key]
                                for element in old_payload_processed[key]
                            )
                        )
                        self.assertTrue(
                            all(
                                element in old_payload_processed[key]
                                for element in new_payload_processed[key]
                            )
                        )
                else:
                    self.assertEqual(
                        old_payload_processed[key], new_payload_processed[key]
                    )
        for key in new_payload_processed:
            if new_payload_processed[key] and key not in exclusion_list:
                if isinstance(new_payload_processed[key], dict):
                    self.assertEqual(
                        old_payload_processed[key], new_payload_processed[key]
                    )
                elif isinstance(new_payload_processed[key], list):
                    try:
                        self.assertEqual(
                            sorted(old_payload_processed[key]),
                            sorted(new_payload_processed[key]),
                        )
                    except TypeError:
                        self.assertTrue(
                            all(
                                element in new_payload_processed[key]
                                for element in old_payload_processed[key]
                            )
                        )
                        self.assertTrue(
                            all(
                                element in old_payload_processed[key]
                                for element in new_payload_processed[key]
                            )
                        )
                else:
                    self.assertEqual(
                        old_payload_processed[key], new_payload_processed[key]
                    )
