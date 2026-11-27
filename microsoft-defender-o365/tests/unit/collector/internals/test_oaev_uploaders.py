import unittest
from unittest.mock import MagicMock

import src.collector.internals.oaev_uploaders as module


class TestExpectationUploaderErrorGuard(unittest.TestCase):
    def setUp(self):
        self.expectation_uploader = module.ExpectationUploader(
            oaev_api=MagicMock(), collector_id="1234abcd"
        )

    def test_result_carrying_an_error_is_never_bulked(self):
        # an error is not a verdict: never bulked as "Not Detected" (collectors#723)
        errored = MagicMock()
        errored.expectation_id = "1"
        errored.expectation = MagicMock()
        errored.error_message = "graph 503"
        genuine = MagicMock()
        genuine.expectation_id = "2"
        genuine.expectation = MagicMock()
        genuine.error_message = None

        bulked_data, skipped_count = (
            self.expectation_uploader.expectation_prepare_bulk_data([errored, genuine])
        )

        self.assertEqual(
            bulked_data,
            {
                "2": {
                    "collector_id": "1234abcd",
                    "result": genuine.to_result_text.return_value,
                    "is_success": genuine.is_valid,
                }
            },
        )
        self.assertEqual(skipped_count, 1)


if __name__ == "__main__":
    unittest.main()
