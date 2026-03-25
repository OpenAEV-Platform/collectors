import unittest
from unittest.mock import MagicMock

import src.services.trace_service as module


class TraceServiceTest(unittest.TestCase):
    def test_init_failure_config_missing(self):
        with self.assertRaises(module.HTTPLogwatcherValidationError):
            module.TraceService()

    def test_traceservice_minimal_init(self):
        config = MagicMock()

        trace_service = module.TraceService(
            config=config,
        )

        assert trace_service.config == config
