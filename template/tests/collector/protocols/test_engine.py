import unittest

import src.collector.protocols.engine as module


class CollectorEngineProtocolTest(unittest.TestCase):
    def test_following_collector_engine_protocol(self):
        """verify that a class following the protocol is seen as such"""

        class GoodCollectorEngine:
            def __init__(self, **kwargs):
                pass

            def configure_engine(self, config, batching=False):
                pass

            def run_engine(self):
                pass

        self.assertTrue(issubclass(GoodCollectorEngine, module.CollectorEngineProtocol))

    def test_not_following_collector_engine_protocol(self):
        """verify that a class not following the protocol is detected as such"""

        class BadCollectorEngine:
            def __init__(self, **kwargs):
                pass

            def configure_engine(self, config, batching=False):
                pass

            def start_engine(self):
                pass

        self.assertFalse(issubclass(BadCollectorEngine, module.CollectorEngineProtocol))
