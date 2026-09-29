import unittest
from unittest.mock import MagicMock

import src.collector.protocols.source_data as module


class SourceDataProtocolTest(unittest.TestCase):
    def test_following_source_data_protocol(self):
        """verify that a class following the protocol is seen as such"""

        class GoodSourceData:
            def to_oaev_data(self):
                return MagicMock()

            def to_traces_data(self):
                return MagicMock()

            def is_prevented(self):
                return False

            def is_detected(self):
                return True

            def __str__(self):
                return ""

        self.assertTrue(issubclass(GoodSourceData, module.SourceDataProtocol))

    def test_not_following_source_data_protocol_no_oaev_data(self):
        """verify that a class not following the protocol is detected as such"""

        class BadSourceData_no_oaev_data:
            def to_traces_data(self):
                return MagicMock()

            def is_prevented(self):
                return False

            def is_detected(self):
                return True

            def __str__(self):
                return ""

        self.assertFalse(
            issubclass(BadSourceData_no_oaev_data, module.SourceDataProtocol)
        )

    def test_not_following_source_data_protocol_no_traces_data(self):
        """verify that a class not following the protocol is detected as such"""

        class BadSourceData_no_traces_data:
            def to_oaev_data(self):
                return MagicMock()

            def is_prevented(self):
                return False

            def is_detected(self):
                return True

            def __str__(self):
                return ""

        self.assertFalse(
            issubclass(BadSourceData_no_traces_data, module.SourceDataProtocol)
        )

    def test_not_following_source_data_protocol_no_prevented(self):
        """verify that a class not following the protocol is detected as such"""

        class BadSourceData_no_prevented:
            def to_oaev_data(self):
                return MagicMock()

            def to_traces_data(self):
                return MagicMock()

            def is_detected(self):
                return True

            def __str__(self):
                return ""

        self.assertFalse(
            issubclass(BadSourceData_no_prevented, module.SourceDataProtocol)
        )

    def test_not_following_source_data_protocol_no_detected(self):
        """verify that a class not following the protocol is detected as such"""

        class BadSourceData_no_detected:
            def to_oaev_data(self):
                return MagicMock()

            def to_traces_data(self):
                return MagicMock()

            def is_prevented(self):
                return False

            def __str__(self):
                return ""

        self.assertFalse(
            issubclass(BadSourceData_no_detected, module.SourceDataProtocol)
        )
