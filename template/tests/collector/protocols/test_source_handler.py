import unittest
from unittest.mock import MagicMock

import src.collector.protocols.source_handler as module


class SourceHandlerProtocolTest(unittest.TestCase):
    def test_following_source_handler_protocol(self):
        """verify that a class following the protocol is seen as such"""

        class GoodSourceHandler:
            def get_source_data(self, data_fetcher):
                return [MagicMock()]

            def serialize_as_oaevdata(self, data):
                return MagicMock()

            def get_expectation_signature_groups(self, signatures, expectations):
                return [{"foo": "bar"}]

            def match_signature_groups_and_oaevdata(
                self, signature_groups, oaev_data, oaev_detection_helper
            ):
                return True

            def serialize_as_tracedata(self, data):
                return MagicMock()

            def match_expectation_and_sourcedata(self, expectation, data):
                return [False, False]

        self.assertTrue(issubclass(GoodSourceHandler, module.SourceHandlerProtocol))

    def test_not_following_source_handler_protocol_no_get_source_data(self):
        """verify that a class not following the protocol is detected as such"""

        class BadSourceHandler_no_get_source_data:
            def serialize_as_oaevdata(self, data):
                return MagicMock()

            def get_expectation_signature_groups(self, signatures, expectations):
                return [{"foo": "bar"}]

            def match_signature_groups_and_oaevdata(
                self, signature_groups, oaev_data, oaev_detection_helper
            ):
                return True

            def serialize_as_tracedata(self, data):
                return MagicMock()

            def match_expectation_and_sourcedata(self, expectation, data):
                return [False, False]

        self.assertFalse(
            issubclass(
                BadSourceHandler_no_get_source_data, module.SourceHandlerProtocol
            )
        )

    def test_not_following_source_handler_protocol_no_serialize_as_oaevdata(self):
        """verify that a class not following the protocol is detected as such"""

        class BadSourceHandler_no_serialize_as_oaevdata:
            def get_source_data(self, data_fetcher):
                return [MagicMock()]

            def get_expectation_signature_groups(self, signatures, expectations):
                return [{"foo": "bar"}]

            def match_signature_groups_and_oaevdata(
                self, signature_groups, oaev_data, oaev_detection_helper
            ):
                return True

            def serialize_as_tracedata(self, data):
                return MagicMock()

            def match_expectation_and_sourcedata(self, expectation, data):
                return [False, False]

        self.assertFalse(
            issubclass(
                BadSourceHandler_no_serialize_as_oaevdata, module.SourceHandlerProtocol
            )
        )

    def test_not_following_source_handler_protocol_no_get_expectation_signature_groups(
        self,
    ):
        """verify that a class not following the protocol is detected as such"""

        class BadSourceHandler_no_get_expectation_signature_groups:
            def get_source_data(self, data_fetcher):
                return [MagicMock()]

            def serialize_as_oaevdata(self, data):
                return MagicMock()

            def match_signature_groups_and_oaevdata(
                self, signature_groups, oaev_data, oaev_detection_helper
            ):
                return True

            def serialize_as_tracedata(self, data):
                return MagicMock()

            def match_expectation_and_sourcedata(self, expectation, data):
                return [False, False]

        self.assertFalse(
            issubclass(
                BadSourceHandler_no_get_expectation_signature_groups,
                module.SourceHandlerProtocol,
            )
        )

    def test_not_following_source_handler_protocol_no_match_signature_groups_and_oaevdata(
        self,
    ):
        """verify that a class not following the protocol is detected as such"""

        class BadSourceHandler_no_match_signature_groups_and_oaevdata:
            def get_source_data(self, data_fetcher):
                return [MagicMock()]

            def serialize_as_oaevdata(self, data):
                return MagicMock()

            def get_expectation_signature_groups(self, signatures, expectations):
                return [{"foo": "bar"}]

            def serialize_as_tracedata(self, data):
                return MagicMock()

            def match_expectation_and_sourcedata(self, expectation, data):
                return [False, False]

        self.assertFalse(
            issubclass(
                BadSourceHandler_no_match_signature_groups_and_oaevdata,
                module.SourceHandlerProtocol,
            )
        )

    def test_not_following_source_handler_protocol_no_serialize_as_tracedata(self):
        """verify that a class not following the protocol is detected as such"""

        class BadSourceHandler_no_serialize_as_tracedata:
            def get_source_data(self, data_fetcher):
                return [MagicMock()]

            def serialize_as_oaevdata(self, data):
                return MagicMock()

            def get_expectation_signature_groups(self, signatures, expectations):
                return [{"foo": "bar"}]

            def match_signature_groups_and_oaevdata(
                self, signature_groups, oaev_data, oaev_detection_helper
            ):
                return True

            def match_expectation_and_sourcedata(self, expectation, data):
                return [False, False]

        self.assertFalse(
            issubclass(
                BadSourceHandler_no_serialize_as_tracedata, module.SourceHandlerProtocol
            )
        )

    def test_not_following_source_handler_protocol_no_match_expectation_and_sourcedata(
        self,
    ):
        """verify that a class not following the protocol is detected as such"""

        class BadSourceHandler_no_match_expectation_and_sourcedata:
            def get_source_data(self, data_fetcher):
                return [MagicMock()]

            def serialize_as_oaevdata(self, data):
                return MagicMock()

            def get_expectation_signature_groups(self, signatures, expectations):
                return [{"foo": "bar"}]

            def match_signature_groups_and_oaevdata(
                self, signature_groups, oaev_data, oaev_detection_helper
            ):
                return True

            def serialize_as_tracedata(self, data):
                return MagicMock()

        self.assertFalse(
            issubclass(
                BadSourceHandler_no_match_expectation_and_sourcedata,
                module.SourceHandlerProtocol,
            )
        )
