import unittest
from unittest.mock import MagicMock

import src.collector.models.source as module
from pydantic import ValidationError


class SourceTest(unittest.TestCase):
    def setUp(self):
        class FakeSourceData:
            def to_oaev_data(self):
                return module.OAEVData(parent_process_name="mother")

            def to_traces_data(self):
                return module.TraceData(
                    alert_name="my name is", alert_link="http://foo.bar/"
                )

            def is_prevented(self):
                return False

            def is_detected(self):
                return True

            def __str__(self):
                return ""

        self.source_data_model = FakeSourceData

        class FakeDataFetcher:
            def fetch_data(self):
                return [FakeSourceData(), FakeSourceData()]

        self.data_fetcher_model = FakeDataFetcher

        self.signatures = [module.SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME]

    def test_source_good_init(self):
        """
        testing the proper init of Source
        """
        source = module.Source(
            data_fetcher_model=self.data_fetcher_model,
            source_data_model=self.source_data_model,
            signatures=self.signatures,
        )

        self.assertEqual(source.data_fetcher_model, self.data_fetcher_model)
        self.assertEqual(source.source_data_model, self.source_data_model)
        self.assertEqual(source.signatures, self.signatures)

    def test_source_wrong_datafetcher_init(self):
        """
        testing the failure of Source init
        due to a data fetcher not following the data fetcher protocol
        """

        class WrongDataFetcher:
            def dont_fetch_data(self):
                pass

        with self.assertRaises(ValidationError):
            module.Source(
                data_fetcher_model=WrongDataFetcher(),
                source_data_model=self.source_data_model,
                signatures=self.signatures,
            )

    def test_source_wrong_sourcedata_init(self):
        """
        testing the failure of Source init
        due to a source data not following the source data protocol
        """

        class WrongSourceData:
            def is_prevented(self):
                return False

            def is_detected(self):
                return True

            def __str__(self):
                return ""

        with self.assertRaises(ValidationError):
            module.Source(
                data_fetcher_model=self.data_fetcher_model,
                source_data_model=WrongSourceData(),
                signatures=self.signatures,
            )

    def test_source_wrong_signatures_init(self):
        """
        testing the failure of Source init
        due to signatures having the wrong type
        """

        wrong_signatures = ["one", "two"]

        with self.assertRaises(ValidationError):
            module.Source(
                data_fetcher_model=self.data_fetcher_model,
                source_data_model=self.source_data_model,
                signatures=wrong_signatures,
            )


class SourceHandlerTest(unittest.TestCase):
    def test_get_source_data(self):
        """
        assert the calls made to data fetcher by source handler
        for the get_source_data function
        """
        data_fetcher = MagicMock()

        module.SourceHandler().get_source_data(data_fetcher)

        data_fetcher.fetch_data.assert_called_once()

    def test_serialize_as_oaevdata(self):
        """
        assert the calls made to source data by source handler
        for the serialize_as_oaevdata function
        """
        data = MagicMock()

        module.SourceHandler().serialize_as_oaevdata(data)

        data.to_oaev_data.assert_called_once()

    def test_get_expectation_signature_groups(self):
        """
        testing the data manipulation made by source handler
        in order to produce signature groups
        through the get_expectation_signature_groups function
        """
        value = "my_type"
        signature = MagicMock(value=value)
        signatures = [signature]
        _type = MagicMock(value=value)
        inject_expectation_signature_1 = MagicMock(type=_type, value="my_value")
        inject_expectation_signature_2 = MagicMock(type=_type, value="my_other_value")
        end_date_type = MagicMock(value="end_date")
        end_date_ies = MagicMock(type=end_date_type, value="now")
        expectation = MagicMock(
            inject_expectation_signatures=[
                inject_expectation_signature_1,
                inject_expectation_signature_2,
                end_date_ies,
            ]
        )

        signature_groups = module.SourceHandler().get_expectation_signature_groups(
            signatures, expectation
        )

        self.assertEqual(1, len(signature_groups))
        self.assertEqual(2, len(signature_groups.get("my_type")))
        self.assertIn(
            {"type": "my_type", "value": "my_value"}, signature_groups.get("my_type")
        )
        self.assertIn(
            {"type": "my_type", "value": "my_other_value"},
            signature_groups.get("my_type"),
        )

    def test_match_signature_groups_and_oaevdata_success(self):
        """
        testing the calls made to oaev detection helper by the source handler
        for a successful matching
        """
        signature_groups = {"my_type": [{"type": "my_type", "value": "my_value"}]}
        oaev_data = MagicMock()
        oaev_detection_helper = MagicMock()
        oaev_detection_helper.match_alert_elements.return_value = True

        flag = module.SourceHandler().match_signature_groups_and_oaevdata(
            signature_groups, oaev_data, oaev_detection_helper
        )

        oaev_detection_helper.match_alert_elements.assert_called_with(
            signature_groups["my_type"], {"my_type": oaev_data.my_type}
        )
        self.assertTrue(flag)

    def test_match_signature_groups_and_oaevdata_failure(self):
        """
        testing the calls made to oaev detection helper by the source handler
        for a failed matching
        """
        signature_groups = {"my_type": [{"type": "my_type", "value": "my_value"}]}
        oaev_data = MagicMock()
        oaev_detection_helper = MagicMock()
        oaev_detection_helper.match_alert_elements.return_value = False

        flag = module.SourceHandler().match_signature_groups_and_oaevdata(
            signature_groups, oaev_data, oaev_detection_helper
        )

        oaev_detection_helper.match_alert_elements.assert_called_with(
            signature_groups["my_type"], {"my_type": oaev_data.my_type}
        )
        self.assertFalse(flag)

    def test_match_signature_groups_and_oaevdata_empty(self):
        """
        testing the calls made to oaev detection helper by the source handler
        for an empty input
        """
        signature_groups = {"my_type": [{"type": "my_type", "value": "my_value"}]}
        oaev_data = None
        oaev_detection_helper = MagicMock()
        oaev_detection_helper.match_alert_elements.return_value = True

        flag = module.SourceHandler().match_signature_groups_and_oaevdata(
            signature_groups, oaev_data, oaev_detection_helper
        )

        oaev_detection_helper.match_alert_elements.assert_not_called()
        self.assertFalse(flag)

    def test_serialize_as_tracedata(self):
        """
        assert the calls made to source data by source handler
        for the serialize_as_tracedata function
        """
        data = MagicMock()

        module.SourceHandler().serialize_as_tracedata(data)

        data.to_traces_data.assert_called_once()

    def test_match_expectation_and_sourcedata_prevention_prevented(self):
        """
        testing a prevented PreventionExpectation
        """
        expectation = MagicMock(spec=module.PreventionExpectation)
        data = MagicMock()
        data.is_prevented.return_value = True
        data.is_detected.return_value = True

        matchflag, breakflag = module.SourceHandler().match_expectation_and_sourcedata(
            expectation, data
        )

        data.is_prevented.assert_called_once()
        data.is_detected.assert_not_called()
        self.assertTrue(matchflag)
        self.assertTrue(breakflag)

    def test_match_expectation_and_sourcedata_prevention_not_prevented(self):
        """
        testing a non-prevented PreventionExpectation
        """
        expectation = MagicMock(spec=module.PreventionExpectation)
        data = MagicMock()
        data.is_prevented.return_value = False
        data.is_detected.return_value = True

        matchflag, breakflag = module.SourceHandler().match_expectation_and_sourcedata(
            expectation, data
        )

        data.is_prevented.assert_called_once()
        data.is_detected.assert_not_called()
        self.assertFalse(matchflag)
        self.assertFalse(breakflag)

    def test_match_expectation_and_sourcedata_detection_detected(self):
        """
        testing a detected DetectionExpectation
        """
        expectation = MagicMock(spec=module.DetectionExpectation)
        data = MagicMock()
        data.is_prevented.return_value = True
        data.is_detected.return_value = True

        matchflag, breakflag = module.SourceHandler().match_expectation_and_sourcedata(
            expectation, data
        )

        data.is_prevented.assert_not_called()
        data.is_detected.assert_called_once()
        self.assertTrue(matchflag)
        self.assertFalse(breakflag)

    def test_match_expectation_and_sourcedata_detection_not_detected(self):
        """
        testing a non-detected DetectionExpectation
        """
        expectation = MagicMock(spec=module.DetectionExpectation)
        data = MagicMock()
        data.is_prevented.return_value = True
        data.is_detected.return_value = False

        matchflag, breakflag = module.SourceHandler().match_expectation_and_sourcedata(
            expectation, data
        )

        data.is_prevented.assert_not_called()
        data.is_detected.assert_called_once()
        self.assertFalse(matchflag)
        self.assertFalse(breakflag)
