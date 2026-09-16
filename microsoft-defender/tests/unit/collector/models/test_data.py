import unittest
from datetime import UTC, datetime

import src.collector.models.data as module
from pydantic import AnyUrl, ValidationError


class OAEVDataTest(unittest.TestCase):
    def test_oaev_data_good_init(self):
        """
        testing the proper init of OAEVData
        """
        parent_process_name = "mother"
        end_date = str(datetime.now(UTC))

        oaevdata = module.OAEVData(
            parent_process_name=parent_process_name, end_date=end_date
        )

        self.assertEqual(oaevdata.parent_process_name, parent_process_name)
        self.assertEqual(oaevdata.end_date, end_date)

    def test_oaev_data_wrong_init(self):
        """
        testing the failure of OAEVData init
        due to parameters outside the allowed range (signature types)
        """
        parent_process_name = "mother"
        foo = "bar"

        with self.assertRaises(ValidationError):
            module.OAEVData(parent_process_name=parent_process_name, foo=foo)

    def test_oaev_data_str_format(self):
        """
        testing the proper init of OAEVData
        with all parameters
        """
        parent_process_name = "mother"
        end_date = str(datetime.now(UTC))

        oaevdata = module.OAEVData(
            parent_process_name=parent_process_name, end_date=end_date
        )

        self.assertEqual(
            str(oaevdata),
            f"OAEVData(parent_process_name='mother', end_date='{end_date}')",
        )


class TraceDataTest(unittest.TestCase):
    def test_trace_data_minimum_init(self):
        """
        testing the proper init of TraceData
        with only required parameters
        """
        alert_name = "my name is"
        alert_link = "https://foo.bar/"

        tracedata = module.TraceData(alert_name=alert_name, alert_link=alert_link)

        self.assertEqual(tracedata.alert_name, alert_name)
        self.assertIsInstance(tracedata.alert_link, AnyUrl)
        self.assertEqual(str(tracedata.alert_link), alert_link)
        self.assertIsNotNone(tracedata.alert_date)
        self.assertIsInstance(tracedata.alert_date, datetime)

    def test_trace_data_maximal_init(self):
        """
        testing the proper init of TraceData
        with all parameters
        """
        alert_name = "my name is"
        alert_link = "https://foo.bar/"
        alert_date = datetime.now(UTC)

        tracedata = module.TraceData(
            alert_name=alert_name, alert_link=alert_link, alert_date=alert_date
        )

        self.assertEqual(tracedata.alert_name, alert_name)
        self.assertIsInstance(tracedata.alert_link, AnyUrl)
        self.assertEqual(str(tracedata.alert_link), alert_link)
        self.assertIsInstance(tracedata.alert_date, datetime)
        self.assertEqual(tracedata.alert_date, alert_date)

    def test_trace_data_wrong_init(self):
        """
        testing a failed init of TraceData
        due to a non-URL for alert_link
        """
        alert_name = "my name is"
        alert_link = "this is not a URL"

        with self.assertRaises(ValidationError):
            module.TraceData(alert_name=alert_name, alert_link=alert_link)

    def test_trace_data_str_format(self):
        """
        testing the proper init of TraceData
        with all parameters
        """
        alert_name = "my name is"
        alert_link = "https://foo.bar/"
        alert_date = datetime.now(UTC)

        tracedata = module.TraceData(
            alert_name=alert_name, alert_link=alert_link, alert_date=alert_date
        )

        self.assertEqual(
            str(tracedata),
            f"TraceData(alert_name='my name is', alert_link='https://foo.bar/', alert_date='{alert_date}')",
        )
