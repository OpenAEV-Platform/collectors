import unittest
from pathlib import Path

import orjson
import src.source.source_data as module

sample_zero = Path("./tests/functional/source/alert_sample_zero.json")


class TestAlertProcessing(unittest.TestCase):
    def test_alert_processing_sample_zero(self):
        data_zero = orjson.loads(sample_zero.read_bytes())
        object_zero = module.Alert(**data_zero)

        self.assertEqual(object_zero.raw, data_zero)

        self.assertTrue(object_zero.is_detected())
        self.assertTrue(object_zero.is_prevented())

        evidences = object_zero._extract_evidences()
        self.assertTrue(
            all(isinstance(key, module.SignatureTypes) for key in evidences.keys())
        )
        self.assertTrue(all(value is not None for value in evidences.values()))

        oaev_data = object_zero.to_oaev_data()
        self.assertIn("myhostname.somewhere.local", oaev_data.target_hostname_address)
        self.assertIn("13.108.65.65", oaev_data.target_ipv4_address)
        self.assertIn(
            "oaev-implant-e0dd601e-594c-420f-b6c6-d1f09e9729cc-agent-f5e972e6-ca8d-436f-b537-8177f67f4c91.exe",
            oaev_data.parent_process_name,
        )

        trace_data = object_zero.to_traces_data()
        self.assertEqual(trace_data.alert_name, "Suspicious network share discovery")
        self.assertEqual(
            str(trace_data.alert_link),
            "https://security.microsoft.com/alerts/50c27011-725c-41d8-9090-efd4c10132c2?tid=e15cdeca-e989-4b00-a5d7-5b3a34eff5f4",
        )
