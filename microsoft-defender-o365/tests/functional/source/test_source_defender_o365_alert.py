import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import orjson
import src.source.defender_o365_alert_model as module
# module.DefenderO365Alert, AnalyzedMessageEvidence, EmailSender

sample_zero = Path("./tests/functional/source/alert_sample_zero.json")
sample_one = Path("./tests/functional/source/alert_sample_one.json")
sample_two = Path("./tests/functional/source/alert_sample_two.json")
sample_three = Path("./tests/functional/source/alert_sample_three.json")


class TestO365AlertProcessing(unittest.TestCase):
    def test_o365_alert_processing_sample_zero(self):
        data_zero = orjson.loads(sample_zero.read_bytes())
        object_zero = module.DefenderO365Alert(**data_zero)
        required_zero = object_zero.filter_evidence()
        self.assertTrue(all(el is not None for el in required_zero.values()))
        for evidence in required_zero['evidence']:
            self.assertTrue(any(el for el in evidence.values()))

    def test_o365_alert_processing_sample_one(self):
        data_one = orjson.loads(sample_one.read_bytes())
        object_one = module.DefenderO365Alert(**data_one)
        required_one = object_one.filter_evidence()
        self.assertTrue(all(el is not None for el in required_one.values()))
        for evidence in required_one['evidence']:
            self.assertTrue(any(el for el in evidence.values()))

    def test_o365_alert_processing_sample_two(self):
        data_two = orjson.loads(sample_two.read_bytes())
        object_two = module.DefenderO365Alert(**data_two)
        required_two = object_two.filter_evidence()
        self.assertTrue(all(el is not None for el in required_two.values()))
        for evidence in required_two['evidence']:
            self.assertTrue(any(el for el in evidence.values()))

    def test_o365_alert_processing_sample_three(self):
        data_three = orjson.loads(sample_three.read_bytes())
        object_three = module.DefenderO365Alert(**data_three)
        required_three = object_three.filter_evidence()
        self.assertTrue(all(el is not None for el in required_three.values()))
        for evidence in required_three['evidence']:
            self.assertTrue(any(el for el in evidence.values()))
