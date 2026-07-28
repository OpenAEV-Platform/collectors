import unittest

import src.source.microsoft_defender_o365_signatures as module


class TestSignatures(unittest.TestCase):
    def test_length(self):
        self.assertEqual(
            len(module.SUPPORTED_SIGNATURES),
            7,
        )

    def test_types(self):
        for sig in module.SUPPORTED_SIGNATURES:
            self.assertIsInstance(sig, module.SignatureTypes)

    def test_no_duplicate(self):
        for sig in module.SUPPORTED_SIGNATURES:
            self.assertEqual(
                module.SUPPORTED_SIGNATURES.count(sig),
                1,
            )
