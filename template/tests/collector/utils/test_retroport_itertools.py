import unittest
from unittest.mock import MagicMock, patch

import src.collector.utils.retroport_itertools as module


class TestRetroportItertools(unittest.TestCase):
    @patch.object(module, "_batched")
    @patch.object(module, "itertools")
    @patch.object(module, "sys")
    def test_batched_with_itertools(self, m_sys, m_itertools, m_batched):
        version_info = MagicMock(major=3, minor=13)
        m_sys.version_info = version_info

        iterable = MagicMock()
        size = MagicMock()

        module.batched(iterable, size)

        m_itertools.batched.assert_called_with(iterable, size)
        m_batched.assert_not_called()

    @patch.object(module, "_batched")
    @patch.object(module, "itertools")
    @patch.object(module, "sys")
    def test_batched_without_itertools(self, m_sys, m_itertools, m_batched):
        version_info = MagicMock(major=3, minor=11)
        m_sys.version_info = version_info

        iterable = MagicMock()
        size = MagicMock()

        module.batched(iterable, size)

        m_batched.assert_called_with(iterable, size)
        m_itertools.batched.assert_not_called()

    def test_batched(self):
        one = MagicMock()
        two = MagicMock()
        three = MagicMock()
        iterable = [one, two, three]
        size = 2

        batches = module._batched(iterable, size)

        batch = next(batches)
        self.assertEqual(batch, (one, two))

        batch = next(batches)
        self.assertEqual(batch, (three,))

    def test_batched_wrong_size(self):
        iterable = [MagicMock(), MagicMock(), MagicMock()]
        size = -2

        with self.assertRaises(ValueError):
            next(module._batched(iterable, size))
