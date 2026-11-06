import unittest

from crowdstrike.pattern_disposition import (
    ALL_MODIFY,
    ALL_PREVENT,
    MODIFY_KILL_ACTION_FAILED,
    MODIFY_POLICY_DISABLED,
    PREVENT_KILL_PROCESS,
    is_prevented,
)


class TestAlert(unittest.TestCase):
    def test_when_pattern_disposition_is_process_killed_when_not_disabled_return_true(
        self,
    ):
        pattern_disposition = PREVENT_KILL_PROCESS

        result = is_prevented(pattern_disposition)

        self.assertTrue(result)

    def test_when_pattern_disposition_is_process_killed_when_failed_return_false(
        self,
    ):
        pattern_disposition = PREVENT_KILL_PROCESS | MODIFY_KILL_ACTION_FAILED

        result = is_prevented(pattern_disposition)

        self.assertFalse(result)

    def test_when_pattern_disposition_is_all_prevents_when_none_are_disabled_return_true(
        self,
    ):
        pattern_disposition = ALL_PREVENT

        result = is_prevented(pattern_disposition)

        self.assertTrue(result)

    def test_when_pattern_disposition_is_all_prevents_when_some_are_disabled_return_false(
        self,
    ):
        pattern_disposition = (
            ALL_PREVENT | MODIFY_KILL_ACTION_FAILED | MODIFY_POLICY_DISABLED
        )

        result = is_prevented(pattern_disposition)

        self.assertFalse(result)

    def test_when_pattern_disposition_is_all_prevents_when_all_are_disabled_return_false(
        self,
    ):
        pattern_disposition = ALL_PREVENT | ALL_MODIFY

        result = is_prevented(pattern_disposition)

        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
