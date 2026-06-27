import unittest
from unittest.mock import MagicMock

from prompt_security.client import PromptSecurityClient, Verdict


def _make_client(base_url="https://example.test", app_id="app-key", auth_header=None):
    return PromptSecurityClient(
        {
            "ps_base_url": base_url,
            "ps_app_id": app_id,
            "ps_auth_header": auth_header,
        }
    )


def _mock_response(payload):
    resp = MagicMock()
    resp.json.return_value = payload
    resp.raise_for_status.return_value = None
    return resp


class TestPromptSecurityClientScan(unittest.TestCase):
    def test_benign_response_is_not_flagged(self):
        client = _make_client()
        client.session.post = MagicMock(
            return_value=_mock_response({"action": "allow"})
        )
        verdict = client.scan("prompt")
        self.assertIsInstance(verdict, Verdict)
        self.assertFalse(verdict.flagged)
        self.assertFalse(verdict.blocked)

    def test_block_action_is_flagged_and_blocked(self):
        client = _make_client()
        client.session.post = MagicMock(
            return_value=_mock_response({"action": "block"})
        )
        verdict = client.scan("prompt")
        self.assertTrue(verdict.flagged)
        self.assertTrue(verdict.blocked)

    def test_modify_action_is_flagged_but_not_blocked(self):
        client = _make_client()
        client.session.post = MagicMock(
            return_value=_mock_response({"action": "modify"})
        )
        verdict = client.scan("prompt")
        self.assertTrue(verdict.flagged)
        self.assertFalse(verdict.blocked)

    def test_violations_drive_flag_and_dict_detail(self):
        client = _make_client()
        client.session.post = MagicMock(
            return_value=_mock_response(
                {"action": "allow", "violations": [{"type": "prompt_injection"}]}
            )
        )
        verdict = client.scan("prompt")
        self.assertTrue(verdict.flagged)
        self.assertFalse(verdict.blocked)
        self.assertEqual(verdict.detail, "prompt_injection")

    def test_non_dict_violation_detail_is_stringified(self):
        client = _make_client()
        client.session.post = MagicMock(
            return_value=_mock_response({"violations": ["jailbreak"]})
        )
        verdict = client.scan("prompt")
        self.assertTrue(verdict.flagged)
        self.assertEqual(verdict.detail, "jailbreak")

    def test_result_wrapper_is_unwrapped(self):
        client = _make_client()
        client.session.post = MagicMock(
            return_value=_mock_response(
                {"result": {"action": "block", "violations": [{"name": "toxicity"}]}}
            )
        )
        verdict = client.scan("prompt")
        self.assertTrue(verdict.flagged)
        self.assertTrue(verdict.blocked)
        self.assertEqual(verdict.detail, "toxicity")

    def test_missing_base_url_raises(self):
        with self.assertRaises(ValueError):
            _make_client(base_url="").scan("prompt")

    def test_missing_app_id_raises(self):
        with self.assertRaises(ValueError):
            _make_client(app_id=None).scan("prompt")

    def test_base_url_trailing_slash_is_stripped(self):
        client = _make_client(base_url="https://example.test/")
        self.assertEqual(client.base_url, "https://example.test")

    def test_scan_posts_auth_header_and_body(self):
        client = _make_client(app_id="secret-token")
        post = MagicMock(return_value=_mock_response({"action": "allow"}))
        client.session.post = post
        client.scan("hello", system_prompt="be safe")
        args, kwargs = post.call_args
        self.assertEqual(args[0], "https://example.test/api/protect")
        self.assertEqual(kwargs["headers"]["APP-ID"], "secret-token")
        self.assertEqual(kwargs["headers"]["Content-Type"], "application/json")
        self.assertEqual(kwargs["json"]["prompt"], "hello")
        self.assertEqual(kwargs["json"]["system_prompt"], "be safe")

    def test_custom_auth_header_and_no_system_prompt(self):
        client = _make_client(app_id="tok", auth_header="X-API-Key")
        post = MagicMock(return_value=_mock_response({"action": "allow"}))
        client.session.post = post
        client.scan("hi")
        _, kwargs = post.call_args
        self.assertEqual(kwargs["headers"]["X-API-Key"], "tok")
        self.assertNotIn("system_prompt", kwargs["json"])


if __name__ == "__main__":
    unittest.main()
