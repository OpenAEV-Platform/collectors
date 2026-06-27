import unittest
from unittest.mock import MagicMock

from prisma_airs.client import PrismaAirsClient, Verdict


def _make_client(api_key="key", profile="profile", base_url="https://example.test"):
    return PrismaAirsClient(
        {
            "prisma_base_url": base_url,
            "prisma_api_key": api_key,
            "prisma_ai_profile": profile,
        }
    )


def _mock_response(payload):
    resp = MagicMock()
    resp.json.return_value = payload
    resp.raise_for_status.return_value = None
    return resp


class TestPrismaAirsClientScan(unittest.TestCase):
    def test_malicious_category_is_flagged_but_not_blocked(self):
        client = _make_client()
        client.session.post = MagicMock(
            return_value=_mock_response({"category": "malicious", "action": "allow"})
        )
        verdict = client.scan("prompt")
        self.assertIsInstance(verdict, Verdict)
        self.assertTrue(verdict.flagged)
        self.assertFalse(verdict.blocked)

    def test_block_action_is_flagged_and_blocked(self):
        client = _make_client()
        client.session.post = MagicMock(
            return_value=_mock_response({"category": "benign", "action": "block"})
        )
        verdict = client.scan("prompt")
        self.assertTrue(verdict.flagged)
        self.assertTrue(verdict.blocked)

    def test_prompt_detected_drives_flag_and_detail(self):
        client = _make_client()
        client.session.post = MagicMock(
            return_value=_mock_response(
                {
                    "category": "benign",
                    "action": "allow",
                    "prompt_detected": {"injection": True, "url_cats": False},
                }
            )
        )
        verdict = client.scan("prompt")
        self.assertTrue(verdict.flagged)
        self.assertIn("injection", verdict.detail)
        self.assertNotIn("url_cats", verdict.detail)

    def test_benign_response_is_not_flagged(self):
        client = _make_client()
        client.session.post = MagicMock(
            return_value=_mock_response({"category": "benign", "action": "allow"})
        )
        verdict = client.scan("prompt")
        self.assertFalse(verdict.flagged)
        self.assertFalse(verdict.blocked)

    def test_missing_api_key_or_profile_raises(self):
        with self.assertRaises(ValueError):
            _make_client(api_key=None).scan("prompt")
        with self.assertRaises(ValueError):
            _make_client(profile=None).scan("prompt")

    def test_base_url_trailing_slash_is_stripped(self):
        client = _make_client(base_url="https://example.test/")
        self.assertEqual(client.base_url, "https://example.test")

    def test_scan_posts_token_and_profile(self):
        client = _make_client(api_key="secret-token", profile="my-profile")
        post = MagicMock(
            return_value=_mock_response({"category": "benign", "action": "allow"})
        )
        client.session.post = post
        client.scan("hello")
        args, kwargs = post.call_args
        self.assertEqual(args[0], "https://example.test/v1/scan/sync/request")
        self.assertEqual(kwargs["headers"]["x-pan-token"], "secret-token")
        self.assertEqual(kwargs["json"]["ai_profile"]["profile_name"], "my-profile")
        self.assertEqual(kwargs["json"]["contents"], [{"prompt": "hello"}])


if __name__ == "__main__":
    unittest.main()
