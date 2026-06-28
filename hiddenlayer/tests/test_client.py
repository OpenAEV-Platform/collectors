"""Unit tests for the HiddenLayer AIDR client.

These tests exercise only ``hiddenlayer.client`` (the requests-based interactions/OAuth2 layer)
and stub ``requests`` via ``unittest.mock``. They deliberately do NOT import the collector daemon
(``hiddenlayer.openaev_hiddenlayer``), which depends on the not-yet-released pyoaev AI APIs, so the
suite stays CI-safe and runnable with only ``requests`` installed.
"""

import unittest
from unittest.mock import MagicMock

from hiddenlayer.client import HiddenLayerClient, Verdict


def _make_client(client_id="", client_secret="", base_url="https://example.test"):
    return HiddenLayerClient(
        {
            "hl_base_url": base_url,
            "hl_auth_url": "https://auth.example.test/oauth2/token",
            "hl_client_id": client_id,
            "hl_client_secret": client_secret,
        }
    )


def _mock_response(payload):
    resp = MagicMock()
    resp.json.return_value = payload
    resp.raise_for_status.return_value = None
    return resp


class TestHiddenLayerClientScan(unittest.TestCase):
    """Verdict mapping of HiddenLayerClient.scan() (self-hosted / unauthenticated)."""

    def test_detection_present_is_flagged_with_detail(self):
        client = _make_client()
        client.session.post = MagicMock(
            return_value=_mock_response(
                {"detections": [{"detection": "prompt_injection"}], "action": "allow"}
            )
        )
        verdict = client.scan("prompt")
        self.assertIsInstance(verdict, Verdict)
        self.assertTrue(verdict.flagged)
        self.assertFalse(verdict.blocked)
        self.assertEqual(verdict.detail, "prompt_injection")

    def test_block_without_detections_is_flagged_and_blocked(self):
        # prevention implies detection: a block counts as flagged even with no detections.
        client = _make_client()
        client.session.post = MagicMock(
            return_value=_mock_response({"action": "block"})
        )
        verdict = client.scan("prompt")
        self.assertTrue(verdict.flagged)
        self.assertTrue(verdict.blocked)
        self.assertEqual(verdict.detail, "HiddenLayer AIDR detection")

    def test_blocked_boolean_field_is_flagged_and_blocked(self):
        client = _make_client()
        client.session.post = MagicMock(return_value=_mock_response({"blocked": True}))
        verdict = client.scan("prompt")
        self.assertTrue(verdict.flagged)
        self.assertTrue(verdict.blocked)

    def test_flagged_field_without_detections_is_flagged_not_blocked(self):
        client = _make_client()
        client.session.post = MagicMock(
            return_value=_mock_response({"flagged": True, "action": "allow"})
        )
        verdict = client.scan("prompt")
        self.assertTrue(verdict.flagged)
        self.assertFalse(verdict.blocked)

    def test_benign_allow_is_not_flagged_with_neutral_detail(self):
        client = _make_client()
        client.session.post = MagicMock(
            return_value=_mock_response({"action": "allow"})
        )
        verdict = client.scan("prompt")
        self.assertFalse(verdict.flagged)
        self.assertFalse(verdict.blocked)
        self.assertEqual(verdict.detail, "No detection")

    def test_non_dict_detection_does_not_raise(self):
        # A non-dict first detection must be stringified, never crash on .get().
        client = _make_client()
        client.session.post = MagicMock(
            return_value=_mock_response({"detections": ["raw_finding"]})
        )
        verdict = client.scan("prompt")
        self.assertTrue(verdict.flagged)
        self.assertEqual(verdict.detail, "raw_finding")

    def test_results_key_is_used_as_detections_fallback(self):
        client = _make_client()
        client.session.post = MagicMock(
            return_value=_mock_response({"results": [{"type": "jailbreak"}]})
        )
        verdict = client.scan("prompt")
        self.assertTrue(verdict.flagged)
        self.assertEqual(verdict.detail, "jailbreak")

    def test_base_url_trailing_slash_is_stripped(self):
        client = _make_client(base_url="https://example.test/")
        self.assertEqual(client.base_url, "https://example.test")

    def test_scan_targets_interactions_endpoint_unauthenticated(self):
        client = _make_client()
        post = MagicMock(return_value=_mock_response({"action": "allow"}))
        client.session.post = post
        client.scan("hello")
        args, kwargs = post.call_args
        self.assertEqual(args[0], "https://example.test/detection/v1/interactions")
        self.assertNotIn("Authorization", kwargs["headers"])
        self.assertEqual(
            kwargs["json"]["input"]["messages"],
            [{"role": "user", "content": "hello"}],
        )

    def test_scan_includes_system_prompt_when_provided(self):
        client = _make_client()
        post = MagicMock(return_value=_mock_response({"action": "allow"}))
        client.session.post = post
        client.scan("hello", system_prompt="be safe")
        _, kwargs = post.call_args
        self.assertEqual(
            kwargs["json"]["input"]["messages"],
            [
                {"role": "system", "content": "be safe"},
                {"role": "user", "content": "hello"},
            ],
        )


class TestHiddenLayerClientBearer(unittest.TestCase):
    """OAuth2 client-credentials guards in HiddenLayerClient._bearer()."""

    def test_both_credentials_empty_is_unauthenticated(self):
        # Both empty -> self-hosted AIDR container, no OAuth2.
        self.assertIsNone(_make_client()._bearer())

    def test_missing_client_secret_raises(self):
        with self.assertRaises(ValueError):
            _make_client(client_id="id", client_secret="")._bearer()

    def test_missing_client_id_raises(self):
        with self.assertRaises(ValueError):
            _make_client(client_id="", client_secret="secret")._bearer()

    def test_token_response_without_access_token_raises(self):
        client = _make_client(client_id="id", client_secret="secret")
        client.session.post = MagicMock(return_value=_mock_response({}))
        with self.assertRaises(ValueError):
            client._bearer()

    def test_valid_token_is_returned_and_cached(self):
        client = _make_client(client_id="id", client_secret="secret")
        post = MagicMock(
            return_value=_mock_response({"access_token": "tok", "expires_in": 600})
        )
        client.session.post = post
        self.assertEqual(client._bearer(), "tok")
        # A cached, unexpired token must not trigger a second token request.
        self.assertEqual(client._bearer(), "tok")
        self.assertEqual(post.call_count, 1)

    def test_authenticated_scan_sends_bearer_header(self):
        client = _make_client(client_id="id", client_secret="secret")
        token_resp = _mock_response({"access_token": "tok", "expires_in": 600})
        scan_resp = _mock_response({"action": "allow"})
        client.session.post = MagicMock(side_effect=[token_resp, scan_resp])
        client.scan("hello")
        token_call, scan_call = client.session.post.call_args_list
        self.assertEqual(token_call.args[0], "https://auth.example.test/oauth2/token")
        self.assertEqual(
            token_call.kwargs["data"], {"grant_type": "client_credentials"}
        )
        self.assertEqual(token_call.kwargs["auth"], ("id", "secret"))
        self.assertEqual(
            scan_call.args[0], "https://example.test/detection/v1/interactions"
        )
        self.assertEqual(scan_call.kwargs["headers"]["Authorization"], "Bearer tok")


if __name__ == "__main__":
    unittest.main()
