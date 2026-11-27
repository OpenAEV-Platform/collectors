"""Tests for the Splunk Web search link builder."""

import pytest
from src.services.utils.search_url import build_search_url

SPL = 'search index="notable" src="1.2.3.4"'
ENCODED_SPL = "search%20index%3D%22notable%22%20src%3D%221.2.3.4%22"


class TestBuildSearchUrl:
    """The link targets Splunk Web, configured or derived from the REST URL."""

    def test_without_web_url_the_management_port_becomes_the_web_port(self):
        url = build_search_url("https://splunk.example.com:8089/", SPL)

        assert url == (
            "https://splunk.example.com:8000/en-US/app/search/search?q=" + ENCODED_SPL
        )

    @pytest.mark.parametrize(
        ("web_base_url", "expected_prefix"),
        [
            ("https://splunk-web.example.com", "https://splunk-web.example.com"),
            ("https://splunk-web.example.com/", "https://splunk-web.example.com"),
            ("http://10.0.0.5:9000", "http://10.0.0.5:9000"),
            ("https://proxy.example.com/splunk/", "https://proxy.example.com/splunk"),
        ],
        ids=["other-host", "trailing-slash", "custom-port", "proxy-path"],
    )
    def test_configured_web_url_is_used_as_is(self, web_base_url, expected_prefix):
        url = build_search_url(
            "https://splunk-api.example.com:8089",
            SPL,
            web_base_url=web_base_url,
        )

        assert url == (f"{expected_prefix}/en-US/app/search/search?q={ENCODED_SPL}")

    def test_configured_web_url_keeps_its_own_port_8089(self):
        """The configured URL is not rewritten, even when it uses port 8089."""
        url = build_search_url(
            "https://splunk.example.com:8089",
            SPL,
            web_base_url="https://splunk.example.com:8089",
        )

        assert url.startswith("https://splunk.example.com:8089/en-US/")

    def test_time_range_follows_the_configured_web_url(self):
        url = build_search_url(
            "https://splunk.example.com:8089",
            SPL,
            web_base_url="https://splunk-web.example.com",
            earliest=100,
            latest=200,
        )

        assert url == (
            "https://splunk-web.example.com/en-US/app/search/search?q="
            f"{ENCODED_SPL}&earliest=100&latest=200"
        )
