"""Splunk Web search links for expectation traces."""

from urllib.parse import quote

SPLUNK_MANAGEMENT_PORT = ":8089"
SPLUNK_WEB_PORT = ":8000"


def build_search_url(
    base_url: str,
    spl: str,
    *,
    web_base_url: str | None = None,
    earliest: int | None = None,
    latest: int | None = None,
) -> str:
    """Build the Splunk Web link that runs a search.

    Args:
        base_url: Splunk REST API base URL (management port 8089).
        spl: The SPL search to open.
        web_base_url: Optional Splunk Web base URL, used as is. When unset,
            it is derived from ``base_url`` with port 8089 swapped for 8000.
        earliest: Optional start of the time range, Unix epoch seconds.
        latest: Optional end of the time range, Unix epoch seconds,
            exclusive as in Splunk.

    Returns:
        The Splunk Web search page URL with the encoded search, and the time
        range when given.

    """
    if web_base_url:
        web_url = web_base_url.rstrip("/")
    else:
        web_url = base_url.rstrip("/").replace(SPLUNK_MANAGEMENT_PORT, SPLUNK_WEB_PORT)
    url = f"{web_url}/en-US/app/search/search?q={quote(spl)}"
    if earliest is not None:
        url += f"&earliest={earliest}"
    if latest is not None:
        url += f"&latest={latest}"
    return url
