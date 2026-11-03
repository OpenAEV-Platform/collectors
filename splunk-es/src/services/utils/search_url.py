"""Splunk Web search links for expectation traces."""

from urllib.parse import quote

SPLUNK_MANAGEMENT_PORT = ":8089"
SPLUNK_WEB_PORT = ":8000"


def build_search_url(
    base_url: str,
    spl: str,
    *,
    earliest: int | None = None,
    latest: int | None = None,
) -> str:
    """Build the Splunk Web link that runs a search.

    Args:
        base_url: Splunk REST API base URL (management port 8089).
        spl: The SPL search to open.
        earliest: Optional start of the time range, Unix epoch seconds.
        latest: Optional end of the time range, Unix epoch seconds,
            exclusive as in Splunk.

    Returns:
        The Splunk Web (port 8000) search page URL with the encoded search,
        and the time range when given.

    """
    web_base_url = base_url.rstrip("/").replace(SPLUNK_MANAGEMENT_PORT, SPLUNK_WEB_PORT)
    url = f"{web_base_url}/en-US/app/search/search?q={quote(spl)}"
    if earliest is not None:
        url += f"&earliest={earliest}"
    if latest is not None:
        url += f"&latest={latest}"
    return url
