"""URL helpers shared across the Elastic Security collector."""

from urllib.parse import urlparse, urlunparse

__all__ = ["redact_userinfo"]


def redact_userinfo(url: str) -> str:
    """Return ``url`` with any embedded userinfo (credentials) removed.

    Operators may configure ``ELASTIC_BASE_URL`` with credentials in the
    authority component (for example ``https://user:pass@host:9200``). Such a
    value must never reach the logs or be propagated into stored data, so this
    helper rebuilds the URL from the scheme, host, port and path only and drops
    the ``user:pass@`` userinfo (as well as any query string or fragment).

    Args:
        url: The URL (or URL-like string) to sanitize.

    Returns:
        The URL without userinfo, query or fragment. Falsy input is returned
        unchanged; a string without a parseable host has any leading
        ``...@`` userinfo stripped defensively.

    """
    if not url:
        return url

    text = str(url)
    parsed = urlparse(text)
    host = parsed.hostname or ""
    if not host:
        # Not a standard scheme://host URL (urlparse could not isolate a host);
        # still strip any leading "user:pass@" so credentials never leak.
        return text.rsplit("@", 1)[-1] if "@" in text else text

    if ":" in host:  # bracket IPv6 literals so the netloc stays valid
        host = f"[{host}]"
    netloc = f"{host}:{parsed.port}" if parsed.port is not None else host

    return urlunparse(parsed._replace(netloc=netloc, params="", query="", fragment=""))
