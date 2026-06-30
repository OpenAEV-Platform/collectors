import hashlib
import secrets
import string
from datetime import datetime, timezone
from typing import Literal


class Authentication:
    """XSOAR Authentication helper."""

    def __init__(
        self,
        api_key: str,
        api_key_id: int,
        api_key_type: Literal["standard", "advanced"] = "standard",
    ):
        """Initialize with API key details."""
        self._api_key = api_key
        self._api_key_id = api_key_id
        self._api_key_type = api_key_type

    def get_headers(self) -> dict[str, str]:
        """Return headers required for XSOAR API calls."""
        headers = {
            "x-xdr-auth-id": str(self._api_key_id),
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        if self._api_key_type == "advanced":
            # Generate a 64 bytes random string
            nonce = "".join(
                [
                    secrets.choice(string.ascii_letters + string.digits)
                    for _ in range(64)
                ]
            )
            # Get the current timestamp as milliseconds.
            timestamp = int(datetime.now(timezone.utc).timestamp() * 1000)
            # Generate the auth key:
            auth_key = "%s%s%s" % (self._api_key, nonce, timestamp)
            # Calculate sha256:
            api_key_hash = hashlib.sha256(auth_key.encode("utf-8")).hexdigest()

            headers.update(
                {
                    "x-xdr-timestamp": str(timestamp),
                    "x-xdr-nonce": nonce,
                    "Authorization": api_key_hash,
                }
            )
        else:
            headers["Authorization"] = self._api_key

        return headers
