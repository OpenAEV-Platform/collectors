import hashlib
from datetime import datetime, timezone
from unittest.mock import patch

from src.models.authentication import Authentication


def test_authentication_standard():
    api_key = "test-api-key"
    api_key_id = "test-api-key-id"
    auth = Authentication(
        api_key=api_key, api_key_id=api_key_id, api_key_type="standard"
    )

    headers = auth.get_headers()

    assert headers["Authorization"] == api_key
    assert headers["x-xdr-auth-id"] == api_key_id
    assert headers["Content-Type"] == "application/json"
    assert headers["Accept"] == "application/json"


@patch("src.models.authentication.secrets.choice")
@patch("src.models.authentication.datetime")
def test_authentication_advanced(mock_datetime, mock_secrets_choice):
    api_key = "test-api-key"
    api_key_id = "test-api-key-id"

    # Mock nonce generation: 64 'a's
    mock_secrets_choice.return_value = "a"
    nonce = "a" * 64

    # Mock timestamp: 1619517600.0 (2021-04-27 10:00:00 UTC) -> 1619517600000 ms
    # Note: 2021-04-27 10:00:00 UTC timestamp is 1619517600
    fixed_now = datetime(2021, 4, 27, 10, 0, 0, tzinfo=timezone.utc)
    mock_datetime.now.return_value = fixed_now
    timestamp = int(fixed_now.timestamp() * 1000)

    auth = Authentication(
        api_key=api_key, api_key_id=api_key_id, api_key_type="advanced"
    )

    headers = auth.get_headers()

    # Calculate expected hash
    auth_key = f"{api_key}{nonce}{timestamp}"
    expected_hash = hashlib.sha256(auth_key.encode("utf-8")).hexdigest()

    print(f"Timestamp: {timestamp}")
    print(f"Expected hash: {expected_hash}")
    print(f"Actual hash: {headers['Authorization']}")

    assert headers["Authorization"] == expected_hash
    assert headers["x-xdr-auth-id"] == api_key_id
    assert headers["x-xdr-timestamp"] == str(timestamp)
    assert headers["x-xdr-nonce"] == nonce
    assert headers["Content-Type"] == "application/json"
    assert headers["Accept"] == "application/json"
