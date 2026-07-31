"""Behavioural tests for source data to OAEVData mapping - Gherkin GWT Format.

Uses raw pytest with _given/_when/_then helpers matching the existing
tests/features/ pattern. No pytest-bdd.
"""

import hashlib

import pytest
from pyoaev.signatures.types import SignatureTypes
from tests.conftest import (
    _given_compacted_alert_with_duplicate_sender,
    _given_compacted_alert_with_empty_evidence,
    _given_compacted_alert_with_full_evidence,
    _given_compacted_alert_with_merged_evidence,
    _then_oaev_data_contains_hashes_from_both_urls,
    _then_oaev_data_field_is_empty_list,
    _then_oaev_data_field_is_empty_string,
    _then_oaev_data_source_email_deduplicated,
    _then_oaev_data_source_email_list,
    _then_oaev_data_target_email_list,
    _then_oaev_data_url_hash_list,
    _when_source_data_to_oaev_data_is_called,
)

# --------
# Scenarios
# --------


# Scenario Outline: Alert with full evidence maps all signature fields correctly
@pytest.mark.parametrize(
    "alert_id, p1_sender, p2_sender, recipient, url",
    [
        (
            "ALT-001",
            "bad@evil.com",
            "spam@evil.com",
            "victim@corp.com",
            "https://phish.example.com/",
        ),
    ],
    ids=["full_evidence_phishing_alert"],
)
def test_alert_with_full_evidence_maps_all_fields(
    alert_id, p1_sender, p2_sender, recipient, url
):
    """Scenario Outline: Alert with full evidence maps all signature fields correctly."""
    alert_dict = _given_compacted_alert_with_full_evidence(
        alert_id, p1_sender, p2_sender, recipient, url
    )

    # When: to_oaev_data is called
    oaev_data = _when_source_data_to_oaev_data_is_called(alert_dict)

    # Then: source email list
    _then_oaev_data_source_email_list(oaev_data, [p1_sender, p2_sender])

    # Then: target email list
    _then_oaev_data_target_email_list(oaev_data, [recipient])

    # Then: URL hash list (SHA256, SHA1, MD5)
    expected_hashes = [
        hashlib.sha256(url.encode("utf-8")).hexdigest(),
        hashlib.sha1(url.encode("utf-8")).hexdigest(),
        hashlib.md5(url.encode("utf-8")).hexdigest(),
    ]
    _then_oaev_data_url_hash_list(oaev_data, expected_hashes)

    # Then: file hash is empty string
    _then_oaev_data_field_is_empty_string(
        oaev_data, SignatureTypes.SIG_TYPE_FILE_HASH.value
    )

    # Then: custom header is empty string
    _then_oaev_data_field_is_empty_string(
        oaev_data, SignatureTypes.SIG_TYPE_EMAIL_CUSTOM_HEADER.value
    )


# Scenario: Alert with duplicate sender emails deduplicates source list
def test_alert_with_duplicate_sender_deduplicates():
    """Scenario: Alert with duplicate sender emails deduplicates source list."""
    alert_dict = _given_compacted_alert_with_duplicate_sender()

    # When: to_oaev_data is called
    oaev_data = _when_source_data_to_oaev_data_is_called(alert_dict)

    # Then: source email list contains exactly one entry
    _then_oaev_data_source_email_deduplicated(oaev_data, "bad@evil.com")


# Scenario: Alert with empty evidence produces empty lists
def test_alert_with_empty_evidence_produces_empty_lists():
    """Scenario: Alert with empty evidence produces empty lists for evidence-derived fields."""
    alert_dict = _given_compacted_alert_with_empty_evidence()

    # When: to_oaev_data is called
    oaev_data = _when_source_data_to_oaev_data_is_called(alert_dict)

    # Then: source email is empty list
    _then_oaev_data_field_is_empty_list(
        oaev_data, SignatureTypes.SIG_TYPE_SOURCE_EMAIL.value
    )

    # Then: target email is empty list
    _then_oaev_data_field_is_empty_list(
        oaev_data, SignatureTypes.SIG_TYPE_TARGET_EMAIL.value
    )

    # Then: URL hash is empty list
    _then_oaev_data_field_is_empty_list(
        oaev_data, SignatureTypes.SIG_TYPE_URL_HASH.value
    )


# Scenario: Alert with multiple evidence items merges all fields
def test_alert_with_multiple_evidence_merges_fields():
    """Scenario: Alert with multiple evidence items merges all fields."""
    alert_dict = _given_compacted_alert_with_merged_evidence()

    # When: to_oaev_data is called
    oaev_data = _when_source_data_to_oaev_data_is_called(alert_dict)

    # Then: source email list
    _then_oaev_data_source_email_list(
        oaev_data, ["sender1@evil.com", "sender2@evil.com"]
    )

    # Then: target email list
    _then_oaev_data_target_email_list(
        oaev_data, ["victim1@corp.com", "victim2@corp.com"]
    )

    # Then: URL hashes from both URLs
    _then_oaev_data_contains_hashes_from_both_urls(
        oaev_data,
        ["https://url1.example.com/", "https://url2.example.com/"],
    )


# --------
# Given Methods
# --------


def _given_compacted_alert_with_full_evidence(
    alert_id: str,
    p1_sender: str,
    p2_sender: str,
    recipient: str,
    url: str,
) -> dict:
    """Given a compacted alert with full evidence.

    Args:
        alert_id: The alert identifier.
        p1_sender: The P1 sender email address.
        p2_sender: The P2 sender email address.
        recipient: The recipient email address.
        url: The URL found in evidence.

    Returns:
        A compacted alert dict matching the structure produced by
        DefenderO365Alert.filter_evidence().
    """
    return {
        "id": alert_id,
        "status": "new",
        "alertWebUrl": "https://security.microsoft.com/alerts/" + alert_id,
        "createdDateTime": "2026-07-01T08:00:00+00:00",
        "evidence": [
            {
                "urls": [url],
                "p1_sender_email": p1_sender,
                "p1_sender_display_name": None,
                "p2_sender_email": p2_sender,
                "p2_sender_display_name": None,
                "recipient_email_address": recipient,
            }
        ],
    }


def _given_compacted_alert_with_duplicate_sender() -> dict:
    """Given a compacted alert with two evidence items sharing the same sender.

    Returns:
        A compacted alert dict with duplicate p1_sender_email values.
    """
    return {
        "id": "ALT-002",
        "status": "new",
        "alertWebUrl": "https://security.microsoft.com/alerts/ALT-002",
        "createdDateTime": "2026-07-01T09:00:00+00:00",
        "evidence": [
            {
                "urls": [],
                "p1_sender_email": "bad@evil.com",
                "p1_sender_display_name": None,
                "p2_sender_email": None,
                "p2_sender_display_name": None,
                "recipient_email_address": "victim@corp.com",
            },
            {
                "urls": [],
                "p1_sender_email": "bad@evil.com",
                "p1_sender_display_name": None,
                "p2_sender_email": None,
                "p2_sender_display_name": None,
                "recipient_email_address": "victim@corp.com",
            },
        ],
    }


def _given_compacted_alert_with_empty_evidence() -> dict:
    """Given a compacted alert with an empty evidence list.

    Returns:
        A compacted alert dict with no evidence items.
    """
    return {
        "id": "ALT-003",
        "status": "active",
        "alertWebUrl": "https://security.microsoft.com/alerts/ALT-003",
        "createdDateTime": "2026-07-01T10:00:00+00:00",
        "evidence": [],
    }


def _given_compacted_alert_with_merged_evidence() -> dict:
    """Given a compacted alert with two distinct evidence items.

    Returns:
        A compacted alert dict whose evidence list must be merged
        across items by to_oaev_data.
    """
    return {
        "id": "ALT-004",
        "status": "new",
        "alertWebUrl": "https://security.microsoft.com/alerts/ALT-004",
        "createdDateTime": "2026-07-01T11:00:00+00:00",
        "evidence": [
            {
                "urls": ["https://url1.example.com/"],
                "p1_sender_email": "sender1@evil.com",
                "p1_sender_display_name": None,
                "p2_sender_email": None,
                "p2_sender_display_name": None,
                "recipient_email_address": "victim1@corp.com",
            },
            {
                "urls": ["https://url2.example.com/"],
                "p1_sender_email": "sender2@evil.com",
                "p1_sender_display_name": None,
                "p2_sender_email": None,
                "p2_sender_display_name": None,
                "recipient_email_address": "victim2@corp.com",
            },
        ],
    }


# --------
# When Methods
# --------


def _when_source_data_to_oaev_data_is_called(alert_dict: dict):
    """When to_oaev_data is called.

    Instantiates MicrosoftDefenderO365SourceData with the provided
    compacted alert dict and invokes to_oaev_data().

    Args:
        alert_dict: A compacted alert dict as produced by
            DefenderO365Alert.filter_evidence().

    Returns:
        The OAEVData instance returned by to_oaev_data().
    """
    from src.source.source_data import MicrosoftDefenderO365SourceData

    source_data = MicrosoftDefenderO365SourceData(alert=alert_dict)
    return source_data.to_oaev_data()


# --------
# Then Methods
# --------


def _then_oaev_data_source_email_list(oaev_data, expected: list[str]) -> None:
    """Then OAEVData[SIG_TYPE_SOURCE_EMAIL] is a list containing the expected emails.

    Args:
        oaev_data: The OAEVData instance under assertion.
        expected: The expected list of sender email addresses.
    """
    actual = oaev_data.model_dump().get(SignatureTypes.SIG_TYPE_SOURCE_EMAIL.value)
    assert actual == expected, f"Expected {expected}, got {actual}"


def _then_oaev_data_target_email_list(oaev_data, expected: list[str]) -> None:
    """Then OAEVData[SIG_TYPE_TARGET_EMAIL] is a list containing the expected emails.

    Args:
        oaev_data: The OAEVData instance under assertion.
        expected: The expected list of recipient email addresses.
    """
    actual = oaev_data.model_dump().get(SignatureTypes.SIG_TYPE_TARGET_EMAIL.value)
    assert actual == expected, f"Expected {expected}, got {actual}"


def _then_oaev_data_url_hash_list(oaev_data, expected: list[str]) -> None:
    """Then OAEVData[SIG_TYPE_URL_HASH] is a list containing the expected hash digests.

    Args:
        oaev_data: The OAEVData instance under assertion.
        expected: The expected list of URL hash digests (SHA256, SHA1, MD5).
    """
    actual = oaev_data.model_dump().get(SignatureTypes.SIG_TYPE_URL_HASH.value)
    assert actual == expected, f"Expected {expected}, got {actual}"


def _then_oaev_data_field_is_empty_string(oaev_data, field: str) -> None:
    """Then OAEVData[field] is an empty string.

    Args:
        oaev_data: The OAEVData instance under assertion.
        field: The signature type field key to check.
    """
    actual = oaev_data.model_dump().get(field)
    assert actual == "", f"Expected empty string for {field}, got {actual!r}"


def _then_oaev_data_field_is_empty_list(oaev_data, field: str) -> None:
    """Then OAEVData[field] is an empty list.

    Args:
        oaev_data: The OAEVData instance under assertion.
        field: The signature type field key to check.
    """
    actual = oaev_data.model_dump().get(field)
    assert actual == [], f"Expected empty list for {field}, got {actual!r}"


def _then_oaev_data_source_email_deduplicated(oaev_data, email: str) -> None:
    """Then OAEVData[SIG_TYPE_SOURCE_EMAIL] contains exactly one entry for the email.

    Args:
        oaev_data: The OAEVData instance under assertion.
        email: The email address that must appear exactly once.
    """
    actual = oaev_data.model_dump().get(SignatureTypes.SIG_TYPE_SOURCE_EMAIL.value)
    assert actual == [email], f"Expected [{email}], got {actual}"


def _then_oaev_data_contains_hashes_from_both_urls(oaev_data, urls: list[str]) -> None:
    """Then OAEVData[SIG_TYPE_URL_HASH] contains hashes derived from both URLs.

    Verifies that SHA256, SHA1, and MD5 digests for each URL are present
    in the URL hash list.

    Args:
        oaev_data: The OAEVData instance under assertion.
        urls: The list of URLs whose hashes must be present.
    """
    actual = oaev_data.model_dump().get(SignatureTypes.SIG_TYPE_URL_HASH.value)
    for url in urls:
        sha256 = hashlib.sha256(url.encode("utf-8")).hexdigest()
        sha1 = hashlib.sha1(url.encode("utf-8")).hexdigest()
        md5 = hashlib.md5(url.encode("utf-8")).hexdigest()
        for digest in (sha256, sha1, md5):
            assert digest in actual, f"Expected {digest} in {actual}"
