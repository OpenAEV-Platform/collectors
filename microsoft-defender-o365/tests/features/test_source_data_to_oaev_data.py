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
