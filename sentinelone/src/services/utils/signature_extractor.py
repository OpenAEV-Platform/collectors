"""Signature extraction utilities for SentinelOne expectation processing."""

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from pyoaev.signatures.types import SignatureTypes

if TYPE_CHECKING:
    from pyoaev.apis.inject_expectation.model.expectation import (
        DetectionExpectation, PreventionExpectation)


class SignatureExtractor:
    """Utility class for extracting signatures from expectations."""

    @staticmethod
    def extract_hostnames(
        batch: list["DetectionExpectation | PreventionExpectation"],
    ) -> list[str]:
        """Extract unique hostnames from a batch of expectations.

        Args:
            batch: List of expectations to extract hostnames from.

        Returns:
            List of unique hostname values.

        """
        hostnames = set()
        for expectation in batch:
            for signature in expectation.inject_expectation_signatures:
                if signature.type == SignatureTypes.SIG_TYPE_TARGET_HOSTNAME_ADDRESS:
                    hostnames.add(signature.value)
        return list(hostnames)

    @staticmethod
    def extract_process_names(
        batch: list["DetectionExpectation | PreventionExpectation"],
    ) -> list[str]:
        """Extract unique parent process names from a batch of expectations.

        Args:
            batch: List of expectations to extract process names from.

        Returns:
            List of unique parent process name values.

        """
        process_names = set()
        for expectation in batch:
            for signature in expectation.inject_expectation_signatures:
                if signature.type.value == "parent_process_name":
                    process_names.add(signature.value)
        return list(process_names)

    @staticmethod
    def extract_end_date(
        batch: list["DetectionExpectation | PreventionExpectation"] | None = None,
    ) -> datetime | None:
        """Extract end_date from batch signatures.

        Args:
            batch: List of expectations to extract end_date from. If None, returns None.

        Returns:
            Parsed end_date as datetime or None if no valid end_date signature found.

        """
        if not batch:
            return None

        for expectation in batch:
            for signature in expectation.inject_expectation_signatures:
                if signature.type.value == "end_date":
                    try:
                        end_date = datetime.fromisoformat(
                            signature.value.replace("Z", "+00:00")
                        )
                        if end_date.tzinfo is None:
                            end_date = end_date.replace(tzinfo=timezone.utc)
                        return end_date
                    except (ValueError, AttributeError):
                        continue
        return None

    @staticmethod
    def group_signatures_by_type(
        expectation: "DetectionExpectation | PreventionExpectation",
        supported_signatures: list[SignatureTypes] | None = None,
    ) -> dict[str, list[dict[str, str]]]:
        """Group signatures by type for detection helper matching.

        Args:
            expectation: Single expectation to group signatures from.
            supported_signatures: List of supported signature types to filter by.
                                 If None, all signature types are included.

        Returns:
            Dictionary mapping signature types to lists of signature dictionaries
            in the format expected by detection helper (with 'value' and 'type' keys).
            Only includes signature types that are in the supported list.
            Excludes end_date as it's only used for query criteria, not matching.

        """
        supported_types = None
        if supported_signatures:
            supported_types = {
                sig_type.value if hasattr(sig_type, "value") else str(sig_type)
                for sig_type in supported_signatures
            }

        signature_groups = {}
        for sig in expectation.inject_expectation_signatures:
            sig_type = sig.type.value if hasattr(sig.type, "value") else str(sig.type)

            if supported_types and sig_type not in supported_types:
                continue

            if sig_type == "end_date":
                continue

            if sig_type not in signature_groups:
                signature_groups[sig_type] = []
            signature_groups[sig_type].append({"type": sig_type, "value": sig.value})
        return signature_groups
