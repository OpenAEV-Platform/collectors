import hashlib
from datetime import datetime
from typing import Any

from pyoaev.signatures.types import SignatureTypes
from src.collector.models.data import OAEVData, TraceData


class MicrosoftDefenderSourceData:
    """Source data wrapper for Microsoft Defender alerts.

    Stores the raw alert dict verbatim so CHK.7 can serialize it without
    information loss. Accepts raw_alert parameter while maintaining
    backward compatibility with no-arg construction.
    """

    def __init__(self, alert: dict[str, Any] | None = None) -> None:
        """Initialize source data with optional raw alert dict.

        Args:
            alert: The original Graph Security API alert dict, preserved
                verbatim. If None, the instance is empty (no placeholder).
        """
        self.alert = alert
        self.value = alert.get("id") if alert else None

    def to_oaev_data(self) -> OAEVData:
        """Map alert fields to OAEVData keyed by signature type values."""

        evidence = self.alert.get("evidence", {})
        url_hashes = []
        sender_emails = []
        recipient_emails_address = []
        for item in evidence:
            p1_sender_email = item.get("p1_sender_email")
            if p1_sender_email:
                sender_emails.append(p1_sender_email)

            p2_sender_email = item.get("p2_sender_email")
            if p2_sender_email:
                sender_emails.append(p2_sender_email)

            recipient_email_address = item.get("recipient_email_address")
            if recipient_email_address:
                recipient_emails_address.append(recipient_email_address)

            for url in item.get("urls", []):
                url_hashes.append(hashlib.sha256(url.encode("utf-8")).hexdigest())
                url_hashes.append(hashlib.sha1(url.encode("utf-8")).hexdigest())
                url_hashes.append(hashlib.md5(url.encode("utf-8")).hexdigest())

        source_emails = list(dict.fromkeys(sender_emails))
        target_emails = list(dict.fromkeys(recipient_emails_address))
        url_hashes = list(dict.fromkeys(url_hashes))
        file_hash = ""
        custom_header = ""

        return OAEVData(
            **{
                SignatureTypes.SIG_TYPE_SOURCE_EMAIL.value: source_emails,
                SignatureTypes.SIG_TYPE_TARGET_EMAIL.value: target_emails,
                SignatureTypes.SIG_TYPE_URL_HASH.value: url_hashes,
                SignatureTypes.SIG_TYPE_FILE_HASH.value: file_hash,
                SignatureTypes.SIG_TYPE_EMAIL_CUSTOM_HEADER.value: custom_header,
            }
        )

    def to_traces_data(self) -> TraceData:
        """Serialize traces data into TraceData."""

        if not self.alert:
            return TraceData(
                alert_name="Microsoft Defender Alert",
                alert_link="https://security.microsoft.com",
            )

        alert_name = self.alert.get("title") or "Microsoft Defender Alert"
        alert_link = (
            self.alert.get("alertWebUrl")
            or self.alert.get("incidentWebUrl")
            or "https://security.microsoft.com"
        )
        alert_date = self._parse_datetime(self.alert.get("createdDateTime"))

        kwargs: dict[str, str | datetime] = {
            "alert_name": alert_name,
            "alert_link": alert_link,
        }
        if alert_date is not None:
            kwargs["alert_date"] = alert_date

        return TraceData(**kwargs)

    def is_prevented(self) -> bool:
        """Determine if the threat is prevented."""
        return self.alert.get("status") in ["inProgress", "resolved"]

    @staticmethod
    def is_detected() -> bool:
        """Determine if the threat is detected.
        Since the object is created only if the alert exists, thus it's always detected
        """
        return True

    def __str__(self) -> str:
        """Str output of the source data for logging purposes."""
        return str(self.value) if self.value else "<empty>"

    @staticmethod
    def _parse_datetime(value: str | None) -> datetime | None:
        if not value:
            return None
        return datetime.fromisoformat(value)
