"""Unit tests for DefenderO365Alert Pydantic model.

Verifies Graph Security API v2 alert validation and evidence filtering.
"""

import unittest
from datetime import datetime

from pydantic import ValidationError

# Import will fail initially (RED state) — model doesn't exist yet.
from src.source.defender_o365_alert_model import (
    AnalyzedMessageEvidence,
    DefenderO365Alert,
    EmailSender,
)


class TestEmailSender(unittest.TestCase):
    """Test EmailSender Pydantic model."""

    def test_email_sender_minimal(self) -> None:
        """Then EmailSender parses with no fields."""
        sender = EmailSender.model_validate({})
        self.assertIsNone(sender.email_address)
        self.assertIsNone(sender.display_name)
        self.assertIsNone(sender.domain_name)

    def test_email_sender_full(self) -> None:
        """Then EmailSender parses all fields with aliases."""
        data = {
            "emailAddress": "test@example.com",
            "displayName": "Test Sender",
            "domainName": "example.com",
        }
        sender = EmailSender.model_validate(data)
        self.assertEqual(sender.email_address, "test@example.com")
        self.assertEqual(sender.display_name, "Test Sender")
        self.assertEqual(sender.domain_name, "example.com")


class TestAnalyzedMessageEvidence(unittest.TestCase):
    """Test AnalyzedMessageEvidence Pydantic model."""

    def test_evidence_minimal(self) -> None:
        """Then AnalyzedMessageEvidence parses with no fields."""
        evidence = AnalyzedMessageEvidence.model_validate({})
        self.assertEqual(evidence.subject, None)
        self.assertEqual(evidence.threats, [])
        self.assertEqual(evidence.urls, [])

    def test_evidence_with_sender(self) -> None:
        """Then AnalyzedMessageEvidence parses nested EmailSender."""
        data = {
            "subject": "Invoice Q2",
            "p1Sender": {
                "emailAddress": "bad@evil.com",
                "domainName": "evil.com",
            },
            "receivedDateTime": "2026-07-05T10:00:00Z",
        }
        evidence = AnalyzedMessageEvidence.model_validate(data)
        self.assertEqual(evidence.subject, "Invoice Q2")
        self.assertEqual(evidence.p1_sender.email_address, "bad@evil.com")
        self.assertIsInstance(evidence.received_date_time, datetime)


class TestDefenderO365Alert(unittest.TestCase):
    """Test DefenderO365Alert Pydantic model."""

    def _minimal_alert(self) -> dict:
        """Return a minimal valid alert dict."""
        return {
            "id": "ALT-001",
            "title": "Phishing email detected",
            "status": "new",
            "severity": "high",
            "serviceSource": "microsoftDefenderForOffice365",
            "createdDateTime": "2026-07-05T14:00:00Z",
        }

    def _alert_with_mixed_evidence(self) -> dict:
        """Return an alert with mixed evidence types."""
        alert = self._minimal_alert()
        alert["evidence"] = [
            {
                "@odata.type": "#microsoft.graph.security.analyzedMessageEvidence",
                "subject": "Invoice",
                "p1Sender": {"emailAddress": "bad@evil.com"},
            },
            {
                "@odata.type": "#microsoft.graph.security.analyzedMessageEvidence",
                "subject": "Receipt",
                "p1Sender": {"emailAddress": "spam@evil.com"},
            },
            {
                "@odata.type": "#microsoft.graph.security.urlEvidence",
                "url": "https://example.com",
            },
        ]
        return alert

    def test_alert_validates_minimal(self) -> None:
        """Then a minimal alert dict validates without error."""
        alert = DefenderO365Alert.model_validate(self._minimal_alert())
        self.assertEqual(alert.id, "ALT-001")
        self.assertEqual(alert.title, "Phishing email detected")
        self.assertEqual(alert.severity, "high")
        self.assertIsInstance(alert.created_date_time, datetime)

    def test_alert_validates_full_with_evidence(self) -> None:
        """Then a full alert with evidence validates correctly."""
        alert = DefenderO365Alert.model_validate(self._alert_with_mixed_evidence())
        self.assertEqual(alert.id, "ALT-001")
        self.assertEqual(len(alert.evidence), 3)

    def test_alert_evidence_filtering(self) -> None:
        """Then evidence filtering keeps only analyzedMessageEvidence items."""
        alert = DefenderO365Alert.model_validate(self._alert_with_mixed_evidence())
        # Filter evidence to only analyzedMessageEvidence
        filtered = alert.filter_evidence()
        self.assertEqual(len(filtered), 2)
        for item in filtered:
            self.assertIsInstance(item, AnalyzedMessageEvidence)

    def test_alert_missing_required_fields(self) -> None:
        """Then a dict with missing required fields raises ValidationError."""
        data = {"id": "ALT-001"}  # missing title, status, severity, etc.
        with self.assertRaises(ValidationError):
            DefenderO365Alert.model_validate(data)

    def test_alert_preserves_raw(self) -> None:
        """Then the alert preserves the original raw dict."""
        data = self._minimal_alert()
        alert = DefenderO365Alert.model_validate(data)
        self.assertEqual(alert.raw, data)


class TestSourceDataRewrite(unittest.TestCase):
    """Test MicrosoftDefenderO365SourceData accepts raw_alert dict."""

    def test_source_data_accepts_raw_alert(self) -> None:
        """Then MicrosoftDefenderO365SourceData accepts raw_alert parameter."""
        from src.source.source_data import MicrosoftDefenderO365SourceData

        raw = {"id": "ALT-001", "title": "Test alert"}
        data = MicrosoftDefenderO365SourceData(raw_alert=raw)
        self.assertEqual(data.raw_alert, raw)

    def test_source_data_backward_compat(self) -> None:
        """Then MicrosoftDefenderO365SourceData still works with no args."""
        from src.source.source_data import MicrosoftDefenderO365SourceData

        data = MicrosoftDefenderO365SourceData()
        self.assertIsNotNone(data)


if __name__ == "__main__":
    unittest.main()
