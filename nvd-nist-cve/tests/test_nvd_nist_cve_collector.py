from datetime import datetime
from unittest import TestCase
from unittest.mock import MagicMock, patch

from nvd_nist_cve.nvd_nist_cve_api_handler import CVEFetchResult
from nvd_nist_cve.nvd_nist_cve_collector import NvdNistCveCollector


class NvdNistCveCollectorTest(TestCase):

    @patch.dict(
        "os.environ",
        {
            "OPENAEV_URL": "http://localhost:8080",
            "OPENAEV_TOKEN": "super-token",
            "COLLECTOR_ID": "collector-42",
            "NVD_NIST_CVE_API_KEY": "nist-api-key",
        },
    )
    def test_end_to_end_initial_dataset(self):
        # -- PREPARE --
        api_client = MagicMock()
        collector = NvdNistCveCollector()
        collector.cve_client = MagicMock()
        collector.api = api_client
        api_client.collector.get.return_value.collector_state = {
            "initial_dataset_completed": True,
            "last_modified_date_fetched": "2025-07-01T00:00:00",
        }

        # Fake CVE Data
        fake_cve_data = {
            "cve": {
                "id": "CVE-2025-0001",
                "descriptions": [{"lang": "en", "value": "Test CVE description"}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5}}]},
                "sourceIdentifier": "nist",
                "published": "2025-08-01T00:00:00",
                "vulnStatus": "ANALYZED",
                "cisaActionDue": None,
                "cisaExploitAdd": None,
                "cisaRequiredAction": None,
                "cisaVulnerabilityName": None,
                "weaknesses": [],
                "references": [{"url": "https://example.com"}],
            }
        }
        fake_result = CVEFetchResult(
            vulnerabilities=[fake_cve_data],
            last_mod_date=datetime(2025, 8, 1),
            last_index=0,
            is_finished=True,
            total_fetched=1,
        )
        collector.cve_client._get_vulnerabilities_by_date_range.return_value = iter(
            [fake_result]
        )

        # -- EXECUTE --
        collector._process_data()

        # -- ASSERT --
        args, kwargs = api_client.cve.upsert.call_args
        payload = kwargs["data"]

        assert payload["source_identifier"] == "collector-42"
        assert len(payload["cves"]) == 1
        assert payload["cves"][0]["cve_external_id"] == "CVE-2025-0001"
        assert payload["cves"][0]["cve_description"] == "Test CVE description"
        assert payload["cves"][0]["cve_cvss_v31"] == 7.5
        assert payload["cves"][0]["cve_reference_urls"] == ["https://example.com"]
        assert payload["cves"][0]["cve_vuln_status"] == "ANALYZED"
