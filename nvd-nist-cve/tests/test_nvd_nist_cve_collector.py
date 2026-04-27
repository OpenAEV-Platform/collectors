from datetime import datetime
from unittest import TestCase
from unittest.mock import MagicMock

from nvd_nist_cve.nvd_nist_cve_api_handler import CVEFetchResult
from nvd_nist_cve.nvd_nist_cve_collector import NvdNistCveCollector
from pyoaev.configuration import Configuration


class NvdNistCveCollectorTest(TestCase):

    def test_end_to_end_initial_dataset(self):
        # -- PREPARE --
        api_client = MagicMock()
        configuration = Configuration(
            config_hints={
                "openaev_url": {"data": "http://localhost:8080"},
                "openaev_token": {"data": "super-token"},
                "collector_id": {"data": "collector-42"},
                "collector_name": {"data": "CVE by NVD NIST"},
                "collector_period": {"data": 7200, "is_number": True},
                "collector_log_level": {"data": "info"},
                "collector_icon_filepath": {"data": "nvd_nist_cve/img/icon-nist.png"},
                "nvd_nist_cve_api_key": {"data": "nist-api-key"},
                "nvd_nist_cve_api_base_url": {
                    "data": "https://services.nvd.nist.gov/rest/json"
                },
                "nvd_nist_cve_start_year": {"data": "2019"},
            }
        )
        collector = NvdNistCveCollector(configuration=configuration)
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
