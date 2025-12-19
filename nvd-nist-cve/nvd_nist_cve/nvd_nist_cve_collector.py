from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Generator, Optional

from nvd_nist_cve.nvd_nist_cve_api_handler import NvdNistCveApiHandler
from nvd_nist_cve.nvd_nist_cve_configuration import NvdNistCveConfiguration
from pyoaev.configuration import Configuration
from pyoaev.daemons import CollectorDaemon


@dataclass
class CVEProcessor:
    message: str
    data_generator: Generator
    state_updater: callable


class NvdNistCveCollector(CollectorDaemon):
    def __init__(self, configuration: Configuration):
        """
        Initialize NVD NIST CVE collector.

        Raises:
            If configuration is invalid
        """
        try:
            self.cve_config = NvdNistCveConfiguration()

            super().__init__(
                configuration=configuration,
                callback=self._process_data,
                collector_type="openaev_nvd_nist_cve",
            )
            self.cve_client = None
            self.logger.info("Nvd Nist CVE Collector initialized successfully")

        except Exception as e:
            print(f"Collector failed to start: {e}")
            raise

    def _setup(self):
        """
        Setup method for NVD NIST CVE collector.

        Initializes the client and prepares for data processing.
        """
        super()._setup()

        self.cve_client = NvdNistCveApiHandler(
            api_key=self._configuration.get("nvd_nist_cve_api_key"),
            base_url=self._configuration.get("nvd_nist_cve_api_base_url"),
            logger=self.logger,
        )

        self.logger.info("Setup complete for NVD NIST CVE collector")

    @staticmethod
    def format_str_timestamp(date_str: str) -> Optional[str]:
        return (
            datetime.fromisoformat(date_str).strftime("%Y-%m-%dT%H:%M:%SZ")
            if date_str
            else None
        )

    @staticmethod
    def datetime_to_iso_string(date: datetime) -> Optional[str]:
        return date.strftime("%Y-%m-%dT%H:%M:%SZ") if date else None

    def __get_english_description(self, descriptions: list) -> str:
        """
        Extract the English description from a list of descriptions from a NIST CVE.
        :param descriptions: List of description dictionaries, each containing 'lang' and 'value'.
        :return: The English description value if available, otherwise an empty string.
        """
        if descriptions is None or len(descriptions) == 0:
            return ""
        return [
            description
            for description in descriptions
            if description.get("lang") == "en"
        ][0]["value"]

    def __format_cwes(self, cwe_datas: list) -> list:
        """
        Format the CWE data from NIST CVE into OpenAEV API Cwe format.
        :param cwe_datas: List of CWE data dictionaries, from NIST CVE.
        :return: List of formatted CWE dictionaries for OpenAEV API.
        """
        cwes_formatted = []
        for cwe in cwe_datas:
            external_id = self.__get_english_description(cwe.get("description", []))
            existing_cwe = next(
                (
                    cwe
                    for cwe in cwes_formatted
                    if cwe["cwe_external_id"] == external_id
                ),
                None,
            )
            source = self.cve_client._get_source_name(cwe.get("source"))

            if existing_cwe is not None:
                existing_cwe["cwe_source"] = existing_cwe["cwe_source"] + "," + source
            else:
                cwes_formatted.append(
                    {
                        "cwe_external_id": external_id,
                        "cwe_source": source,
                    }
                )

        return cwes_formatted

    def __format_vulnerability_status(self, status: str) -> str | None:
        """
        Format the vulnerability status from NIST CVE into OpenAEV API format.
        :param status: The status string from NIST CVE
        :return: Formatted status string for OpenAEV API if valid, otherwise None.
        """
        if status is None:
            return None
        status_upper = status.upper()
        valid_statuses = {"ANALYZED", "DEFERRED", "MODIFIED"}
        return status_upper if status_upper in valid_statuses else None

    def __extract_unique_urls(self, references: list) -> list[str]:
        """
        Extract unique URLs from the references of a NIST CVE.
        :param references: List of reference dictionaries, each containing a 'url' key.
        :return: List of unique URLs extracted from the references.
        """
        if not references:
            return []

        urls = [ref.get("url") for ref in references if ref.get("url")]
        return list(dict.fromkeys(urls))

    def __filter_and_format_cve(self, datas: dict) -> list[dict]:
        """
        Filter and format CVE data from NIST CVE API response to match OpenAEV API format.
        :param datas: List of CVE data dictionaries from NIST CVE API.
        :return: List of formatted CVE dictionaries for OpenAEV API.
        """
        vulnerabilities = []
        for data in datas:
            if data["cve"]["metrics"].get("cvssMetricV31", None) is None:
                continue
            vulnerabilities.append(
                {
                    "cve_external_id": data["cve"]["id"],
                    "cve_cvss_v31": data["cve"]["metrics"]
                    .get("cvssMetricV31", [{}])[0]
                    .get("cvssData", {})
                    .get("baseScore", None),
                    "cve_description": self.__get_english_description(
                        data["cve"].get("descriptions", None)
                    ),
                    "cve_source_identifier": data["cve"].get("sourceIdentifier"),
                    "cve_published": self.format_str_timestamp(
                        data["cve"].get("published")
                    ),
                    "cve_vuln_status": self.__format_vulnerability_status(
                        data["cve"].get("vulnStatus")
                    ),
                    "cve_cisa_action_due": self.format_str_timestamp(
                        data["cve"].get("cisaActionDue")
                    ),
                    "cve_cisa_exploit_add": self.format_str_timestamp(
                        data["cve"].get("cisaExploitAdd")
                    ),
                    "cve_cisa_required_action": data["cve"].get(
                        "cisaRequiredAction", None
                    ),
                    "cve_cisa_vulnerability_name": data["cve"].get(
                        "cisaVulnerabilityName", None
                    ),
                    "cve_cwes": (
                        self.__format_cwes(data["cve"].get("weaknesses"))
                        if "weaknesses" in data["cve"]
                        else []
                    ),
                    "cve_reference_urls": self.__extract_unique_urls(
                        data["cve"].get("references")
                    ),
                }
            )
        return vulnerabilities

    def __send_cves_bundle_to_api(
        self,
        cves: list[dict],
        last_modified_date_fetched: datetime,
        state_info: dict = None,
    ) -> None:
        """
        Send a bundle of CVEs to the OpenAEV API.
        :param cves: List of CVE dictionaries formatted for OpenAEV API.
        :param last_modified_date_fetched: Last modified date of the CVEs, used for state management.
        :param state_info: Additional state information to be included in the API request (optional).
        :return: None
        """
        self.api.cve.upsert(
            data={
                "source_identifier": self.get_id(),
                "cves": cves,
                "last_modified_date_fetched": self.datetime_to_iso_string(
                    last_modified_date_fetched
                ),
                **(state_info or {}),
            }
        )

    def __get_processor_to_initialisation(self, collector_state) -> CVEProcessor:
        """
        Prepare the processor for the initial dataset collection of NVD NIST CVE.
        :param collector_state: Current state of the collector, used to determine the last index processed.
        :return: Dictionary containing the message, data generator, and state updater function.
        """
        state_updater = lambda result: {
            "last_index": result.last_index,
            "initial_dataset_completed": result.is_finished,
        }
        return CVEProcessor(
            message="Starting initial dataset for NVD NIST CVE collector",
            data_generator=self.cve_client._get_vulnerabilities_by_index(
                collector_state.get("last_index", 0)
            ),
            state_updater=state_updater,
        )

    def __get_processor_to_update(self, collector_state) -> CVEProcessor:
        """
        Prepare the processor for updating the NVD NIST CVE collector with new data.
        :param collector_state: Current state of the collector, used to determine the last modified date fetched.
        :return: Dictionary containing the message, data generator, and state updater function.
        """
        start_date = (
            datetime(2019, 1, 1)
            if collector_state.get("last_modified_date_fetched") is None
            else datetime.fromisoformat(
                collector_state.get("last_modified_date_fetched")
            )
        )
        now = datetime.now(timezone.utc).replace(microsecond=0)

        return CVEProcessor(
            message="Starting updates for NVD NIST CVE collector",
            data_generator=self.cve_client._get_vulnerabilities_by_date_range(
                start_date, now
            ),
            state_updater=lambda result: {
                "last_modified_date_fetched": self.datetime_to_iso_string(
                    result.last_mod_date
                )
            },
        )

    def _process_data(self):
        """
        Process data for NVD NIST CVE collector.
        :return: None
        """
        # Fetch collector status
        collector_info = self.api.collector.get(self.get_id())
        collector_state = getattr(collector_info, "collector_state", {}) or {}

        counters = {"total_fetched": 0, "total_send": 0}

        # Determine processing mode and get data generator
        if not collector_state.get("initial_dataset_completed"):
            processor = self.__get_processor_to_initialisation(collector_state)
        else:
            processor = self.__get_processor_to_update(collector_state)

        self.logger.info(processor.message)

        for result in processor.data_generator:
            counters["total_fetched"] += len(result.vulnerabilities)
            formatted_cves = self.__filter_and_format_cve(result.vulnerabilities)
            counters["total_send"] += len(formatted_cves)
            self.__send_cves_bundle_to_api(
                formatted_cves, result.last_mod_date, processor.state_updater(result)
            )
            if result.is_finished:
                self.logger.info("Data processing completed")
                self.logger.info(
                    f"{counters['total_fetched']} total vulnerabilities fetched from NIST"
                )
                self.logger.info(
                    f"{counters['total_send']} total vulnerabilities that contains CVSS 3.1 and sent to API"
                )
                break
