import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, Generator, List, Optional

import requests


@dataclass
class CVEFetchResult:
    vulnerabilities: List[Dict]
    total_fetched: int
    is_finished: bool
    last_index: int
    last_mod_date: Optional[datetime] = None
    error: Optional[str] = None


class NvdNistCveApiHandler:
    """
    Handler for NVD NIST CVE API interactions.
    This class is responsible for managing API requests and responses.
    """

    def __init__(self, base_url: str, api_key, logger=None):
        self.token = api_key
        self.session = requests.Session()
        if api_key:
            self.session.headers.update({"apiKey": api_key})
        self.base_url = base_url
        self.logger = logger
        self.cve_url = "/cves/2.0"
        self.source_url = "/source/2.0"
        self.source_cache: Dict[str, str] = {}

    @staticmethod
    def _update_cve_params_date(start_date: datetime, end_date: datetime) -> dict:
        """
        Generate parameters for CVE API requests based on date range.

        :param start_date: Start date for CVE data retrieval.
        :param end_date: End date for CVE data retrieval.
        :return: Dictionary of parameters for API request.
        """
        return {
            "lastModStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "lastModEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }

    def __api_request(self, url: str, params=None):
        """
        Internal method to handle API requests to NIST.
        :param url: The endpoint URL to send the request to.
        :param params: Dictionary of parameters to include in the request.
        :return: Response in JSON format or raises an exception on error.
        """
        try:
            response = self.session.get(self.base_url + url, params=params)
            if response.status_code == 200:
                # It is recommended that users "sleep" their scripts for six seconds between requests (NIST)
                time.sleep(6)
                return response.json()
            elif response.status_code == 404:
                error_data = response.headers
                if error_data.get("message") == "Invalid apiKey.":
                    raise Exception(
                        "[API] Invalid API Key provided. Please check your configuration."
                    )
                else:
                    raise Exception(f"[API] Error: {error_data.get('message')}")
            raise Exception(
                "[API] Attempting to retrieve data failed. Wait for connector to re-run..."
            )

        except Exception as err:
            self.logger.error(f"Failed to fetch cve datas: {err}")
            raise

    def __fetch_cve_data_by_page(
        self, cve_params: dict, start_index=0
    ) -> Generator[CVEFetchResult]:
        """
        Fetch CVE data from the NIST API in pages.
        :param cve_params: Dictionary of parameters for the CVE API request.
        :param start_index: Starting index for pagination.
        :return: Generator yielding CVEFetchResult objects.
        """
        cve_params_with_rate = {
            "resultsPerPage": 2000,
            "startIndex": start_index,
            **cve_params,
        }
        total_fetched = 0
        total_results = None
        is_finished = False

        while is_finished is False:
            response = self.__api_request(self.cve_url, cve_params_with_rate)
            if response is None:
                yield CVEFetchResult(
                    vulnerabilities=[],
                    last_index=cve_params_with_rate["startIndex"],
                    is_finished=True,
                    total_fetched=0,
                    error="Failed to fetch CVE data. Response is None.",
                )
                return {}

            vulnerabilities = response.get("vulnerabilities", [])
            total_fetched += len(vulnerabilities)
            total_results = response.get("totalResults", 0)

            if not vulnerabilities:
                self.logger.info("No vulnerabilities found in the response.")
                is_finished = True
            else:
                self.logger.info(
                    f"NIST Fetch Status | "
                    f"Batch: {len(vulnerabilities)} vulnerabilities fetch | "
                    f"Range: {cve_params_with_rate["startIndex"]}-{cve_params_with_rate["startIndex"]+cve_params_with_rate["resultsPerPage"]} | "
                    f"Total Progress: {start_index + total_fetched}/{total_results}"
                )
                is_finished = total_fetched + start_index >= total_results
                cve_params_with_rate["startIndex"] += cve_params_with_rate[
                    "resultsPerPage"
                ]

            yield CVEFetchResult(
                vulnerabilities=vulnerabilities,
                last_index=cve_params_with_rate["startIndex"],
                total_fetched=total_fetched,
                is_finished=is_finished,
            )

    def _get_vulnerabilities_by_date_range(
        self, start_date: datetime, end_date: datetime
    ) -> Generator[CVEFetchResult]:
        """
        Fetch CVE data from the NIST API within a specified date range.
        :param start_date: Start date for CVE data retrieval.
        :param end_date: End date for CVE data retrieval.
        :return: Generator yielding CVEFetchResult objects.
        """
        self.logger.info(f"Fetching CVE data from {start_date} to {end_date}")
        batch_length = timedelta(days=120)
        current_start_date = start_date

        while current_start_date < end_date:
            current_end_date = min(current_start_date + batch_length, end_date)
            cve_params = self._update_cve_params_date(
                current_start_date, current_end_date
            )
            self.logger.info(
                f"Batching from {current_start_date} to {current_end_date}"
            )

            is_last_batch = current_end_date >= end_date

            for result in self.__fetch_cve_data_by_page(cve_params):
                result.last_mod_date = current_end_date
                if not is_last_batch:
                    result.is_finished = False
                yield result

            current_start_date = current_end_date + timedelta(days=1)

    def _get_vulnerabilities_by_index(self, start_index=0) -> Generator[CVEFetchResult]:
        """
        Fetch CVE data from the NIST API starting from a specific index.
        :param start_index: Starting index for pagination.
        :return: Generator yielding CVEFetchResult objects.
        """
        self.logger.info(f"Fetching CVE data starting from index {start_index}")
        for result in self.__fetch_cve_data_by_page({}, start_index):
            result.last_mod_date = datetime.fromisoformat(
                result.vulnerabilities[len(result.vulnerabilities) - 1]
                .get("cve", {})
                .get("lastModified")
            )
            yield result

    def _get_source_name(self, source_identifier: str) -> Optional[str]:
        """
        Retrieve the source name for a given source identifier from the NIST API.
        :param source_identifier: The identifier of the source to retrieve.
        :return: The name of the source if found, otherwise None.
        """
        if source_identifier in self.source_cache:
            return self.source_cache[source_identifier]

        params = {"sourceIdentifier": source_identifier}
        response = self.__api_request(self.source_url, params)

        if response and "sources" in response and response["sources"]:
            source_name = response["sources"][0].get("name")
            self.source_cache[source_identifier] = source_name
            return source_name

        return None
