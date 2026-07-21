from pyoaev.configuration import Configuration
from pyoaev.daemons import CollectorDaemon

from openaev.configuration.config_loader import ConfigLoader
from openaev.github_crawler import GithubCrawler, extract_from_url_prefix
from openaev.processors import JsonApiProcessor, JsonFlatProcessor


class OpenAEVOpenAEV(CollectorDaemon):
    def __init__(
        self,
        configuration: Configuration,
    ) -> None:
        super().__init__(
            configuration=configuration,
            callback=self._process_message,
            collector_type="openaev_openaev",
        )
        self.openaev_url_prefix = self._configuration.get("openaev_url_prefix")
        repo_name, ref_value = extract_from_url_prefix(self.openaev_url_prefix)
        self.github_crawler = GithubCrawler(repo_name, ref_value)

    def _is_valid_json_api(self, payload: dict) -> bool:
        """check if the JSON data is in the JSON:API format"""
        return "data" in payload.keys()

    def _is_valid_json_flat(self, payload: dict) -> bool:
        """check if the JSON data is in the legacy flat JSON payload format"""
        return "payload_information" in payload.keys()

    def _process_single_payload(self, payload_path) -> str | None:
        payload = self.github_crawler.get_json(payload_path)

        openaev_import_only_native = self._configuration.get(
            "openaev_import_only_native"
        )
        if openaev_import_only_native and (
            "native_collection" not in payload or not payload["native_collection"]
        ):
            return

        if self._is_valid_json_api(payload):  # new format
            json_api_processor = JsonApiProcessor(
                api=self.api,
                logger=self.logger,
                payload_path=payload_path,
                github_crawler=self.github_crawler,
            )
            payload = json_api_processor._process_payload(payload)
        elif self._is_valid_json_flat(payload):  # legacy format
            json_flat_processor = JsonFlatProcessor(
                api=self.api,
                logger=self.logger,
                payload_path=payload_path,
                github_crawler=self.github_crawler,
            )
            payload = json_flat_processor._process_payload(payload)
        else:
            self.logger.warning(
                f"Skipping a payload that didn't match JSON:API format nor flat legacy format: {self.payload_path}"
            )
            return

        payload["payload_collector"] = self._configuration.get("collector_id")
        self.api.payload.upsert(payload)
        self.logger.info(f"Payload {payload["payload_name"]} imported")

        return payload["payload_external_id"]

    def _process_message(self) -> None:
        payload_external_ids = []
        payloads = self.github_crawler.get_json_file_paths()

        for payload_path in payloads:
            payload_external_id = self._process_single_payload(payload_path)
            if payload_external_id:
                payload_external_ids.append(payload_external_id)

        self.api.payload.deprecate(
            {
                "collector_id": self._configuration.get("collector_id"),
                "payload_external_ids": payload_external_ids,
            }
        )


if __name__ == "__main__":
    OpenAEVOpenAEV(configuration=ConfigLoader().to_daemon_config()).start()
