from datetime import datetime

import pytz
import requests
from dateutil.parser import parse
from dateutil.relativedelta import relativedelta
from microsoft_sentinel.api_handler import SentinelApiHandler
from pyobas.helpers import (
    OpenBASCollectorHelper,
    OpenBASConfigHelper,
    OpenBASDetectionHelper,
)


class OpenBASMicrosoftSentinel:
    def __init__(self):
        self.session = requests.Session()
        self.config = OpenBASConfigHelper(
            __file__,
            {
                # API information
                "openbas_url": {"env": "OPENBAS_URL", "file_path": ["openbas", "url"]},
                "openbas_token": {
                    "env": "OPENBAS_TOKEN",
                    "file_path": ["openbas", "token"],
                },
                # Config information
                "collector_id": {
                    "env": "COLLECTOR_ID",
                    "file_path": ["collector", "id"],
                },
                "collector_name": {
                    "env": "COLLECTOR_NAME",
                    "file_path": ["collector", "name"],
                    "default": "Microsoft Sentinel"
                },
                "collector_type": {
                    "env": "COLLECTOR_TYPE",
                    "file_path": ["collector", "type"],
                    "default": "openbas_microsoft_sentinel",
                },
                "collector_log_level": {
                    "env": "COLLECTOR_LOG_LEVEL",
                    "file_path": ["collector", "log_level"],
                    "default": "warn"
                },
                "collector_period": {
                    "env": "COLLECTOR_PERIOD",
                    "file_path": ["collector", "period"],
                    "default": 60
                },
                "collector_platform": {
                    "env": "COLLECTOR_PLATFORM",
                    "file_path": ["collector", "platform"],
                    "default": "SIEM",
                },
                "microsoft_sentinel_tenant_id": {
                    "env": "MICROSOFT_SENTINEL_TENANT_ID",
                    "file_path": ["collector", "microsoft_sentinel_tenant_id"],
                },
                "microsoft_sentinel_client_id": {
                    "env": "MICROSOFT_SENTINEL_CLIENT_ID",
                    "file_path": ["collector", "microsoft_sentinel_client_id"],
                },
                "microsoft_sentinel_client_secret": {
                    "env": "MICROSOFT_SENTINEL_CLIENT_SECRET",
                    "file_path": ["collector", "microsoft_sentinel_client_secret"],
                },
                "microsoft_sentinel_subscription_id": {
                    "env": "MICROSOFT_SENTINEL_SUBSCRIPTION_ID",
                    "file_path": ["collector", "microsoft_sentinel_subscription_id"],
                },
                "microsoft_sentinel_workspace_id": {
                    "env": "MICROSOFT_SENTINEL_WORKSPACE_ID",
                    "file_path": ["collector", "microsoft_sentinel_workspace_id"],
                },
                "microsoft_sentinel_resource_group": {
                    "env": "MICROSOFT_SENTINEL_RESOURCE_GROUP",
                    "file_path": ["collector", "microsoft_sentinel_resource_group"],
                },
                "microsoft_sentinel_edr_collectors": {
                    "env": "MICROSOFT_SENTINEL_EDR_COLLECTORS",
                    "file_path": ["collector", "microsoft_sentinel_edr_collectors"],
                },
            },
        )

        self.helper = OpenBASCollectorHelper(
            config=self.config,
            icon="microsoft_sentinel/img/icon-microsoft-sentinel.png",
            security_platform_type="SIEM",
        )

        self.log_analytics_url = "https://api.loganalytics.azure.com/v1"

        # Initialize Sentinel API
        self.sentinel_api_handler = SentinelApiHandler(
            self.helper,
            self.config.get_conf("microsoft_sentinel_tenant_id"),
            self.config.get_conf("microsoft_sentinel_client_id"),
            self.config.get_conf("microsoft_sentinel_client_secret"),
        )

        # Initialize signatures helper
        self.relevant_signatures_types = [
            "parent_process_name",
        ]
        self.openbas_detection_helper = OpenBASDetectionHelper(
            self.helper.collector_logger, self.relevant_signatures_types
        )

        self.scanning_delta = 45

    # --- EXTRACTOR ---

    def _extract_alert_link(self, columns_index, alert):
        alert_link = []
        # Direct Alert Link
        alert_link.append(alert[columns_index["AlertLink"]])
        # Extended Alert Link
        if "ExtendedLinks" in alert:
            for link in alert["ExtendedLinks"]:
                if "Href" in link:
                    alert_link.append(link["Href"])
        return alert_link

    def _extract_alert_name(self, columns_index, alert):
        display_name = [alert[columns_index["DisplayName"]]]
        return display_name

    def _extract_alert_detection_date(self, columns_index, alert):
        detection_date = [alert[columns_index["StartTime"]]]
        return detection_date

    def _extract_alert_prevention_date(self, columns_index, alert):
        prevention_date = [alert[columns_index["EndTime"]]]
        return prevention_date

    # --- MATCHING ---

    def _is_prevented(self, columns_index, alert):
        prevented_keywords = ["blocked", "quarantine", "remove", "prevented"]
        alert_name = alert[columns_index["AlertName"]].strip().lower()
        result_alert_name = any(
            prevented_keyword in alert_name for prevented_keyword in prevented_keywords
        )
        return result_alert_name

    def _match_alert_link(self, expectation, alert_link_datas) -> bool:
        # Extract expectation alert link
        alert_id_expectation = None
        for item in expectation["inject_expectation_results"]:
            self.helper.collector_logger.info(item["sourceName"])
            attached_collectors = self.config.get_conf(
                "microsoft_sentinel_edr_collectors"
            )
            if item["sourceId"] in attached_collectors:
                alert_id_expectation = item["metadata"]["alertId"]
                break

        if alert_id_expectation:
            for alert_link_data in alert_link_datas:
                if alert_id_expectation in alert_link_data:
                    return True
        return False

    def _match_alert_from_edr(self, _endpoint, columns_index, alert, expectation):
        self.helper.collector_logger.info(
            "Trying to match alert from EDR"
            + str(alert[columns_index["SystemAlertId"]])
            + " with expectation "
            + expectation["inject_expectation_id"]
        )
        match_result = self._match_alert_link(
            expectation=expectation,
            alert_link_datas=self._extract_alert_link(columns_index, alert),
        )
        if match_result:
            if self._is_prevented(columns_index, alert):
                return "PREVENTED"
            else:
                return "DETECTED"
        return False

    # --- PROCESS ---

    def _process_alerts(self):
        self.helper.collector_logger.info("Gathering expectations for executed injects")
        # Get expectation that are NOT FILLED for this collector
        expectations = (
            self.helper.api.inject_expectation.expectations_assets_for_source(
                self.config.get_conf("collector_id")
            )
        )

        self.helper.collector_logger.info(
            "Found " + str(len(expectations)) + " expectations waiting to be matched"
        )

        if not any(expectations):
            self.helper.collector_logger.info(
                "No expectations found: skipping iteration."
            )
            return

        limit_date = datetime.now().astimezone(pytz.UTC) - relativedelta(
            minutes=self.scanning_delta
        )

        # Retrieve alerts
        url = (
            self.log_analytics_url
            + "/workspaces/"
            + self.config.get_conf("microsoft_sentinel_workspace_id")
            + "/query"
        )
        body = {"query": "SecurityAlert | sort by TimeGenerated desc | take 200"}
        data = self.sentinel_api_handler._query(method="post", url=url, payload=body)

        if len(data["tables"]) == 0:
            return
        self.helper.collector_logger.info(
            "Found " + str(len(data["tables"][0]["rows"])) + " alerts"
        )
        columns = data["tables"][0]["columns"]
        columns_index = {}
        for idx, column in enumerate(columns):
            columns_index[column["name"]] = idx

        endpoint_per_asset = {}
        # For each expectation, try to find the proper alert to assign a detection or prevention result
        for expectation in expectations:
            if expectation["inject_expectation_asset"] not in endpoint_per_asset:
                endpoint_per_asset[expectation["inject_expectation_asset"]] = (
                    self.helper.api.endpoint.get(
                        expectation["inject_expectation_asset"]
                    )
                )

            # Check expired expectation
            expectation_date = parse(
                expectation["inject_expectation_created_at"]
            ).astimezone(pytz.UTC)
            if expectation_date < limit_date:
                self.helper.collector_logger.info(
                    "Expectation expired, failing inject "
                    + expectation["inject_expectation_inject"]
                    + " ("
                    + expectation["inject_expectation_type"]
                    + ")"
                )
                self.helper.api.inject_expectation.update(
                    expectation["inject_expectation_id"],
                    {
                        "collector_id": self.config.get_conf("collector_id"),
                        "result": (
                            "Not Detected"
                            if expectation["inject_expectation_type"] == "DETECTION"
                            else "Not Prevented"
                        ),
                        "is_success": False,
                    },
                )
                continue

            for alert in data["tables"][0]["rows"]:
                alert_date = parse(
                    str(alert[columns_index["TimeGenerated"]])
                ).astimezone(pytz.UTC)
                if alert_date > limit_date:
                    result = self._match_alert_from_edr(
                        endpoint_per_asset[expectation["inject_expectation_asset"]],
                        columns_index,
                        alert,
                        expectation,
                    )
                    if result is not False:
                        self.helper.collector_logger.info(
                            "Expectation matched, fulfilling expectation "
                            + expectation["inject_expectation_inject"]
                            + " ("
                            + expectation["inject_expectation_type"]
                            + ")"
                        )
                        if expectation["inject_expectation_type"] == "DETECTION":
                            self.helper.api.inject_expectation.update(
                                expectation["inject_expectation_id"],
                                {
                                    "collector_id": self.config.get_conf(
                                        "collector_id"
                                    ),
                                    "result": "Detected",
                                    "is_success": True,
                                },
                            )
                        elif (
                            expectation["inject_expectation_type"] == "PREVENTION"
                            and result == "PREVENTED"
                        ):
                            self.helper.api.inject_expectation.update(
                                expectation["inject_expectation_id"],
                                {
                                    "collector_id": self.config.get_conf(
                                        "collector_id"
                                    ),
                                    "result": "Prevented",
                                    "is_success": True,
                                },
                            )

                        # Send alert to openbas for current matched expectation. Duplicate alerts are handled by openbas itself
                        self.helper.collector_logger.info(
                            "Expectation matched, adding trace for expectation "
                            + expectation["inject_expectation_inject"]
                            + " ("
                            + expectation["inject_expectation_type"]
                            + ")"
                        )
                        self.helper.api.inject_expectation_trace.create(
                            data={
                                "inject_expectation_trace_expectation": expectation[
                                    "inject_expectation_id"
                                ],
                                "inject_expectation_trace_source_id": self.config.get_conf(
                                    "collector_id"
                                ),
                                "inject_expectation_trace_alert_name": self._extract_alert_name(
                                    columns_index, alert
                                )[
                                    0
                                ],
                                "inject_expectation_trace_alert_link": self._extract_alert_link(
                                    columns_index, alert
                                )[
                                    0
                                ],
                                "inject_expectation_trace_date": self._extract_alert_detection_date(
                                    columns_index, alert
                                )[
                                    0
                                ],
                            }
                        )

    def _process_message(self) -> None:
        self._process_alerts()

    # Start the main loop
    def start(self):
        period = self.config.get_conf("collector_period", default=120, is_number=True)
        self.helper.schedule(message_callback=self._process_message, delay=period)


if __name__ == "__main__":
    openBASMicrosoftSentinel = OpenBASMicrosoftSentinel()
    openBASMicrosoftSentinel.start()

# Avoir un bandeau pour limiter la casse: quand on a Sentinel qui tourne sans Defender -> ça ne marche pas
