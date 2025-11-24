from datetime import datetime, timedelta

import pytz
from dateutil.parser import parse
from pyoaev.configuration import Configuration
from pyoaev.daemons import CollectorDaemon
from pyoaev.helpers import OpenAEVDetectionHelper
from pyoaev.signatures.signature_type import SignatureType
from pyoaev.signatures.types import MatchTypes, SignatureTypes

from crowdstrike.configuration.config_loader import ConfigLoader
from crowdstrike.crowdstrike_api_handler import CrowdstrikeApiHandler
from crowdstrike.query_strategy.alert import Alert, Item
from crowdstrike.query_strategy.base import Base


class OpenAEVCrowdStrike(CollectorDaemon):
    def __init__(
        self,
        configuration: Configuration,
        strategy: Base = None,
        detection_helper: OpenAEVDetectionHelper = None,
        signature_types=None,
    ):
        super().__init__(
            configuration=configuration,
            callback=self._process,
            collector_type="openaev_crowdstrike",
        )
        self.strategy = strategy or Alert(
            api_handler=CrowdstrikeApiHandler(
                logger=self.logger,
                client_id=self._configuration.get("crowdstrike_client_id"),
                client_secret=self._configuration.get("crowdstrike_client_secret"),
                base_url=self._configuration.get("crowdstrike_api_base_url"),
            )
        )
        self.signature_types = signature_types or [
            SignatureType(
                SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME,
                match_type=MatchTypes.MATCH_TYPE_FUZZY,
                match_score=95,
            ),
        ]
        self.detection_helper = detection_helper or OpenAEVDetectionHelper(
            self.logger,
            [signature_type.label.value for signature_type in self.signature_types],
        )
        self.scanning_delta = 45

    # --- FETCHER ---

    def _fetch_expectations(self, start_time):
        self.logger.info("Gathering expectations for executed injects")
        # Get expectation that are NOT FILLED for this collector
        expectations = self.api.inject_expectation.expectations_assets_for_source(
            self._configuration.get("collector_id")
        )
        self.logger.info(
            "Found " + str(len(expectations)) + " expectations waiting to be matched"
        )

        valid_expectations = []

        for expectation in expectations:
            # Parse the creation date of the expectation
            expectation_date = parse(
                expectation["inject_expectation_created_at"]
            ).astimezone(pytz.UTC)

            # Check if the expectation is expired: created date is greater than request start time
            if expectation_date < start_time:
                self.logger.info(
                    f"Expectation expired, failing inject {expectation['inject_expectation_inject']} "
                    f"({expectation['inject_expectation_type']})"
                )
                self.api.inject_expectation.update(
                    expectation["inject_expectation_id"],
                    {
                        "collector_id": self._configuration.get("collector_id"),
                        "result": (
                            "Not Detected"
                            if expectation["inject_expectation_type"] == "DETECTION"
                            else "Not Prevented"
                        ),
                        "is_success": False,
                    },
                )
            else:
                # Add valid expectations to the list
                valid_expectations.append(expectation)

        return valid_expectations

    # --- MATCHING ---

    def _match_expectations(
        self, alerts: list[Item], expectations
    ) -> list[dict[str, str]]:
        """
        Match OpenAEV expectations with CS alerts.

        Args:
            alerts: The list of alerts received from CS.
            expectations: The list of OpenAEV expectation to match to CS alerts.

        Returns:
            * A list of expectation traces that need to be created following all the matches, if any alerts matched any
              of the given expectations.
              OR
            * [], otherwise.
        """
        traces_to_create: list[dict[str, str]] = []

        self.logger.debug("Total expectations returned: " + str(len(expectations)))

        for expectation in expectations:
            if expectation.get("inject_expectation_signatures") is None:
                self.logger.warning(
                    f"No expected signatures found in expectation #{expectation.get('id')}"
                )
                continue

            for alert in alerts:
                if self.detection_helper.match_alert_elements(
                    signatures=expectation.get("inject_expectation_signatures"),
                    alert_data=self.strategy.get_signature_data(
                        alert, self.signature_types
                    ),
                ):
                    result: str
                    success_or_failure: bool
                    if expectation.get("inject_expectation_type") == "DETECTION":
                        success_or_failure = True
                        result = "Detected"
                    elif expectation.get("inject_expectation_type") == "PREVENTION":
                        success_or_failure = self.strategy.is_prevented(alert)
                        result = "Prevented" if success_or_failure else "Not Prevented"
                    else:
                        self.logger.warning(
                            f"Unsupported expectation type for now: {expectation.get('inject_expectation_type')}"
                        )
                        continue

                    self.api.inject_expectation.update(
                        expectation["inject_expectation_id"],
                        {
                            "collector_id": self._configuration.get("collector_id"),
                            "result": result,
                            "is_success": success_or_failure,
                            "metadata": {"alertId": self.strategy.get_alert_id(alert)},
                        },
                    )

                    # Save alert to openaev for current matched expectation. Duplicate alerts are handled by openaev itself
                    self.logger.info(
                        "Expectation matched, adding trace for expectation "
                        + expectation["inject_expectation_id"]
                        + " ("
                        + expectation["inject_expectation_type"]
                        + ")"
                    )
                    traces_to_create.append(
                        {
                            "inject_expectation_trace_expectation": expectation[
                                "inject_expectation_id"
                            ],
                            "inject_expectation_trace_source_id": self._configuration.get(
                                "collector_id"
                            ),
                            "inject_expectation_trace_alert_name": alert.display_name,
                            "inject_expectation_trace_alert_link": self._configuration.get(
                                "crowdstrike_ui_base_url"
                            )
                            + "/unified-detections/"
                            + alert.composite_id,
                            "inject_expectation_trace_date": alert.updated_timestamp,
                        }
                    )

        return traces_to_create

    # --- PROCESS ---

    def _process(self):
        """Fetch and match expectations with data from cs"""
        now = datetime.now(pytz.UTC)
        start_time = now - timedelta(minutes=self.scanning_delta)

        traces = self._match_expectations(
            alerts=self.strategy.get_raw_data(start_time),
            expectations=self._fetch_expectations(start_time),
        )

        self.api.inject_expectation_trace.bulk_create(
            payload={"expectation_traces": traces}
        )


if __name__ == "__main__":
    OpenAEVCrowdStrike(configuration=ConfigLoader().to_daemon_config()).start()
