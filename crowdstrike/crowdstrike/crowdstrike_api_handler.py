from datetime import datetime

from falconpy import Alerts as CsAlerts

from crowdstrike.crowdstrike_credentials import CrowdstrikeCredentials


class CrowdstrikeApiHandler:
    def __init__(self, logger, credentials: CrowdstrikeCredentials, base_url):
        self.logger = logger
        self.credentials = credentials
        self.base_url = base_url
        self.client_id, self.client_secret = credentials.read()

        self._auth()

    def _init_service(self, service_class):
        return service_class(
            client_id=self.client_id,
            client_secret=self.client_secret,
            base_url=self.base_url,
        )

    def _auth(self):
        self.alerts = self._init_service(CsAlerts)

    def _refresh_credentials(self) -> bool:
        """Read the credentials again and authenticate again if they changed.

        Returns:
            True when the credentials changed.
        """
        try:
            credentials = self.credentials.read()
        except (OSError, ValueError) as error:
            self.logger.warning(
                f"Could not read the CrowdStrike credentials, keeping the current ones: {error}"
            )
            return False
        if credentials == (self.client_id, self.client_secret):
            return False
        self.logger.info("CrowdStrike credentials changed, authenticating again")
        self.client_id, self.client_secret = credentials
        self._auth()
        return True

    def get_alerts_v2(self, start_time: datetime):
        self._refresh_credentials()
        parameters = {
            "filter": f"timestamp:>'{start_time.isoformat()}'+type:'ldt'",
        }
        response = self.alerts.query_alerts_v2(parameters=parameters)
        # The credentials may have been rotated since the start of the run
        if response["status_code"] == 401 and self._refresh_credentials():
            response = self.alerts.query_alerts_v2(parameters=parameters)

        if response["status_code"] == 200:
            if not response["body"]["resources"]:
                self.logger.warning("No alerts found.")
                return []
            alerts_response = self.alerts.get_alerts_v2(
                composite_ids=response["body"]["resources"]
            )
            # Get detailed information for each alert
            if alerts_response["status_code"] == 200:
                return alerts_response["body"]["resources"]
            else:
                self.logger.info(
                    "No alerts ID found for this specific parameters :"
                    + str(parameters)
                )
                return []

        self.logger.error(
            "Could not fetch alerts from the Crowdstrike backend: "
            + str((response.get("body") or {}).get("errors"))
        )
        return []
