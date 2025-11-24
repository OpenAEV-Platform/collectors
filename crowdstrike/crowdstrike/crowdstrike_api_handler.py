from datetime import datetime

from falconpy import Alerts as CsAlerts


class CrowdstrikeApiHandler:
    def __init__(self, logger, client_id, client_secret, base_url):
        self.logger = logger
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = base_url

        self._auth()

    def _init_service(self, service_class):
        return service_class(
            client_id=self.client_id,
            client_secret=self.client_secret,
            base_url=self.base_url,
        )

    def _auth(self):
        self.alerts = self._init_service(CsAlerts)

    def get_alerts_v2(self, start_time: datetime):
        parameters = {
            "filter": f"timestamp:>'{start_time.isoformat()}'+type:'ldt'",
        }
        response = self.alerts.query_alerts_v2(parameters=parameters)

        if response["status_code"] == 200:
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
