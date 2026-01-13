import logging
import os
import sys

# from src import ConfigLoader
# from src.models.authentication import Authentication
# from src.services.alerts_api import AlertsAPI

# def main():
#    config = ConfigLoader()
#    auth = Authentication(
#        api_key=config.palo_alto_cortex_xdr.api_key.get_secret_value(),
#        api_key_id=config.palo_alto_cortex_xdr.api_key_id,
#        auth_type=config.palo_alto_cortex_xdr.api_key_type
#    )
#    alerts_api = AlertsAPI(auth, fqdn=config.palo_alto_cortex_xdr.fqdn)
#    response = alerts_api.get_alerts(search_from=0, search_to=10)
#
#    alerts = list(filter(
#        lambda _alert: "execution-7ea965db-1a47-464b-aa5f-2a66069d33f0" in (_alert.actor_process_command_line or ""),
#        response.reply.alerts
#    ))
#
#    for alert in alerts:
#        print(f"Alert ID: {alert.alert_id}, Severity: {alert.severity}")

LOG_PREFIX = "[Main]"


def main() -> None:
    """Define the main function to run the collector."""
    logger = logging.getLogger(__name__)

    try:
        logger.info(f"{LOG_PREFIX} Starting SentinelOne collector...")
        # collector = Collector()
        # collector.start()
    except KeyboardInterrupt:
        logger.info(f"{LOG_PREFIX} Collector stopped by user (Ctrl+C)")
        os._exit(0)
    except Exception as e:
        logger.exception(f"{LOG_PREFIX} Fatal error starting collector: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
