"""PaloAltoCortexXDR Data Converter to OAEV format."""

import logging
from typing import Any

from src.models.alert import Alert
from src.services.exception import (
    PaloAltoCortexXDRDataConversionError,
    PaloAltoCortexXDRValidationError,
)

LOG_PREFIX = "[Converter]"


class PaloAltoCortexXDRConverter:
    """Converter for PaloAltoCortexXDR alert data to OAEV format."""

    def __init__(self) -> None:
        self.logger = logging.getLogger(__name__)
        self.logger.debug(f"{LOG_PREFIX} PaloAltoCortexXDR converter initialized")

    def convert_alerts_to_oaev(self, alerts: list[Alert]) -> list[dict[str, Any]]:
        """Convert PaloAltoCortexXDR alert data to OAEV format.

        Args:
            alerts: List of Alert objects.

        Returns:
            List of OAEV data dictionaries.

        Raises:
            PaloAltoCortexXDRValidationError: If data format is invalid.
            PaloAltoCortexXDRDataConversionError: If conversion fails.

        """
        if not alerts:
            self.logger.debug(f"{LOG_PREFIX} No alerts to convert")
            return []

        if not isinstance(alerts, list):
            raise PaloAltoCortexXDRValidationError("alerts must be a list")

        try:
            self.logger.debug(
                f"{LOG_PREFIX} Converting {len(alerts)} alerts to OAEV format"
            )

            oaev_data_list = []
            converted_count = 0

            for i, alert in enumerate(alerts, 1):
                if not isinstance(alert, Alert):
                    self.logger.warning(
                        f"{LOG_PREFIX} Item {i} is not an Alert: {type(alert)}"
                    )
                    continue

                try:
                    oaev_data = self._convert_alert_to_oaev(alert)
                    if oaev_data:
                        oaev_data_list.append(oaev_data)
                        converted_count += 1
                        self.logger.debug(
                            f"{LOG_PREFIX} Converted alert {i}/{len(alerts)}: {alert.alert_id}"
                        )
                except Exception as e:
                    self.logger.warning(
                        f"{LOG_PREFIX} Failed to convert alert {i}: {e}"
                    )

            self.logger.info(
                f"{LOG_PREFIX} Conversion completed: {converted_count} alerts -> {len(oaev_data_list)} OAEV items"
            )
            return oaev_data_list

        except Exception as e:
            raise PaloAltoCortexXDRDataConversionError(
                f"Failed to convert alerts to OAEV format: {e}"
            ) from e

    def _convert_alert_to_oaev(self, alert: Alert) -> dict[str, Any]:
        """Convert a single alert to OAEV format.

        Args:
            alert: Alert object to convert.

        Returns:
            OAEV formatted data dictionary.

        Raises:
            PaloAltoCortexXDRValidationError: If alert data is invalid.

        """
        if not alert.alert_id:
            raise PaloAltoCortexXDRValidationError("Alert must have a alert_id")

        try:
            oaev_data = {
                "alert_id": {"type": "simple", "data": [alert.alert_id], "score": 95}
            }

            self.logger.debug(
                f"{LOG_PREFIX} Successfully converted alert {alert.alert_id} to OAEV format"
            )
            return oaev_data

        except Exception as e:
            raise PaloAltoCortexXDRDataConversionError(
                f"Error converting alert {alert.alert_id} to OAEV: {e}"
            ) from e
