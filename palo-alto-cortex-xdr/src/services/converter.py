"""PaloAltoCortexXDR Data Converter to OAEV format."""

import logging
from typing import Any

from src.models.alert import Alert
from src.services.exception import (
    PaloAltoCortexXDRDataConversionError,
)

LOG_PREFIX = "[Converter]"


class PaloAltoCortexXDRConverter:
    """Converter for PaloAltoCortexXDR alert data to OAEV format."""

    def __init__(self) -> None:
        self.logger = logging.getLogger(__name__)
        self.logger.debug(f"{LOG_PREFIX} PaloAltoCortexXDR converter initialized")

    def convert_alert_to_oaev(self, alert: Alert) -> dict[str, Any]:
        """Convert a single PaloAltoCortexXDR Alert to OAEV format.

        Args:
            alert: Alert object to convert.

        Returns:
            OAEV formatted data dictionary.

        Raises:
            PaloAltoCortexXDRDataConversionError: If conversion fails.

        """
        try:
            oaev_data = {
                "alert_id": {
                    "type": "simple",
                    "data": [alert.alert_id],
                    "score": 95,
                }
            }

            self.logger.debug(
                f"{LOG_PREFIX} Successfully converted alert {alert.alert_id} to OAEV format"
            )
            return oaev_data

        except Exception as e:
            raise PaloAltoCortexXDRDataConversionError(
                f"Error converting alert {alert.alert_id} to OAEV: {e}"
            ) from e
