"""PaloAltoCortexXSOAR Data Converter to OAEV format."""

import logging
from typing import Any

from src.services.exception import PaloAltoCortexXSOARDataConversionError
from src.services.ioc_extractor import IncidentResult

LOG_PREFIX = "[Converter]"


class PaloAltoCortexXSOARConverter:
    """Converter for PaloAltoCortexXSOAR incident data to OAEV format."""

    def __init__(self) -> None:
        self.logger = logging.getLogger(__name__)
        self.logger.debug(f"{LOG_PREFIX} PaloAltoCortexXSOAR converter initialized")

    def convert_incident_to_oaev(self, incident: IncidentResult) -> dict[str, Any]:
        """Convert a single PaloAltoCortexXSOAR IncidentResult to OAEV format.

        Args:
            incident: IncidentResult object to convert.

        Returns:
            OAEV formatted data dictionary.

        Raises:
            PaloAltoCortexXSOARDataConversionError: If conversion fails.

        """
        try:
            oaev_data = {
                "alert_id": {
                    "type": "simple",
                    "data": [incident.id],
                    "score": 95,
                }
            }

            self.logger.debug(
                f"{LOG_PREFIX} Successfully converted incident {incident.id} to OAEV format"
            )
            return oaev_data

        except Exception as e:
            raise PaloAltoCortexXSOARDataConversionError(
                f"Error converting incident {incident.id} to OAEV: {e}"
            ) from e
