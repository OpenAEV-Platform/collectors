"""HTTPLogwatcher Data Converter to OAEV format."""

import logging
from typing import Any

from src.models.logline import LogLine
from src.services.exception import (
    HTTPLogwatcherDataConversionError,
)

LOG_PREFIX = "[Converter]"


class HTTPLogwatcherConverter:
    """Converter for HTTPLogwatcher alert data to OAEV format."""

    def __init__(self) -> None:
        self.logger = logging.getLogger(__name__)
        self.logger.debug(f"{LOG_PREFIX} HTTPLogwatcher converter initialized")

    def convert_logline_to_oaev(self, logline: LogLine) -> dict[str, Any]:
        """Convert a single HTTPLogwatcher LogLine to OAEV format.

        Args:
            logline: LogLine object to convert.

        Returns:
            OAEV formatted data dictionary.

        Raises:
            HTTPLogwatcherDataConversionError: If conversion fails.

        """
        try:
            oaev_data = {
                "source_ipv4_address": {
                    "type": "fuzzy",
                    "data": [logline.ip_source],
                    "score": 95,
                }
            }

            self.logger.debug(
                f"{LOG_PREFIX} Successfully converted logline to OAEV format"
            )
            return oaev_data

        except Exception as e:
            raise HTTPLogwatcherDataConversionError(
                f"Error converting logline to OAEV: {e}"
            ) from e
