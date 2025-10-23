"""SentinelOne Data Converter to OAEV format."""

import logging
from typing import Any

from .exception import SentinelOneDataConversionError, SentinelOneValidationError
from .model_threat import SentinelOneThreat

LOG_PREFIX = "[SentinelOneConverter]"


class SentinelOneConverter:
    """Converter for SentinelOne threat data to OAEV format."""

    def __init__(self) -> None:
        """Initialize the SentinelOne data converter."""
        self.logger = logging.getLogger(__name__)
        self.logger.debug(f"{LOG_PREFIX} SentinelOne converter initialized")

    def convert_threats_to_oaev(
        self, threats: list[SentinelOneThreat]
    ) -> list[dict[str, Any]]:
        """Convert SentinelOne threat data to OAEV format.

        Args:
            threats: List of SentinelOneThreat objects.

        Returns:
            List of OAEV data dictionaries.

        Raises:
            SentinelOneValidationError: If data format is invalid.
            SentinelOneDataConversionError: If conversion fails.

        """
        if not threats:
            self.logger.debug(f"{LOG_PREFIX} No threats to convert")
            return []

        if not isinstance(threats, list):
            raise SentinelOneValidationError("threats must be a list")

        try:
            self.logger.debug(
                f"{LOG_PREFIX} Converting {len(threats)} threats to OAEV format"
            )

            oaev_data_list = []
            converted_count = 0

            for i, threat in enumerate(threats, 1):
                if not isinstance(threat, SentinelOneThreat):
                    self.logger.warning(
                        f"{LOG_PREFIX} Item {i} is not a SentinelOneThreat: {type(threat)}"
                    )
                    continue

                try:
                    oaev_data = self._convert_threat_to_oaev(threat)
                    if oaev_data:
                        oaev_data_list.append(oaev_data)
                        converted_count += 1
                        self.logger.debug(
                            f"{LOG_PREFIX} Converted threat {i}/{len(threats)}: {threat.threat_id}"
                        )
                except Exception as e:
                    self.logger.warning(
                        f"{LOG_PREFIX} Failed to convert threat {i}: {e}"
                    )

            self.logger.info(
                f"{LOG_PREFIX} Conversion completed: {converted_count} threats -> {len(oaev_data_list)} OAEV items"
            )
            return oaev_data_list

        except Exception as e:
            raise SentinelOneDataConversionError(
                f"Failed to convert threats to OAEV format: {e}"
            ) from e

    def _convert_threat_to_oaev(self, threat: SentinelOneThreat) -> dict[str, Any]:
        """Convert a single threat to OAEV format.

        Args:
            threat: SentinelOneThreat object to convert.

        Returns:
            OAEV formatted data dictionary.

        Raises:
            SentinelOneValidationError: If threat data is invalid.

        """
        if not threat.threat_id:
            raise SentinelOneValidationError("Threat must have a threat_id")

        try:
            oaev_data = {
                "threat_id": {"type": "fuzzy", "data": [threat.threat_id], "score": 95}
            }

            if threat.hostname:
                oaev_data["target_hostname_address"] = {
                    "type": "fuzzy",
                    "data": [threat.hostname],
                    "score": 95,
                }

            self.logger.debug(
                f"{LOG_PREFIX} Successfully converted threat {threat.threat_id} to OAEV format"
            )
            return oaev_data

        except Exception as e:
            raise SentinelOneDataConversionError(
                f"Error converting threat {threat.threat_id} to OAEV: {e}"
            ) from e
