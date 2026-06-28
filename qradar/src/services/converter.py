"""IBM QRadar Data Converter.

This module provides conversion functionality for IBM QRadar data types.
Handles conversion between different data formats and OAEV data.
"""

import logging
from typing import Any

from .exception import QRadarDataConversionError, QRadarValidationError
from .models import QRadarAlert
from .utils.parent_process_parser import ParentProcessParser

LOG_PREFIX = "[QRadarConverter]"


class Converter:
    """Converter for IBM QRadar data to OAEV format."""

    def __init__(self) -> None:
        """Initialize converter with logger.

        Sets up logging for the converter instance.
        """
        self.logger = logging.getLogger(__name__)
        self.parent_process_parser = ParentProcessParser()
        self.logger.debug(f"{LOG_PREFIX} IBM QRadar data converter initialized")

    def convert_data_to_oaev_data(
        self,
        data: QRadarAlert | list[QRadarAlert] | None,
    ) -> list[dict[str, Any]]:
        """Convert IBM QRadar data to OAEV format.

        Args:
            data: Raw IBM QRadar alert data.

        Returns:
            List of OAEV data dictionaries.

        Raises:
            QRadarValidationError: If data format is invalid.
            QRadarDataConversionError: If conversion fails.

        """
        if not data:
            self.logger.debug(
                f"{LOG_PREFIX} No data provided for conversion, returning empty list"
            )
            return []

        if not isinstance(data, list):
            data = [data]

        try:
            self.logger.debug(
                f"{LOG_PREFIX} Converting {len(data)} IBM QRadar alert items to OAEV format"
            )
            oaev_datas = []
            alert_count = 0
            unknown_count = 0

            for i, item in enumerate(data, 1):
                self.logger.debug(f"{LOG_PREFIX} Processing alert item {i}/{len(data)}")

                try:
                    if self._is_alert_data(item):
                        oaev_data = self._alert_data(item)
                        alert_count += 1
                        self.logger.debug(
                            f"{LOG_PREFIX} Converted IBM QRadar alert item {i}"
                        )
                    else:
                        unknown_count += 1
                        self.logger.warning(
                            f"{LOG_PREFIX} Unknown data type for item {i}: {type(item)}"
                        )
                        continue

                    if oaev_data:
                        oaev_datas.append(oaev_data)
                        self.logger.debug(
                            f"{LOG_PREFIX} Successfully converted item {i} to OAEV format"
                        )
                    else:
                        self.logger.debug(
                            f"{LOG_PREFIX} Item {i} conversion resulted in empty OAEV data - filtering out"
                        )

                except Exception as e:
                    raise QRadarDataConversionError(
                        f"Failed to convert data item {i}: {e}"
                    ) from e

            self.logger.info(
                f"{LOG_PREFIX} IBM QRadar to OAEV conversion: processed {len(data)} items -> {len(oaev_datas)} results"
            )

            self.logger.info(
                f"{LOG_PREFIX} Conversion completed: {alert_count} alerts, "
                f"{unknown_count} unknown items -> {len(oaev_datas)} OAEV items"
            )
            return oaev_datas

        except QRadarDataConversionError:
            raise
        except Exception as e:
            raise QRadarDataConversionError(
                f"Unexpected error converting data to OAEV format: {e}"
            ) from e

    def _is_alert_data(self, data: Any) -> bool:
        """Check if data is IBM QRadar alert data.

        Args:
            data: Data object to check.

        Returns:
            True if data is a QRadarAlert instance.

        """
        return isinstance(data, QRadarAlert)

    def _alert_data(self, alert_data: QRadarAlert) -> dict[str, Any]:
        """Convert IBM QRadar alert data to OAEV format.

        Args:
            alert_data: IBM QRadar alert data.

        Returns:
            OAEV formatted data dictionary.

        Raises:
            QRadarValidationError: If input type is invalid.
            QRadarDataConversionError: If conversion fails.

        """
        try:
            oaev_data = {}

            if not isinstance(alert_data, QRadarAlert):
                raise QRadarValidationError(
                    f"Invalid input type for alert conversion: {type(alert_data)}"
                )

            source_ips = self._extract_source_ips(alert_data)
            if source_ips:
                oaev_data["source_ipv4_address"] = {
                    "type": "simple",
                    "data": source_ips,
                }
                self.logger.debug(f"{LOG_PREFIX} Using source IPs: {source_ips}")

            target_ips = self._extract_target_ips(alert_data)
            if target_ips:
                oaev_data["target_ipv4_address"] = {
                    "type": "simple",
                    "data": target_ips,
                }
                self.logger.debug(f"{LOG_PREFIX} Using target IPs: {target_ips}")

            parent_process_name = self._extract_parent_process_name(alert_data)
            if parent_process_name:
                oaev_data["parent_process_name"] = {
                    "type": "fuzzy",
                    "data": [parent_process_name],
                    "score": 95,
                }
                self.logger.debug(
                    f"{LOG_PREFIX} Using parent process name: {parent_process_name}"
                )

            if alert_data.signature:
                self.logger.debug(
                    f"{LOG_PREFIX} Alert includes signature: {alert_data.signature}"
                )

            if alert_data.rule_name:
                self.logger.debug(
                    f"{LOG_PREFIX} Alert includes rule name: {alert_data.rule_name}"
                )

            self.logger.debug(
                f"{LOG_PREFIX} Converted IBM QRadar alert to OAEV with {len(oaev_data)} fields"
            )
            return oaev_data if oaev_data else {}

        except QRadarValidationError:
            raise
        except Exception as e:
            raise QRadarDataConversionError(
                f"Error converting IBM QRadar alert data to OAEV: {e}"
            ) from e

    def _extract_source_ips(self, alert_data: QRadarAlert) -> list[str]:
        """Extract source IP addresses from alert data.

        Args:
            alert_data: QRadarAlert object.

        Returns:
            List of unique source IP addresses.

        """
        source_ips = []

        if alert_data.src_ip and alert_data.src_ip not in source_ips:
            source_ips.append(alert_data.src_ip)

        return source_ips

    def _extract_target_ips(self, alert_data: QRadarAlert) -> list[str]:
        """Extract target IP addresses from alert data.

        Args:
            alert_data: QRadarAlert object.

        Returns:
            List of unique target IP addresses.

        """
        target_ips = []

        if alert_data.dst_ip and alert_data.dst_ip not in target_ips:
            target_ips.append(alert_data.dst_ip)

        return target_ips

    def _extract_parent_process_name(self, alert_data: QRadarAlert) -> str:
        """Extract parent process name from alert data.

        This method reconstructs the parent process name from the URL path
        found in the alert data.

        Args:
            alert_data: QRadarAlert object.

        Returns:
            Reconstructed parent process name if UUIDs found in URL path, empty string otherwise.

        """
        if not alert_data.url_path:
            self.logger.debug(f"{LOG_PREFIX} No URL path found in alert data")
            return ""

        try:
            self.logger.debug(
                f"{LOG_PREFIX} Extracting parent process name from URL path: {alert_data.url_path}"
            )

            uuids = self.parent_process_parser.extract_uuids_from_url_path(
                alert_data.url_path
            )
            if uuids:
                inject_uuid, agent_uuid = uuids
                parent_process_name = (
                    self.parent_process_parser.construct_parent_process_name(
                        inject_uuid, agent_uuid
                    )
                )
                self.logger.debug(
                    f"{LOG_PREFIX} Reconstructed parent process name: {parent_process_name}"
                )
                return parent_process_name
            else:
                self.logger.debug(
                    f"{LOG_PREFIX} No UUIDs found in URL path: {alert_data.url_path}"
                )
                return ""
        except Exception as e:
            self.logger.error(f"{LOG_PREFIX} Error extracting parent process name: {e}")
            return ""
