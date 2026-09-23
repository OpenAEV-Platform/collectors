"""Elastic Security Data Converter.

This module provides conversion functionality for Elastic Security data types.
Handles conversion between different data formats and OAEV data.
"""

import logging
from typing import Any

from .exception import ElasticDataConversionError, ElasticValidationError
from .models import ElasticAlert
from .utils.parent_process_parser import ParentProcessParser

LOG_PREFIX = "[ElasticConverter]"


class Converter:
    """Converter for Elastic Security data to OAEV format."""

    def __init__(self) -> None:
        """Initialize converter with logger.

        Sets up logging for the converter instance.
        """
        self.logger = logging.getLogger(__name__)
        self.parent_process_parser = ParentProcessParser()
        self.logger.debug(f"{LOG_PREFIX} Elastic Security data converter initialized")

    def convert_data_to_oaev_data(
        self,
        data: ElasticAlert | list[ElasticAlert] | None,
    ) -> list[dict[str, Any]]:
        """Convert Elastic Security data to OAEV format.

        Items that are not ``ElasticAlert`` instances are skipped (logged as
        unknown) instead of raising; an empty list is returned when no input
        is provided or when no item yields OAEV data.

        Args:
            data: Raw Elastic Security alert data.

        Returns:
            List of OAEV data dictionaries (empty if nothing converts).

        Raises:
            ElasticDataConversionError: If converting a recognized alert fails.

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
                f"{LOG_PREFIX} Converting {len(data)} Elastic Security alert items to OAEV format"
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
                            f"{LOG_PREFIX} Converted Elastic Security alert item {i}"
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
                    raise ElasticDataConversionError(
                        f"Failed to convert data item {i}: {e}"
                    ) from e

            self.logger.info(
                f"{LOG_PREFIX} Elastic Security to OAEV conversion: processed {len(data)} items -> {len(oaev_datas)} results"
            )

            self.logger.info(
                f"{LOG_PREFIX} Conversion completed: {alert_count} alerts, "
                f"{unknown_count} unknown items -> {len(oaev_datas)} OAEV items"
            )
            return oaev_datas

        except ElasticDataConversionError:
            raise
        except Exception as e:
            raise ElasticDataConversionError(
                f"Unexpected error converting data to OAEV format: {e}"
            ) from e

    def _is_alert_data(self, data: Any) -> bool:
        """Check if data is Elastic Security alert data.

        Args:
            data: Data object to check.

        Returns:
            True if data is a ElasticAlert instance.

        """
        return isinstance(data, ElasticAlert)

    def _alert_data(self, alert_data: ElasticAlert) -> dict[str, Any]:
        """Convert Elastic Security alert data to OAEV format.

        Args:
            alert_data: Elastic Security alert data.

        Returns:
            OAEV formatted data dictionary.

        Raises:
            ElasticValidationError: If input type is invalid.
            ElasticDataConversionError: If conversion fails.

        """
        try:
            oaev_data = {}

            if not isinstance(alert_data, ElasticAlert):
                raise ElasticValidationError(
                    f"Invalid input type for alert conversion: {type(alert_data)}"
                )

            source_ips = self._extract_source_ips(alert_data)
            for field, values in self._partition_by_family(
                source_ips, "source"
            ).items():
                if values:
                    oaev_data[field] = {"type": "simple", "data": values}
                    self.logger.debug(f"{LOG_PREFIX} Using {field}: {values}")

            target_ips = self._extract_target_ips(alert_data)
            for field, values in self._partition_by_family(
                target_ips, "target"
            ).items():
                if values:
                    oaev_data[field] = {"type": "simple", "data": values}
                    self.logger.debug(f"{LOG_PREFIX} Using {field}: {values}")

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

            # Carry the specific alert's identity (non-signature keys, ignored by
            # matching) so a trace can link to the exact matched alert instead of
            # a broad IP search.
            if oaev_data:
                if alert_data.alert_id:
                    oaev_data["_alert_id"] = alert_data.alert_id
                if alert_data.alert_url:
                    oaev_data["_alert_url"] = alert_data.alert_url
                if alert_data.rule_name or alert_data.signature:
                    oaev_data["_rule_name"] = (
                        alert_data.rule_name or alert_data.signature
                    )
                if alert_data.time:
                    oaev_data["_alert_time"] = alert_data.time
                # Whether this alert comes from endpoint/process telemetry (it
                # has a process context: host + pid) and could therefore carry
                # an implant marker via the drilldown. Network telemetry
                # (Suricata/Zeek: source/destination IPs, no process) cannot.
                # Drives deterministic correlation for implant injects
                # (non-signature key, ignored by matching).
                oaev_data["_endpoint_context"] = bool(
                    alert_data.host_name and alert_data.pid
                )

            self.logger.debug(
                f"{LOG_PREFIX} Converted Elastic Security alert to OAEV with {len(oaev_data)} fields"
            )
            return oaev_data if oaev_data else {}

        except ElasticValidationError:
            raise
        except Exception as e:
            raise ElasticDataConversionError(
                f"Error converting Elastic Security alert data to OAEV: {e}"
            ) from e

    @staticmethod
    def _partition_by_family(ips: list[str], role: str) -> dict[str, list[str]]:
        """Split IPs into the OAEV IPv4 / IPv6 signature fields for a role.

        Matching compares an alert's ``*_ipv4_address`` / ``*_ipv6_address``
        against the same-typed expectation signatures, so IPv6 candidates must
        not be emitted under an IPv4 field (they would never be seen).

        Args:
            ips: IP addresses to classify.
            role: ``"source"`` or ``"target"``.

        Returns:
            Mapping of OAEV signature field name to the IPs of that family.

        """
        ipv4: list[str] = []
        ipv6: list[str] = []
        for ip in ips:
            (ipv6 if ":" in str(ip) else ipv4).append(ip)
        return {f"{role}_ipv4_address": ipv4, f"{role}_ipv6_address": ipv6}

    def _extract_source_ips(self, alert_data: ElasticAlert) -> list[str]:
        """Extract source IP addresses from alert data.

        Args:
            alert_data: ElasticAlert object.

        Returns:
            List of unique source IP addresses.

        """
        source_ips: list[str] = []

        if alert_data.src_ip and alert_data.src_ip not in source_ips:
            source_ips.append(alert_data.src_ip)

        # Endpoint/process alerts have no source.ip; correlate on the host's own
        # addresses instead (host.ip), which carry the executing asset identity.
        for host_ip in alert_data.host_ips or []:
            if host_ip and host_ip not in source_ips:
                source_ips.append(host_ip)

        return source_ips

    def _extract_target_ips(self, alert_data: ElasticAlert) -> list[str]:
        """Extract target IP addresses from alert data.

        Args:
            alert_data: ElasticAlert object.

        Returns:
            List of unique target IP addresses.

        """
        target_ips = []

        if alert_data.dst_ip and alert_data.dst_ip not in target_ips:
            target_ips.append(alert_data.dst_ip)

        return target_ips

    def _extract_parent_process_name(self, alert_data: ElasticAlert) -> str:
        """Extract parent process name from alert data.

        This method reconstructs the parent process name from the URL path
        found in the alert data.

        Args:
            alert_data: ElasticAlert object.

        Returns:
            Reconstructed parent process name if UUIDs found in URL path, empty string otherwise.

        """
        # A marker recovered from the source-event drilldown is authoritative:
        # it ties the alert to a specific inject+agent (deterministic
        # correlation), unlike the URL-path heuristic.
        if alert_data.implant_marker:
            self.logger.debug(
                f"{LOG_PREFIX} Using implant marker from drilldown: "
                f"{alert_data.implant_marker}"
            )
            return alert_data.implant_marker

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
