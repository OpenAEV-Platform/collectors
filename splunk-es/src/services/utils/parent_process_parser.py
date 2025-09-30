"""Utility functions for parsing parent process names and extracting UUIDs.

This module provides functions to extract UUIDs from parent process names
and reconstruct them for matching purposes.
"""

import logging
import re
from typing import Optional, Tuple

LOG_PREFIX = "[ParentProcessParser]"


class ParentProcessParser:
    """Parser for extracting and reconstructing parent process name data."""

    def __init__(self) -> None:
        """Initialize the parent process parser."""
        self.logger = logging.getLogger(__name__)

        self.uuid_pattern = (
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
        )
        self.parent_process_pattern = r"obas-implant-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})-agent-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"

    def extract_uuids_from_parent_process_name(
        self, parent_process_name: str
    ) -> Optional[Tuple[str, str]]:
        """Extract UUIDs from parent process name.

        Args:
            parent_process_name: The parent process name containing UUIDs.
                Expected format: 'obas-implant-{UUID1}-agent-{UUID2}'

        Returns:
            Tuple of (inject_uuid, agent_uuid) if found, None otherwise.

        Example:
            Input: 'obas-implant-877b423b-ae91-4fc5-86c3-fa8ea3c938ba-agent-1402422f-2eaa-4fbd-80b2-b30df1b83b19'
            Output: ('877b423b-ae91-4fc5-86c3-fa8ea3c938ba', '1402422f-2eaa-4fbd-80b2-b30df1b83b19')

        """
        if not parent_process_name:
            self.logger.debug(f"{LOG_PREFIX} Empty parent process name provided")
            return None

        try:
            self.logger.debug(
                f"{LOG_PREFIX} Extracting UUIDs from: {parent_process_name}"
            )

            match = re.search(
                self.parent_process_pattern, parent_process_name, re.IGNORECASE
            )
            if match:
                inject_uuid = match.group(1)
                agent_uuid = match.group(2)
                self.logger.debug(
                    f"{LOG_PREFIX} Extracted UUIDs - inject: {inject_uuid}, agent: {agent_uuid}"
                )
                return (inject_uuid, agent_uuid)
            else:
                self.logger.warning(
                    f"{LOG_PREFIX} No UUIDs found in parent process name: {parent_process_name}"
                )
                return None

        except Exception as e:
            self.logger.error(
                f"{LOG_PREFIX} Error extracting UUIDs from parent process name: {e}"
            )
            return None

    def construct_parent_process_name(self, inject_uuid: str, agent_uuid: str) -> str:
        """Construct parent process name from UUIDs.

        Args:
            inject_uuid: The inject UUID.
            agent_uuid: The agent UUID.

        Returns:
            Constructed parent process name.

        Example:
            Input: inject_uuid='877b423b-ae91-4fc5-86c3-fa8ea3c938ba',
                   agent_uuid='1402422f-2eaa-4fbd-80b2-b30df1b83b19'
            Output: 'obas-implant-877b423b-ae91-4fc5-86c3-fa8ea3c938ba-agent-1402422f-2eaa-4fbd-80b2-b30df1b83b19'

        """
        if not inject_uuid or not agent_uuid:
            self.logger.warning(
                f"{LOG_PREFIX} Missing UUIDs for parent process construction"
            )
            return ""

        try:
            parent_process_name = f"obas-implant-{inject_uuid}-agent-{agent_uuid}"
            self.logger.debug(
                f"{LOG_PREFIX} Constructed parent process name: {parent_process_name}"
            )
            return parent_process_name

        except Exception as e:
            self.logger.error(
                f"{LOG_PREFIX} Error constructing parent process name: {e}"
            )
            return ""

    def extract_uuids_from_url_path(self, url_path: str) -> Optional[Tuple[str, str]]:
        """Extract UUIDs from URL path.

        Args:
            url_path: URL path containing UUIDs.
                Expected format: '/api/injects/{UUID1}/{UUID2}/executable-payload'

        Returns:
            Tuple of (inject_uuid, agent_uuid) if found, None otherwise.

        Example:
            Input: '/api/injects/877b423b-ae91-4fc5-86c3-fa8ea3c938ba/1402422f-2eaa-4fbd-80b2-b30df1b83b19/executable-payload'
            Output: ('877b423b-ae91-4fc5-86c3-fa8ea3c938ba', '1402422f-2eaa-4fbd-80b2-b30df1b83b19')

        """
        if not url_path:
            self.logger.debug(f"{LOG_PREFIX} Empty URL path provided")
            return None

        try:
            self.logger.debug(
                f"{LOG_PREFIX} Extracting UUIDs from URL path: {url_path}"
            )

            url_pattern = r"/api/injects/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/executable-payload"

            match = re.search(url_pattern, url_path, re.IGNORECASE)
            if match:
                inject_uuid = match.group(1)
                agent_uuid = match.group(2)
                self.logger.debug(
                    f"{LOG_PREFIX} Extracted UUIDs from URL - inject: {inject_uuid}, agent: {agent_uuid}"
                )
                return (inject_uuid, agent_uuid)
            else:
                self.logger.warning(
                    f"{LOG_PREFIX} No UUIDs found in URL path: {url_path}"
                )
                return None

        except Exception as e:
            self.logger.error(f"{LOG_PREFIX} Error extracting UUIDs from URL path: {e}")
            return None

    def build_url_path_search_query(self, inject_uuid: str, agent_uuid: str) -> str:
        """Build URL path search query from UUIDs.

        Args:
            inject_uuid: The inject UUID.
            agent_uuid: The agent UUID.

        Returns:
            URL path search query string.

        Example:
            Input: inject_uuid='877b423b-ae91-4fc5-86c3-fa8ea3c938ba',
                   agent_uuid='1402422f-2eaa-4fbd-80b2-b30df1b83b19'
            Output: 'url_path="/api/injects/877b423b-ae91-4fc5-86c3-fa8ea3c938ba/1402422f-2eaa-4fbd-80b2-b30df1b83b19/executable-payload"'

        """
        if not inject_uuid or not agent_uuid:
            self.logger.warning(f"{LOG_PREFIX} Missing UUIDs for URL path search query")
            return ""

        try:
            url_path = f"/api/injects/{inject_uuid}/{agent_uuid}/executable-payload"

            url_fields = ["url_path", "url", "path", "query"]
            url_conditions = []
            for field in url_fields:
                url_conditions.append(f'{field}="{url_path}"')

            search_query = f"({' OR '.join(url_conditions)})"
            self.logger.debug(
                f"{LOG_PREFIX} Built URL path search query: {search_query}"
            )
            return search_query

        except Exception as e:
            self.logger.error(f"{LOG_PREFIX} Error building URL path search query: {e}")
            return ""

    def validate_uuid_format(self, uuid_string: str) -> bool:
        """Validate if string matches UUID format.

        Args:
            uuid_string: String to validate.

        Returns:
            True if string matches UUID format, False otherwise.

        """
        if not uuid_string:
            return False

        try:
            return bool(re.match(f"^{self.uuid_pattern}$", uuid_string, re.IGNORECASE))
        except Exception:
            return False
