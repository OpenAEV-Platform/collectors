"""Template Data Converter to OAEV format."""

import logging
from typing import Any

from .exception import TemplateDataConversionError, TemplateValidationError
from .model_data import TemplateData

LOG_PREFIX = "[TemplateConverter]"


class TemplateConverter:
    """Converter for Template data to OAEV format."""

    def __init__(self) -> None:
        """Initialize the Template data converter."""
        self.logger = logging.getLogger(__name__)
        self.logger.debug(f"{LOG_PREFIX} Template converter initialized")

    def convert_data_to_oaev(self, data: list[TemplateData]) -> list[dict[str, Any]]:
        """Convert Template data to OAEV format.

        Args:
            data: List of TemplateData objects.

        Returns:
            List of OAEV data dictionaries.

        Raises:
            TemplateValidationError: If data format is invalid.
            TemplateDataConversionError: If conversion fails.

        """
        if not data:
            self.logger.debug(f"{LOG_PREFIX} No data to convert")
            return []

        if not isinstance(data, list):
            raise TemplateValidationError("data must be a list")

        try:
            self.logger.debug(
                f"{LOG_PREFIX} Converting {len(data)} data to OAEV format"
            )

            oaev_data_list = []
            converted_count = 0

            for i, single_data in enumerate(data, 1):
                if not isinstance(single_data, TemplateData):
                    self.logger.warning(
                        f"{LOG_PREFIX} Item {i} is not a TemplateData: {type(single_data)}"
                    )
                    continue

                try:
                    oaev_data = self._convert_data_to_oaev(single_data)
                    if oaev_data:
                        oaev_data_list.append(oaev_data)
                        converted_count += 1
                        self.logger.debug(
                            f"{LOG_PREFIX} Converted data {i}/{len(data)}"
                        )
                except Exception as e:
                    self.logger.warning(f"{LOG_PREFIX} Failed to convert data {i}: {e}")

            self.logger.info(
                f"{LOG_PREFIX} Conversion completed: {converted_count} data -> {len(oaev_data_list)} OAEV items"
            )

            return oaev_data_list

        except Exception as e:
            raise TemplateDataConversionError(
                f"Failed to convert data to OAEV format: {e}"
            ) from e

    def _convert_data_to_oaev(self, data: TemplateData) -> dict[str, Any]:
        """Convert a single data to OAEV format.

        Args:
            data: TemplateData object to convert.

        Returns:
            OAEV formatted data dictionary.

        Raises:
            TemplateValidationError: If data is invalid.

        """
        try:
            oaev_data = {"change-me-key": "change-me-value"}
            # oaev_data to update according to the custom data object for your collector

            self.logger.debug(
                f"{LOG_PREFIX} Successfully converted data to OAEV format"
            )
            return oaev_data

        except Exception as e:
            raise TemplateDataConversionError(
                f"Error converting data to OAEV: {e}"
            ) from e
