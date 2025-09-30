"""Core collector."""

import os

from pyobas.daemons import CollectorDaemon  # type: ignore[import-untyped]
from pyobas.helpers import OpenBASDetectionHelper  # type: ignore[import-untyped]
from src.services.expectation_service import SentinelOneExpectationService
from src.services.trace_service import SentinelOneTraceService
from src.services.utils import SentinelOneConfig

from .exception import (
    CollectorConfigError,
    CollectorProcessingError,
    CollectorSetupError,
)
from .expectation_handler import GenericExpectationHandler
from .expectation_manager import GenericExpectationManager

LOG_PREFIX = "[Collector]"


class Collector(CollectorDaemon):  # type: ignore[misc]
    """Generic Collector using service provider pattern.

    This collector is use-case agnostic and works with any service provider.
    """

    def __init__(self) -> None:
        """Initialize the collector.

        Raises:
            CollectorConfigError: If collector initialization fails.

        """
        try:
            self.config = SentinelOneConfig()
            self.config_instance = self.config.load

            super().__init__(
                configuration=self.config_instance.to_daemon_config(),
                callback=self._process_callback,
                collector_type="openbas_sentinelone",
            )

            self.logger.info(  # type: ignore[has-type]
                f"{LOG_PREFIX} SentinelOne Collector initialized successfully"
            )

        except Exception as err:
            import logging

            logging.basicConfig(level=logging.ERROR)
            self.logger = logging.getLogger(__name__)
            self.logger.error(f"{LOG_PREFIX} Failed to initialize collector: {err}")
            raise CollectorConfigError(
                f"Failed to initialize the collector: {err}"
            ) from err

    def _setup(self) -> None:
        """Set up the collector.

        Initializes SentinelOne services, expectation handler, expectation manager,
        and OpenBAS detection helper. Sets up the collector for processing expectations.

        Raises:
            CollectorSetupError: If collector setup fails.

        """
        try:
            self.logger.info(f"{LOG_PREFIX} Starting collector setup...")

            super()._setup()

            self.logger.debug(f"{LOG_PREFIX} Initializing SentinelOne services...")

            self.sentinelone_service = SentinelOneExpectationService(
                self.config_instance
            )

            self.trace_service = SentinelOneTraceService(self.config_instance)

            self.expectation_handler = GenericExpectationHandler(
                self.sentinelone_service
            )

            self.expectation_manager = GenericExpectationManager(
                oaev_api=self.api,
                collector_id=self.get_id(),
                expectation_handler=self.expectation_handler,
                trace_service=self.trace_service,
            )

            supported_signatures = self.sentinelone_service.get_supported_signatures()
            self.oaev_detection_helper = OpenBASDetectionHelper(
                logger=self.logger,
                relevant_signatures_types=supported_signatures,
            )

            self.logger.info(f"{LOG_PREFIX} Collector setup completed successfully")
            self.logger.info(
                f"{LOG_PREFIX} Supported signatures: {[sig.value for sig in supported_signatures]}"
            )

            service_info = self.sentinelone_service.get_service_info()
            self.logger.debug(f"{LOG_PREFIX} Service info: {service_info}")

        except Exception as err:
            self.logger.error(f"{LOG_PREFIX} Collector setup failed: {err}")
            raise CollectorSetupError(f"Failed to setup the collector: {err}") from err

    def _process_callback(self) -> None:
        """Process the callback for expectation processing.

        Executes a single processing cycle, handling expectations through the
        expectation manager and logging results. Handles keyboard interrupts
        and system exits gracefully.

        Raises:
            CollectorProcessingError: If processing cycle fails.

        """
        try:
            self.logger.info(f"{LOG_PREFIX} Starting processing cycle...")
            self.logger.debug(
                f"{LOG_PREFIX} Processing expectations using SentinelOne services"
            )

            results = self.expectation_manager.process_expectations(
                detection_helper=self.oaev_detection_helper
            )

            self.logger.info(
                f"{LOG_PREFIX} Processing cycle completed: {results.processed} total, "
                f"{results.valid} valid, {results.invalid} invalid, "
                f"{results.skipped} skipped"
            )

        except (KeyboardInterrupt, SystemExit):
            self.logger.info(f"{LOG_PREFIX} Collector stopping...")
            os._exit(0)
        except Exception as e:
            self.logger.error(f"{LOG_PREFIX} Error during processing cycle: {str(e)}")
            raise CollectorProcessingError(f"Processing error: {str(e)}") from e
