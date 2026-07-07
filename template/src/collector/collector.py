import logging

from pyoaev.daemons import CollectorDaemon
from slugify import slugify
from src.collector.engines.basic import BasicCollectorEngine
from src.collector.models.exception import (
    CollectorConfigError,
    CollectorEngineConfigError,
    CollectorSetupError,
)
from src.collector.models.source import (
    Source,
    SourceHandler,
)
from src.collector.protocols.engine import CollectorEngineProtocol
from src.collector.protocols.source_handler import SourceHandlerProtocol
from src.models.settings.config_loader import ConfigLoader

LOG_PREFIX = "[Collector]"


class BaseCollector(CollectorDaemon):
    """
    Generic BaseCollector providing a defined source to a generic collector engine.
    This collector is use-case agnostic and works with any source provided.
    """

    def __init__(
        self,
        name: str,
        source: Source,
        source_handler_model: type[SourceHandlerProtocol] | None = None,
        engine_model: type[CollectorEngineProtocol] | None = None,
    ) -> None:
        """Initialize the collector.

        Raises:
            CollectorConfigError: If collector initialization fails.
            CollectorEngineConfigError: If collector engine initialization fails.
        """
        self.name = name

        try:
            self.config = ConfigLoader()

            super().__init__(
                configuration=self.config.to_daemon_config(),
                collector_type=f"openaev_{slugify(self.name, separator="_")}",
            )

            self.logger.info(
                f"{LOG_PREFIX} {self.name} Collector initialized successfully"
            )

            if source and not isinstance(source, Source):
                self.logger.error(f"{LOG_PREFIX} Source provided is not of type Source")
                raise TypeError("Source provided is not of type Source")
            self.source = source

            if source_handler_model and not issubclass(
                source_handler_model, SourceHandlerProtocol
            ):
                self.logger.error(
                    f"{LOG_PREFIX} Source handler model provided does not follow source handler protocol"
                )
                raise TypeError(
                    "Source handler model provided does not follow source handler protocol"
                )
            source_handler_model = source_handler_model or SourceHandler
            self.source_handler = source_handler_model(self.config.custom)

            if engine_model and not issubclass(engine_model, CollectorEngineProtocol):
                self.logger.error(
                    f"{LOG_PREFIX} Engine model provided does not follow collector engine protocol"
                )
                raise TypeError(
                    "Engine model provided does not follow collector engine protocol"
                )
            self.engine_model = engine_model or BasicCollectorEngine

        except Exception as err:
            logging.basicConfig(level=logging.ERROR)
            self.logger = logging.getLogger(__name__)
            raise CollectorConfigError(
                f"Failed to initialize the {self.name} collector: {err}"
            ) from err

        try:
            self.engine = self.engine_model(
                name=self.name,
                collector_id=self.get_id(),
                source=self.source,
                source_handler=self.source_handler,
                oaev_api=self.api,
            )
            self.set_callback(self.engine.run_engine)
        except Exception as err:
            self.logger.info(
                f"{LOG_PREFIX} {self.name} Failure during collector engine configuration: {err}"
            )
            raise CollectorEngineConfigError(
                f"Failed to initialize the engine of {self.name} collector: {err}"
            ) from err

    def _setup(self, batching: bool = False) -> None:
        """Set up the collector.

        Setup the collector daemon and configure the engine.
        Set up the collector for processing expectations.

        Raises:
            CollectorSetupError: If collector setup fails.

        """
        try:
            self.logger.info(f"{LOG_PREFIX} Starting collector setup...")

            super()._setup()

            self.logger.debug(f"{LOG_PREFIX} Configuring the collector engine...")
            self.engine.configure_engine(self.config.custom, batching=batching)

            self.logger.info(f"{LOG_PREFIX} Collector setup completed successfully")

        except Exception as err:
            self.logger.error(f"{LOG_PREFIX} Collector setup failed: {err}")
            raise CollectorSetupError(f"Failed to setup the collector: {err}") from err
