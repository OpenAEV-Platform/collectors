"""BaseCollector — lifecycle class for collector extensions.

Inherits from CollectorDaemon (pyoaev) and wires the engine,
source handler, and configuration together.
"""

from __future__ import annotations

import argparse
import logging
from typing import Any

from collectors_sdk._core.engine.engine import BasicCollectorEngine
from collectors_sdk._core.errors import (
    CollectorConfigError,
    CollectorEngineConfigError,
    CollectorSetupError,
)
from collectors_sdk._core.models.source import Source, SourceHandler
from collectors_sdk._core.protocols import (
    CollectorEngineProtocol,
    SourceHandlerProtocol,
)

LOG_PREFIX = "[Collector]"

__all__ = ["BaseCollector"]


class BaseCollector:
    """Generic base collector providing a source to a collector engine.

    Use-case agnostic: works with any source, source handler, and engine model.
    Concrete collectors subclass this and provide a Source definition.

    Note: In production, this inherits from pyoaev.daemons.CollectorDaemon.
    The SDK defines the lifecycle contract; pyoaev provides the runtime.
    """

    def __init__(
        self,
        name: str,
        source: Source,
        config: Any = None,
        collector_id: str = "",
        oaev_api: Any = None,
        source_handler_model: type[Any] | None = None,
        engine_model: type[Any] | None = None,
    ) -> None:
        """Initialize the collector.

        Args:
            name: Human-readable collector name.
            source: Source definition (data fetcher, data model, signatures).
            config: Configuration object (custom config section).
            collector_id: Unique collector instance identifier.
            oaev_api: OpenAEV API client instance.
            source_handler_model: Custom source handler class (defaults to SourceHandler).
            engine_model: Custom engine class (defaults to BasicCollectorEngine).

        Raises:
            CollectorConfigError: If collector initialization fails.
            CollectorEngineConfigError: If engine initialization fails.
        """
        self.name = name
        self.logger = logging.getLogger(__name__)

        try:
            if not isinstance(source, Source):
                raise TypeError("Source provided is not of type Source")
            self.source = source

            if source_handler_model and not issubclass(
                source_handler_model, SourceHandlerProtocol
            ):
                raise TypeError(
                    "Source handler model does not follow SourceHandlerProtocol"
                )
            source_handler_cls: type[Any] = source_handler_model or SourceHandler
            self.source_handler = source_handler_cls(config)

            if engine_model and not issubclass(
                engine_model, CollectorEngineProtocol
            ):
                raise TypeError(
                    "Engine model does not follow CollectorEngineProtocol"
                )
            self.engine_model: type[Any] = engine_model or BasicCollectorEngine

        except Exception as err:
            logging.basicConfig(level=logging.ERROR)
            self.logger = logging.getLogger(__name__)
            raise CollectorConfigError(
                f"Failed to initialize the {self.name} collector: {err}"
            ) from err

        try:
            engine_cls: type[Any] = self.engine_model
            self.engine = engine_cls(
                name=self.name,
                collector_id=collector_id,
                source=self.source,
                source_handler=self.source_handler,
                oaev_api=oaev_api,
            )
        except Exception as err:
            self.logger.info(
                f"{LOG_PREFIX} {self.name} Failure during engine configuration: {err}"
            )
            raise CollectorEngineConfigError(
                f"Failed to initialize the engine of {self.name} collector: {err}"
            ) from err

        self.logger.info(
            f"{LOG_PREFIX} {self.name} Collector initialized successfully"
        )

    def start(self) -> None:
        """Start the collector daemon lifecycle.

        Runs setup, then enters the main execution loop calling the engine
        on each cycle. Mirrors the CollectorDaemon.start() contract.
        """
        parser = argparse.ArgumentParser(description="collector daemon options")
        parser.add_argument("--dump-config-schema", action="store_true")
        args = parser.parse_args()
        if args.dump_config_schema:
            return

        self._setup()
        self.engine.run_engine()

    def _setup(self, batching: bool = False) -> None:
        """Set up the collector and configure the engine.

        Args:
            batching: Whether to enable batch processing.

        Raises:
            CollectorSetupError: If setup fails.
        """
        try:
            self.logger.info(f"{LOG_PREFIX} Starting collector setup...")
            self.logger.debug(f"{LOG_PREFIX} Configuring the collector engine...")
            self.engine.configure_engine(
                getattr(self.source_handler, "config", None), batching=batching
            )
            self.logger.info(f"{LOG_PREFIX} Collector setup completed successfully")
        except Exception as err:
            self.logger.error(f"{LOG_PREFIX} Collector setup failed: {err}")
            raise CollectorSetupError(
                f"Failed to setup the collector: {err}"
            ) from err
