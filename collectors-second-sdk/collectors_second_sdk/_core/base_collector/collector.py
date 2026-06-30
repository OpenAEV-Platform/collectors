"""BaseCollector — generic collector providing a source to a collector engine.

Use-case agnostic: works with any source, source handler, and engine model.
Concrete collectors subclass this and provide a Source definition.

The oaev_api client is auto-created from ConfigBaseSettings when not
explicitly provided — requires OPENAEV_URL/OPENAEV_TOKEN in env or config.yml.
"""

from __future__ import annotations

import argparse
import logging
from typing import Any

from collectors_second_sdk._core.base_collector.engines.basic import BasicCollectorEngine
from collectors_second_sdk._core.base_collector.models.exception import (
    CollectorConfigError,
    CollectorEngineConfigError,
    CollectorSetupError,
)
from collectors_second_sdk._core.base_collector.models.source import Source, SourceHandler
from collectors_second_sdk._core.base_collector.protocols.engine import CollectorEngineProtocol
from collectors_second_sdk._core.base_collector.protocols.source_handler import SourceHandlerProtocol
from pyoaev.utils import setup_logging_config

LOG_PREFIX = "[Collector]"


class BaseCollector:
    """Generic base collector providing a source to a collector engine.

    Use-case agnostic: works with any source, source handler, and engine model.
    Concrete collectors subclass this and provide a Source definition.

    The oaev_api client is auto-created from ConfigBaseSettings when not
    explicitly provided — requires OPENAEV_URL/OPENAEV_TOKEN in env or config.yml.
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
            oaev_api: OpenAEV API client instance (auto-created from config if None).
            source_handler_model: Custom source handler class (defaults to SourceHandler).
            engine_model: Custom engine class (defaults to BasicCollectorEngine).

        Raises:
            CollectorConfigError: If collector initialization fails.
            CollectorEngineConfigError: If engine initialization fails.
        """
        self.name = name
        self._explicit_api = oaev_api is not None
        self._setup_logging()
        self.logger = logging.getLogger(name)

        try:
            if not isinstance(source, Source):
                raise TypeError("Source provided is not of type Source")
            self.source = source

            # Auto-wire pyoaev API client from config if not provided
            if oaev_api is None:
                oaev_api = self._create_api_client_from_config()
                if not collector_id:
                    collector_id = self._resolve_collector_id()

            self.collector_id = collector_id
            self.oaev_api = oaev_api
            self.config = config

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
            raise CollectorConfigError(
                f"Failed to initialize the {self.name} collector: {err}"
            ) from err

        try:
            engine_cls: type[Any] = self.engine_model
            self.engine = engine_cls(
                name=self.name,
                collector_id=self.collector_id,
                source=self.source,
                source_handler=self.source_handler,
                oaev_api=self.oaev_api,
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

    def _create_api_client_from_config(self) -> Any:
        """Create pyoaev OpenAEV API client from ConfigBaseSettings."""
        from collectors_second_sdk._core.config.settings import ConfigBaseSettings
        from pyoaev import OpenAEV

        self._settings = ConfigBaseSettings()
        return OpenAEV(
            url=str(self._settings.openaev.url),
            token=self._settings.openaev.token,
        )

    def _resolve_collector_id(self) -> str:
        """Resolve collector_id from ConfigBaseSettings."""
        if hasattr(self, "_settings"):
            return self._settings.collector.id
        from collectors_second_sdk._core.config.settings import ConfigBaseSettings

        settings = ConfigBaseSettings()
        return settings.collector.id

    def _setup_logging(self) -> None:
        """Configure structured JSON logging (matching pyoaev daemon output)."""
        log_level = "INFO"
        try:
            from collectors_second_sdk._core.config.settings import ConfigBaseSettings

            settings = ConfigBaseSettings()
            log_level = (settings.collector.log_level or "info").upper()
        except Exception:
            pass
        setup_logging_config(log_level, json_logging=True)

    def _setup(self, batching: bool = False) -> None:
        """Set up the collector and configure the engine.

        Args:
            batching: Whether to enable batch processing.

        Raises:
            CollectorSetupError: If setup fails.
        """
        try:
            self.logger.info(f"{LOG_PREFIX} Starting collector setup...")
            self.engine.configure_engine(self.config, batching=batching)
            self.logger.info(f"{LOG_PREFIX} Collector setup completed successfully")
        except Exception as err:
            self.logger.error(f"{LOG_PREFIX} Collector setup failed: {err}")
            raise CollectorSetupError(f"Failed to setup the collector: {err}") from err

    def start(self) -> None:
        """Start the collector daemon lifecycle."""
        import sched
        import time

        parser = argparse.ArgumentParser(description="collector daemon options")
        parser.add_argument("--dump-config-schema", action="store_true")
        args = parser.parse_args()
        if args.dump_config_schema:
            import json
            from collectors_second_sdk._core.config.settings import ConfigBaseSettings
            print(json.dumps(ConfigBaseSettings.model_json_schema(), indent=2))
            return

        self._setup()
        self.logger.info(
            f"{LOG_PREFIX} Supported signatures: "
            f"{[s.value for s in self.source.signatures]}"
        )

        period = self._get_period_seconds()
        scheduler = sched.scheduler(time.time, time.sleep)

        self.logger.info(f"{LOG_PREFIX} Starting processing loop (period={period}s)...")
        self._run_cycle()
        scheduler.enter(
            delay=period,
            priority=1,
            action=self._schedule,
            argument=(scheduler, period),
        )
        scheduler.run()

    def _get_period_seconds(self) -> int:
        """Get polling period from config (default 120s)."""
        settings = getattr(self, "_settings", None)
        if settings and settings.collector.period:
            period = settings.collector.period
            return int(period.total_seconds()) if hasattr(period, "total_seconds") else 120
        return 120

    def _schedule(self, scheduler: Any, period: int) -> None:
        """Schedule the next cycle (re-entrant)."""
        self._run_cycle()
        scheduler.enter(
            delay=period,
            priority=1,
            action=self._schedule,
            argument=(scheduler, period),
        )

    def _run_cycle(self) -> None:
        """Execute one processing cycle with error resilience."""
        try:
            self.logger.info(f"{LOG_PREFIX} Starting processing cycle...")
            self.engine.run_engine()
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as err:
            self.logger.error(f"{LOG_PREFIX} Processing cycle failed: {err}")
