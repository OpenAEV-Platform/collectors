"""Collector dev runtime: runs a collector without the platform.

The collector reads the ``--expectations`` list (the platform's pending expectations,
as its expectation endpoints serve them) through a stand-in of the platform client,
which writes every update and trace to the dev sink. ``--once`` runs a single cycle;
otherwise the cycle runs on the collector's period, as on the platform.
"""

import json
import sys
from typing import Any, Callable

from collectors_sdk._core.daemons.schedule import CollectorSchedule
from collectors_sdk.seam.runtime import CollectorDevOptions
from pydantic import TypeAdapter, ValidationError
from xtm_oaev_sdk import (
    CallTape,
    InjectExpectationOutput,
    OpenAEVError,
    dev_sink,
    environment_secret_values,
)

from .client import CollectorDevClient
from .options import collector_help, collector_options

__all__ = ["CollectorDevRuntime"]

#: Body keys holding ids, booleans, enum values or dates: a secret never rewrites them.
KEPT_KEYS = (
    "collector_id",
    "is_success",
    "inject_expectation_trace_expectation",
    "inject_expectation_trace_source_id",
    "inject_expectation_trace_date",
    "inject_expectation_trace_match_type",
)
_PENDING = TypeAdapter(list[InjectExpectationOutput])


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def _start_tape(
    sink: Any, options: CollectorDevOptions, secrets: list[str], daemon: Any
) -> CallTape | None:
    """The tape recording or replaying the run's outside calls, if one is asked for;
    exits with code 2 when the replay tape cannot be read."""
    if not (options.record or options.replay):
        return None
    mode = "record" if options.record else "replay"
    tape = CallTape(
        options.record or options.replay,
        mode,
        secrets=secrets,
        daemon=str(daemon) if daemon else None,
    )
    try:
        return tape.start()
    except OpenAEVError as error:
        raise SystemExit(sink.refuse(str(error))) from error


class CollectorDevRuntime:
    """Implements ``CollectorDevRuntimePort``."""

    def options(self, argv: list[str] | None = None) -> CollectorDevOptions:
        return collector_options(argv)

    def help(self) -> str:
        return collector_help()

    def exit_on_help(self, options: CollectorDevOptions) -> None:
        if options.help:
            sys.stdout.write(self.help())
            sys.stdout.flush()
            raise SystemExit(0)

    def api_client(
        self,
        configuration: Any,
        options: CollectorDevOptions,
        models_for_source: Callable[..., list[Any]],
    ) -> CollectorDevClient:
        secrets = environment_secret_values()
        if configuration is not None:
            secrets += configuration.secret_values()
        sink = dev_sink(options.out, secrets, KEPT_KEYS)
        if options.record and options.replay:
            raise SystemExit(
                sink.refuse("--record and --replay cannot be given together")
            )
        feed: list[dict[str, Any]] = []
        if options.expectations:
            try:
                feed = json.loads(_read(options.expectations))
                _PENDING.validate_python(feed)
            except (OSError, ValueError, ValidationError) as error:
                code = sink.refuse(f"not the platform's pending expectations: {error}")
                sink.close()
                raise SystemExit(code) from error
        name = None
        if configuration is not None:
            name = configuration.get("collector_name") or configuration.get("name")
        return CollectorDevClient(
            feed, sink, models_for_source, _start_tape(sink, options, secrets, name)
        )

    def run(
        self,
        callback: Callable[[], Any],
        period: Any,
        api: Any,
        options: CollectorDevOptions,
    ) -> None:
        sink = api.sink
        try:
            if not options.expectations:
                raise SystemExit(
                    sink.refuse(
                        "--expectations PATH (or - for stdin) is required in dev mode"
                    )
                )
            if options.once:
                callback()
            else:
                CollectorSchedule().run(callback, period)
        finally:
            sink.close()
            if api.tape is not None:
                api.tape.stop()
