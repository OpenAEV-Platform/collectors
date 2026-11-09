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
    InjectExpectationOutput,
    dev_argument_parser,
    dev_options,
    dev_sink,
    environment_secret_values,
)

from .client import CollectorDevClient

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

_DESCRIPTION = (
    "Collector dev mode: run the collector without the OpenAEV platform. It reads the"
    " pending expectations as the platform serves them, and writes every call the"
    ' platform would have received as one JSON list of {"method", "path", "body"}.'
)
_EPILOG = (
    "Exit code 2 when the expectations are missing or not the platform's."
    " Guide: xtm-oaev-sdk docs/how_to_dev_mode.md."
)


def _parser():
    parser = dev_argument_parser(_DESCRIPTION, _EPILOG)
    collector = parser.add_argument_group("collector options")
    collector.add_argument(
        "--expectations",
        metavar="PATH",
        help="the pending expectations to answer, a JSON list as the platform"
        " serves them (- for stdin)",
    )
    collector.add_argument(
        "--once",
        action="store_true",
        help="run a single cycle, then return",
    )
    return parser


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, encoding="utf-8") as handle:
        return handle.read()


class CollectorDevRuntime:
    """Implements ``CollectorDevRuntimePort``."""

    def options(self, argv: list[str] | None = None) -> CollectorDevOptions:
        args, _ = _parser().parse_known_args(argv)
        common = dev_options(argv)
        return CollectorDevOptions(
            enabled=common.enabled,
            out=common.out,
            record=common.record,
            replay=common.replay,
            help=common.help,
            expectations=args.expectations,
            once=args.once,
        )

    def help(self) -> str:
        return _parser().format_help()

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
        feed: list[dict[str, Any]] = []
        if options.expectations:
            try:
                feed = json.loads(_read(options.expectations))
                _PENDING.validate_python(feed)
            except (OSError, ValueError, ValidationError) as error:
                code = sink.refuse(f"not the platform's pending expectations: {error}")
                sink.close()
                raise SystemExit(code) from error
        return CollectorDevClient(feed, sink, models_for_source)

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
