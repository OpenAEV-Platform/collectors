"""Collector dev options: the common dev options plus the collector's own."""

from collectors_sdk.seam.runtime import CollectorDevOptions
from xtm_oaev_sdk import dev_argument_parser, dev_options

__all__ = ["collector_help", "collector_options"]

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


def collector_options(argv: list[str] | None = None) -> CollectorDevOptions:
    """The collector's dev options, read from ``argv`` (the process arguments when
    ``None``); injector options and the collector's own flags are left alone."""
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


def collector_help() -> str:
    """The help of the collector's dev options."""
    return _parser().format_help()
