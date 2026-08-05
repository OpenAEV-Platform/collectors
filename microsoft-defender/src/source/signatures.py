from pyoaev.signatures.types import (  # type: ignore[import-untyped]  # noqa: F401
    SignatureTypes,
)

SUPPORTED_SIGNATURES: list[SignatureTypes] = [
    SignatureTypes.SIG_TYPE_START_DATE,
    SignatureTypes.SIG_TYPE_END_DATE,
    SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME,
    "process_name",
    "command_line",
    "file_name",
    "hostname",
    "ipv4_address",
    "ipv6_address",
]
