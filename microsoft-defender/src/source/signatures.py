from pyoaev.signatures.types import (  # type: ignore[import-untyped]  # noqa: F401
    SignatureTypes,
)

SUPPORTED_SIGNATURES: list[SignatureTypes] = [
    SignatureTypes.SIG_TYPE_START_DATE,
    SignatureTypes.SIG_TYPE_END_DATE,
    SignatureTypes.SIG_TYPE_PROCESS_NAME,
    SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME,
    SignatureTypes.SIG_TYPE_COMMAND_LINE,
    SignatureTypes.SIG_TYPE_FILE_NAME,
    SignatureTypes.SIG_TYPE_HOSTNAME,
    SignatureTypes.SIG_TYPE_IPV4_ADDRESS,
    SignatureTypes.SIG_TYPE_TARGET_IPV4_ADDRESS,
    SignatureTypes.SIG_TYPE_IPV6_ADDRESS,
    SignatureTypes.SIG_TYPE_TARGET_IPV6_ADDRESS,
]
