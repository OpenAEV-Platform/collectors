from pyoaev.signatures.types import (  # type: ignore[import-untyped]  # noqa: F401
    SignatureTypes,
)

<<<<<<< HEAD
SUPPORTED_SIGNATURES: list[SignatureTypes] = [
    SignatureTypes.SIG_TYPE_START_DATE,
    SignatureTypes.SIG_TYPE_END_DATE,
    SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME,
    SignatureTypes.SIG_TYPE_URL_HASH,
    SignatureTypes.SIG_TYPE_FILE_HASH,
    SignatureTypes.SIG_TYPE_SOURCE_EMAIL,
    SignatureTypes.SIG_TYPE_TARGET_EMAIL,
    SignatureTypes.SIG_TYPE_EMAIL_CUSTOM_HEADER,
]
