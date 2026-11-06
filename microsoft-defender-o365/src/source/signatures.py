from pyoaev.signatures.signature_type import SignatureType
from pyoaev.signatures.types import (  # type: ignore[import-untyped]  # noqa: F401
    SignatureTypes,
)

SUPPORTED_SIGNATURES: list[SignatureType] = [
    SignatureType(SignatureTypes.SIG_TYPE_START_DATE),
    SignatureType(SignatureTypes.SIG_TYPE_END_DATE),
    SignatureType(SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME),
    SignatureType(SignatureTypes.SIG_TYPE_URL_HASH),
    SignatureType(SignatureTypes.SIG_TYPE_FILE_HASH),
    SignatureType(SignatureTypes.SIG_TYPE_SOURCE_EMAIL),
    SignatureType(SignatureTypes.SIG_TYPE_TARGET_EMAIL),
    SignatureType(SignatureTypes.SIG_TYPE_EMAIL_CUSTOM_HEADER),
]
