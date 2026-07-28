from pyoaev.signatures.types import SignatureTypes  # noqa: F401


SUPPORTED_SIGNATURES: list[SignatureTypes] = [
    SignatureTypes.SIG_TYPE_START_DATE,
    SignatureTypes.SIG_TYPE_END_DATE,
    SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME,
    SignatureTypes.SIG_TYPE_URL_HASH,
    SignatureTypes.SIG_TYPE_FILE_HASH,
    SignatureTypes.SIG_TYPE_SOURCE_EMAIL,
    SignatureTypes.SIG_TYPE_TARGET_EMAIL,
]
