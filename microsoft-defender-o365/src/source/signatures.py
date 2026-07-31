from pyoaev.signatures.types import SignatureTypes  # noqa: F401

# No signature definitions in this chunk (#471 - project architecture setup).
# Signatures will be added once the actual data collection logic is implemented.
SUPPORTED_SIGNATURES: list[SignatureTypes] = [
    SignatureTypes.SIG_TYPE_SOURCE_EMAIL,
    SignatureTypes.SIG_TYPE_TARGET_EMAIL,
    SignatureTypes.SIG_TYPE_URL_HASH,
    SignatureTypes.SIG_TYPE_FILE_HASH,
    SignatureTypes.SIG_TYPE_EMAIL_CUSTOM_HEADER,
]
