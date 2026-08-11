from pyoaev.signatures.signature_type import SignatureType
from pyoaev.signatures.types import (
    MatchTypes,
    SignatureTypes,
)

SUPPORTED_SIGNATURES: list[SignatureType] = [
    SignatureType(SignatureTypes.SIG_TYPE_END_DATE),
    SignatureType(SignatureTypes.SIG_TYPE_START_DATE),
    SignatureType(
        SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME,
        match_type=MatchTypes.MATCH_TYPE_FUZZY,
        match_score=60,
    ),
]
