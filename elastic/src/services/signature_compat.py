"""Compatibility shim that makes pyoaev's ``SignatureTypes`` enum fail-soft.

The released pyoaev ``SignatureTypes`` enum is strict (it has no ``_missing_``
hook). A single expectation whose signature carries a type the enum does not
know - e.g. the agentless / NetExec vocabulary ``source_ipv4`` / ``start_time``,
or any future type the OpenAEV server introduces - raises a pydantic
``ValidationError`` inside ``expectations_models_for_source`` and aborts the
**entire tenant fetch for the whole cycle** (not just the offending inject).
Nothing gets graded and the collector looks dead.

This shim installs a ``_missing_`` hook so that:

* known **alias spellings resolve to their canonical member**
  (``source_ipv4`` -> ``source_ipv4_address``, ``start_time`` -> ``start_date``,
  ...), so agentless injects still correlate via IP + time; and
* any **other unknown value resolves to a pass-through member** instead of
  raising, so one odd/future signature type can never abort the batch (the
  service layer simply filters it out as unsupported).

It is idempotent, safe to import for its side effect, and becomes a no-op once
pyoaev ships native support. Crucially it removes any dependency on a hand-edited
``site-packages`` copy of the enum (which is unreproducible for customers).

This is a deliberate, documented interim; fail-soft signature parsing belongs in
pyoaev / the SDK. See docs/CLIENT_READINESS_SPEC.md (DoD-1).
"""

import logging

logger = logging.getLogger(__name__)

# Non-canonical alias value -> canonical value the pipeline already understands.
CANONICAL_ALIASES = {
    "source_ipv4": "source_ipv4_address",
    "source_ipv6": "source_ipv6_address",
    "target_ipv4": "target_ipv4_address",
    "target_ipv6": "target_ipv6_address",
    "start_time": "start_date",
    "end_time": "end_date",
}

_SHIM_FLAG = "_oaev_failsoft_installed"

# Upper bound on distinct pass-through members synthesized for unknown types, so
# a flood of distinct unknown signature types cannot grow the enum value-map
# without limit (a mild memory-DoS). Past the cap, further unknowns collapse onto
# one shared pass-through member: every unknown type is filtered out identically
# downstream (none is in SUPPORTED_SIGNATURES), so a shared identity is harmless.
_MAX_SYNTHETIC_TYPES = 256
_OVERFLOW_VALUE = "__oaev_unknown_signature_type__"


def install() -> bool:  # noqa: C901
    """Install the fail-soft ``_missing_`` hook on ``SignatureTypes`` (idempotent).

    Returns True when the hook is in place (either just installed or already
    present), False if it could not be installed (never raises).
    """
    try:
        from pyoaev.signatures.types import (  # type: ignore[import-untyped]
            SignatureTypes,
        )
    except Exception as e:  # pragma: no cover - pyoaev always present at runtime
        logger.debug("signature_compat: pyoaev SignatureTypes unavailable: %s", e)
        return False

    if getattr(SignatureTypes, _SHIM_FLAG, False):
        return True

    known_values = {member.value for member in SignatureTypes}
    synth = {"count": 0}  # distinct pass-through members synthesized so far

    def _synthesize(cls, value):  # noqa: ANN001, ANN202
        member = str.__new__(cls, value)
        member._name_ = value.upper()
        member._value_ = value
        cls._value2member_map_[value] = member
        return member

    @classmethod  # type: ignore[misc]
    def _missing_(cls, value):  # noqa: ANN001, ANN206
        if not isinstance(value, str):
            return None
        canonical = CANONICAL_ALIASES.get(value)
        if canonical is not None and canonical in known_values:
            return cls(canonical)
        cached = cls._value2member_map_.get(value)
        if cached is not None:
            return cached
        # Unknown/future type: synthesize a pass-through member so pydantic
        # coercion succeeds and the whole-batch fetch is never aborted. The
        # service filters it out (it is not in SUPPORTED_SIGNATURES). Bound the
        # number of distinct synthesized members (see _MAX_SYNTHETIC_TYPES).
        try:
            if synth["count"] >= _MAX_SYNTHETIC_TYPES:
                overflow = cls._value2member_map_.get(_OVERFLOW_VALUE)
                if overflow is None:
                    overflow = _synthesize(cls, _OVERFLOW_VALUE)
                return overflow
            member = _synthesize(cls, value)
            synth["count"] += 1
        except Exception:  # pragma: no cover - defensive
            return None
        logger.debug(
            "signature_compat: tolerating unknown signature type %r (pass-through)",
            value,
        )
        return member

    try:
        SignatureTypes._missing_ = _missing_  # type: ignore[method-assign]
        setattr(SignatureTypes, _SHIM_FLAG, True)
    except Exception as e:  # pragma: no cover - defensive
        logger.warning("signature_compat: could not install fail-soft hook: %s", e)
        return False
    return True


# Apply on import so it is active before the manager parses any expectation.
install()
