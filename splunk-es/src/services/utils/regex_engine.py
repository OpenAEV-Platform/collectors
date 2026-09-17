"""Generic raw-text regex signature matching engine.

This module provides a self-contained engine that matches literal
signature values against raw event text (such as the Splunk ``_raw``
field). Signature values are compiled as escaped regular expressions so
metacharacters are always matched literally, with an in-process compile
cache, optional text normalization, and deterministic match-scoring
semantics.
"""

import logging
import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

LOG_PREFIX = "[RegexSignatureEngine]"


@dataclass(frozen=True)
class Signature:
    """A literal value to search for, labeled with a signature type.

    Attributes:
        type: Signature type label.
        value: Primary literal value to search for.
        alternates: Additional literal values representing the same
            signature (for example, the implant callback URL rebuilt
            from the UUIDs embedded in a parent process name); the
            signature counts as found when any of its literals is
            present.

    """

    type: str
    value: str
    alternates: tuple[str, ...] = ()


@dataclass(frozen=True)
class SignatureMatch:
    """Outcome of searching a single signature in one evaluation.

    Attributes:
        signature: The signature that was searched.
        found: Whether the literal value was found in the text.
        matched_span: ``(start, end)`` span of the match in the (possibly
            normalized) text, or ``None`` when not found.

    """

    signature: Signature
    found: bool
    matched_span: tuple[int, int] | None


@dataclass(frozen=True)
class EngineResult:
    """Aggregated outcome of evaluating signatures against raw text.

    Attributes:
        total: Number of signatures evaluated.
        matched: Number of signatures found in the text.
        score: ``matched / total`` (``0.0`` when ``total`` is zero).
        is_match: Whether the evaluation satisfies the engine's match rule
            (``require_all`` or ``min_matches``).
        matches: Per-signature outcomes, in input order.

    """

    total: int
    matched: int
    score: float
    is_match: bool
    matches: list[SignatureMatch]


class RegexSignatureEngine:
    """Literal signature matcher for raw event text.

    Each signature value is treated as a literal: it is escaped with
    ``re.escape`` and searched with ``re.search``. Compiled patterns are
    cached per ``(value, normalize, case_sensitive)`` so repeated values
    are never recompiled.

    With ``normalize=True`` (the default) both the text and the value are
    lowercased before matching and whitespace runs in the text are
    collapsed to single spaces.

    A signature may carry alternate literals, which are different
    representations of the same value (for example, the implant callback
    URL rebuilt from the UUIDs inside a parent process name). The
    signature counts as found when its primary value or any of its
    alternates is present.

    Match rule: with ``require_all=True`` every signature must be
    present; otherwise at least ``max(1, min_matches)`` signatures must
    be present. An empty signature list never matches.
    """

    def __init__(
        self,
        *,
        case_sensitive: bool = True,
        normalize: bool = True,
        min_matches: int = 1,
        require_all: bool = False,
    ) -> None:
        """Initialize the engine.

        Args:
            case_sensitive: Match case-sensitively; ``False`` adds
                ``re.IGNORECASE`` to the search.
            normalize: Lowercase both text and value and collapse
                whitespace runs in the text before matching.
            min_matches: Minimum number of signatures that must be found
                for a match (clamped to at least 1).
            require_all: Require every signature to be found.

        """
        self.logger = logging.getLogger(__name__)
        self._case_sensitive = case_sensitive
        self._normalize = normalize
        self._min_matches = max(1, min_matches)
        self._require_all = require_all
        self._compile_cache: dict[tuple[str, bool, bool], re.Pattern[str]] = {}

    def evaluate(self, raw_text: str, signatures: Sequence[Signature]) -> EngineResult:
        """Evaluate signatures against raw text.

        Args:
            raw_text: The raw event text to search.
            signatures: Signatures whose literal values are each searched
                independently in the text.

        Returns:
            EngineResult with per-signature outcomes, counts, score, and
            the engine's match verdict.

        """
        text = self._normalize_text(raw_text)
        matches: list[SignatureMatch] = []
        matched = 0
        for signature in signatures:
            # A signature is found when its primary value or any of its
            # alternates (other representations of the same value) is
            # present; the first hit wins and spans are tracked per hit.
            hit: re.Match[str] | None = None
            for candidate in (signature.value, *signature.alternates):
                hit = self._pattern_for(candidate).search(text)
                if hit is not None:
                    break
            if hit is not None:
                matched += 1
                span: tuple[int, int] | None = (hit.start(), hit.end())
                self.logger.debug(
                    f"{LOG_PREFIX} Signature found: "
                    f"type={signature.type} value={signature.value!r}"
                )
            else:
                span = None
            matches.append(
                SignatureMatch(
                    signature=signature,
                    found=hit is not None,
                    matched_span=span,
                )
            )

        total = len(matches)
        if total == 0:
            score = 0.0
            is_match = False
        else:
            score = matched / total
            is_match = (
                matched == total if self._require_all else matched >= self._min_matches
            )

        self.logger.debug(
            f"{LOG_PREFIX} Evaluation finished: "
            f"matched={matched} total={total} is_match={is_match}"
        )
        return EngineResult(
            total=total,
            matched=matched,
            score=score,
            is_match=is_match,
            matches=matches,
        )

    def matches(self, raw_text: str, signatures: Sequence[Signature]) -> bool:
        """Return whether the evaluation satisfies the engine's match rule.

        Args:
            raw_text: The raw event text to search.
            signatures: Signatures whose literal values are each searched
                independently in the text.

        Returns:
            ``True`` when the match rule is satisfied, else ``False``.

        """
        return self.evaluate(raw_text, signatures).is_match

    def raw_text_from(self, raw: Mapping[str, Any] | str | None) -> str:
        """Extract searchable raw text from a raw event payload.

        Args:
            raw: Raw event data: a mapping (e.g. a Splunk event dict),
                a plain string, or ``None``.

        Returns:
            The event's raw text: a non-empty string ``_raw`` field when
            present on a mapping, otherwise space-joined ``key=value``
            pairs (skipping ``None`` values); the string unchanged for
            string input; and an empty string for ``None``.

        """
        if raw is None:
            return ""
        if isinstance(raw, str):
            return raw
        if isinstance(raw, Mapping):
            raw_field = raw.get("_raw")
            if isinstance(raw_field, str) and raw_field:
                return raw_field
            return " ".join(
                f"{key}={value}" for key, value in raw.items() if value is not None
            )
        return str(raw)

    def _normalize_text(self, raw_text: str) -> str:
        """Normalize text according to the engine's normalize setting.

        Args:
            raw_text: The raw event text.

        Returns:
            Lowercased text with whitespace runs collapsed to single
            spaces, or the text unchanged when normalization is off.

        """
        if not self._normalize:
            return raw_text
        return " ".join(raw_text.lower().split())

    def _pattern_for(self, value: str) -> re.Pattern[str]:
        """Get (or compile and cache) the escaped literal pattern.

        Args:
            value: The signature's literal value.

        Returns:
            The compiled pattern for the escaped value under the current
            normalize/case-sensitivity settings.

        """
        key = (value, self._normalize, self._case_sensitive)
        pattern = self._compile_cache.get(key)
        if pattern is None:
            effective_value = value.lower() if self._normalize else value
            flags = re.IGNORECASE if not self._case_sensitive else 0
            pattern = re.compile(re.escape(effective_value), flags)
            self._compile_cache[key] = pattern
        return pattern
