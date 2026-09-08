"""Tests for the generic raw-text regex signature matching engine."""

from src.services.utils.regex_engine import RegexSignatureEngine, Signature


def _sig(value: str, sig_type: str = "value") -> Signature:
    """Build a Signature with the given value and an optional type label."""
    return Signature(type=sig_type, value=value)


def _email_injection_signatures() -> list[Signature]:
    """Build the email-injection detection signature set."""
    return [
        Signature(type="source_email", value="attacker@evil.example"),
        Signature(type="target_email", value="victim@corp.example"),
        Signature(type="url_hash", value="d41d8cd98f00b204e9800998ecf8427e"),
        Signature(type="file_hash", value="deadbeefcafe"),
        Signature(type="email_custom_header", value="X-OpenAEV-Trace: 42"),
    ]


def _email_injection_raw_text() -> str:
    """Build a sample raw event containing every injection signature."""
    return (
        "From: attacker@evil.example To: victim@corp.example "
        "Subject: Invoice "
        "X-OpenAEV-Trace: 42 "
        "url_hash=d41d8cd98f00b204e9800998ecf8427e "
        "file_hash=deadbeefcafe "
        "Body: Please review the attached invoice."
    )


class TestRegexSignatureEngine:
    """Test cases for the literal raw-text signature matching engine.

    Covers literal matching, metacharacter escaping, normalization and
    case behavior, match-threshold rules, scoring, and raw-text
    extraction from event payloads.
    """

    def test_literal_signature_hit(self):
        """Test that a literal value present in the text is found."""
        engine = RegexSignatureEngine()

        result = engine.evaluate("hello attacker.com world", [_sig("attacker.com")])

        assert result.total == 1  # noqa: S101
        assert result.matched == 1  # noqa: S101
        assert result.is_match is True  # noqa: S101
        assert result.matches[0].found is True  # noqa: S101
        assert result.matches[0].signature == _sig("attacker.com")  # noqa: S101
        assert result.matches[0].matched_span == (6, 18)  # noqa: S101

    def test_literal_signature_miss(self):
        """Test that an absent literal value is reported as not found."""
        engine = RegexSignatureEngine()

        result = engine.evaluate("nothing relevant here", [_sig("attacker.com")])

        assert result.total == 1  # noqa: S101
        assert result.matched == 0  # noqa: S101
        assert result.is_match is False  # noqa: S101
        assert result.matches[0].found is False  # noqa: S101
        assert result.matches[0].matched_span is None  # noqa: S101

    def test_metacharacter_dot_is_escaped(self):
        """Test that '.' in a value matches literally, not as a wildcard."""
        engine = RegexSignatureEngine()
        sig = _sig("evil.com")

        # As a regex, 'evil.com' would match 'evilxcom'; as a literal it must not.
        assert (
            engine.evaluate("visit evilxcom instead", [sig]).is_match is False
        )  # noqa: S101
        assert (
            engine.evaluate("visit evil.com now", [sig]).is_match is True
        )  # noqa: S101

    def test_metacharacter_quantifiers_are_escaped(self):
        """Test that '*', '?' and other quantifiers match only literally."""
        engine = RegexSignatureEngine()
        sig = _sig("a*b?c")

        assert (
            engine.evaluate("the literal a*b?c appears", [sig]).is_match is True
        )  # noqa: S101
        # Unescaped 'a*b?c' would also match 'abc' and any bare 'c'.
        assert (
            engine.evaluate("the text abc is here", [sig]).is_match is False
        )  # noqa: S101
        assert (
            engine.evaluate("the text ab c is here", [sig]).is_match is False
        )  # noqa: S101

    def test_normalize_matches_across_case(self):
        """Test that normalization makes matching case-insensitive."""
        engine = RegexSignatureEngine()  # normalize=True by default

        assert (
            engine.evaluate("see Evil.Com please", [_sig("evil.com")]).is_match is True
        )  # noqa: S101
        assert (
            engine.evaluate("see evil.com please", [_sig("EVIL.COM")]).is_match is True
        )  # noqa: S101

    def test_normalize_collapses_whitespace_runs(self):
        """Test that whitespace runs in the text collapse to single spaces."""
        engine = RegexSignatureEngine()

        assert (
            engine.evaluate("foo    bar", [_sig("foo bar")]).is_match is True
        )  # noqa: S101

    def test_no_normalize_preserves_case_and_whitespace(self):
        """Test that normalize=False searches the text as-is."""
        engine = RegexSignatureEngine(normalize=False)

        assert (
            engine.evaluate("see Evil.Com please", [_sig("evil.com")]).is_match is False
        )  # noqa: S101
        assert (
            engine.evaluate("see evil.com please", [_sig("evil.com")]).is_match is True
        )  # noqa: S101
        assert (
            engine.evaluate("foo    bar", [_sig("foo bar")]).is_match is False
        )  # noqa: S101

    def test_case_insensitive_flag_without_normalize(self):
        """Test that case_sensitive=False works on unnormalized text."""
        engine = RegexSignatureEngine(normalize=False, case_sensitive=False)

        assert (
            engine.evaluate("see Evil.Com please", [_sig("evil.com")]).is_match is True
        )  # noqa: S101

    def test_min_matches_threshold(self):
        """Test that the min_matches threshold drives the match verdict."""
        sigs = [_sig("alpha"), _sig("beta"), _sig("gamma")]
        text = "alpha and beta here"

        assert (
            RegexSignatureEngine(min_matches=2).evaluate(text, sigs).is_match is True
        )  # noqa: S101
        assert (
            RegexSignatureEngine(min_matches=3).evaluate(text, sigs).is_match is False
        )  # noqa: S101

    def test_min_matches_clamped_to_one(self):
        """Test that min_matches below 1 is treated as 1."""
        sigs = [_sig("alpha"), _sig("beta")]

        assert (
            RegexSignatureEngine(min_matches=0).evaluate("only alpha", sigs).is_match
            is True
        )  # noqa: S101
        # With an effective threshold of 1, zero hits must not match.
        assert (
            RegexSignatureEngine(min_matches=0)
            .evaluate("nothing at all", sigs)
            .is_match
            is False
        )  # noqa: S101

    def test_require_all(self):
        """Test that require_all demands every signature to be present."""
        sigs = [_sig("alpha"), _sig("beta"), _sig("gamma")]
        engine = RegexSignatureEngine(require_all=True)

        assert (
            engine.evaluate("alpha and beta here", sigs).is_match is False
        )  # noqa: S101
        assert engine.evaluate("alpha beta gamma", sigs).is_match is True  # noqa: S101

    def test_empty_signatures_never_match(self):
        """Test that an empty signature list yields a zero, non-matching result."""
        engine = RegexSignatureEngine()

        result = engine.evaluate("some raw text", [])

        assert result.total == 0  # noqa: S101
        assert result.matched == 0  # noqa: S101
        assert result.score == 0.0  # noqa: S101
        assert result.is_match is False  # noqa: S101
        assert result.matches == []  # noqa: S101

    def test_score_value(self):
        """Test that the score is matched/total (1 of 2 -> 0.5)."""
        engine = RegexSignatureEngine()
        sigs = [_sig("alpha"), _sig("beta")]

        result = engine.evaluate("alpha only", sigs)

        assert result.score == 0.5  # noqa: S101

    def test_raw_text_from_raw_field(self):
        """Test that a mapping's non-empty '_raw' string is returned verbatim."""
        engine = RegexSignatureEngine()
        payload = {"_raw": "hello world", "source": "index", "eventtype": "x"}

        assert engine.raw_text_from(payload) == "hello world"  # noqa: S101

    def test_raw_text_from_falls_back_to_fields(self):
        """Test that a mapping without '_raw' joins k=v pairs, skipping None."""
        engine = RegexSignatureEngine()
        payload = {"source": "attacker@evil.example", "note": None, "port": 443}

        assert (
            engine.raw_text_from(payload) == "source=attacker@evil.example port=443"
        )  # noqa: S101

    def test_raw_text_from_empty_raw_falls_back_to_fields(self):
        """Test that a non-string/empty '_raw' falls back to the field join.

        The fallback joins every non-None key/value pair, so an empty
        '_raw' is included as '_raw='; a non-string '_raw' is likewise
        included with its str value.
        """
        engine = RegexSignatureEngine()
        empty_raw = {"_raw": "", "source": "x"}
        non_str_raw = {"_raw": 123, "source": "x"}

        assert engine.raw_text_from(empty_raw) == "_raw= source=x"  # noqa: S101
        assert engine.raw_text_from(non_str_raw) == "_raw=123 source=x"  # noqa: S101

    def test_raw_text_from_none_and_str(self):
        """Test None input and plain-string passthrough."""
        engine = RegexSignatureEngine()

        assert engine.raw_text_from(None) == ""  # noqa: S101
        assert (
            engine.raw_text_from("passthrough text") == "passthrough text"
        )  # noqa: S101

    def test_email_injection_signatures_all_present(self):
        """Test an email-injection-style signature set against a sample event.

        Verifies that all five signatures (source email, target email, URL
        hash, file hash, custom header) found in the raw event text yield
        a full match.
        """
        engine = RegexSignatureEngine()
        sigs = _email_injection_signatures()

        result = engine.evaluate(_email_injection_raw_text(), sigs)

        assert result.total == 5  # noqa: S101
        assert result.matched == 5  # noqa: S101
        assert result.score == 1.0  # noqa: S101
        assert result.is_match is True  # noqa: S101
        assert all(m.found for m in result.matches)  # noqa: S101

    def test_matches_agrees_with_evaluate(self):
        """Test that matches() always agrees with evaluate().is_match."""
        engine = RegexSignatureEngine()
        sigs = [_sig("alpha"), _sig("beta")]
        cases = [
            ("alpha and beta", True),
            ("only alpha here", True),
            ("none of them", False),
        ]
        for text, expected in cases:
            assert engine.evaluate(text, sigs).is_match == expected  # noqa: S101
            assert engine.matches(text, sigs) == expected  # noqa: S101

        engine_all = RegexSignatureEngine(require_all=True)
        assert engine_all.matches("only alpha here", sigs) is False  # noqa: S101
        assert engine_all.matches("alpha beta", sigs) is True  # noqa: S101

    def test_alternate_literal_matches(self):
        """A signature with alternates is found when any literal appears.

        The primary value and every alternate literal represent the same
        signature; the signature counts as found when the primary or any
        alternate is present in the raw text.
        """
        engine = RegexSignatureEngine()
        sig = Signature(
            type="parent_process_name",
            value="oaev-implant-aa-agent-bb",
            alternates=("/api/injects/aa/bb/executable-payload",),
        )
        assert engine.matches("proc: oaeV-implant-AA-agent-BB", [sig])  # noqa: S101
        assert (
            engine.matches("GET /api/injects/aa/bb/executable-payload HTTP/1.1", [sig])
            is True
        )  # noqa: S101
        assert engine.matches("unrelated text", [sig]) is False  # noqa: S101

    def test_alternates_do_not_change_score_denominator(self):
        """Alternates are extra literals of one signature, not extra signatures.

        The score denominator stays the number of signatures; a signature
        hit through an alternate counts once, exactly like a primary hit.
        """
        engine = RegexSignatureEngine()
        sigs = [
            Signature(
                type="parent_process_name", value="aa-name", alternates=("aa-url",)
            ),
            Signature(type="other", value="bb"),
        ]

        result = engine.evaluate("aa-name and bb here", sigs)
        assert result.total == 2  # noqa: S101
        assert result.matched == 2  # noqa: S101
        assert result.score == 1.0  # noqa: S101

        result_alt = engine.evaluate("aa-url only here", sigs)
        assert result_alt.matched == 1  # noqa: S101
        assert result_alt.score == 0.5  # noqa: S101
        assert result_alt.is_match is True  # noqa: S101
