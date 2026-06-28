"""Tests for Elastic Security data models (ECS value selection and parsing)."""

from src.services.models import ElasticResponse, _first


class TestFirst:
    """Tests for the ``_first`` ECS value selector.

    These lock in the contract that only genuinely-missing values are skipped
    while falsy-but-present scalars (``0``, ``False``) are preserved.
    """

    def test_preserves_zero(self):
        """A numeric ``0`` is a present value and must be kept, not dropped."""
        assert _first({"event.severity": 0}, ["event.severity"]) == "0"  # noqa: S101

    def test_preserves_false_boolean(self):
        """A boolean ``False`` is a present value and must be kept."""
        assert _first({"flag": False}, ["flag"]) == "False"  # noqa: S101

    def test_skips_none_then_uses_next_path(self):
        """A ``None`` value is skipped so a later path can still win."""
        assert _first({"a": None, "b": "value"}, ["a", "b"]) == "value"  # noqa: S101

    def test_skips_empty_string(self):
        """An empty string counts as missing and is skipped."""
        assert _first({"a": "", "b": "value"}, ["a", "b"]) == "value"  # noqa: S101

    def test_skips_empty_list(self):
        """An empty list yields no value and falls through to ``None``."""
        assert _first({"a": []}, ["a"]) is None  # noqa: S101

    def test_uses_first_list_element(self):
        """A non-empty list resolves to its first element."""
        assert _first({"a": ["x", "y"]}, ["a"]) == "x"  # noqa: S101

    def test_zero_in_list_is_preserved(self):
        """A list whose first element is ``0`` keeps that value."""
        assert _first({"a": [0]}, ["a"]) == "0"  # noqa: S101

    def test_returns_none_when_all_paths_missing(self):
        """When no path resolves to a present value, ``None`` is returned."""
        assert _first({}, ["a", "b"]) is None  # noqa: S101


class TestFromRawResponse:
    """Tests for ``ElasticResponse.from_raw_response`` ECS parsing."""

    def test_zero_severity_is_not_dropped(self):
        """A regression guard: ECS ``event.severity: 0`` must be parsed.

        Before the ``_first`` fix the falsy ``0`` was treated as missing and
        the parsed ``severity`` was silently lost.
        """
        raw = {
            "hits": {
                "hits": [
                    {
                        "_source": {
                            "@timestamp": "2026-01-01T00:00:00Z",
                            "source.ip": "192.168.1.10",
                            "event.severity": 0,
                        }
                    }
                ]
            }
        }

        response = ElasticResponse.from_raw_response(raw)

        assert len(response.results) == 1  # noqa: S101
        assert response.results[0].severity == "0"  # noqa: S101

    def test_nested_and_flattened_fields_resolve(self):
        """Both nested and flattened ECS layouts are parsed for IP fields."""
        raw = {
            "hits": {
                "hits": [
                    {
                        "_source": {
                            "@timestamp": "2026-01-01T00:00:00Z",
                            "source": {"ip": "10.0.0.1"},
                            "destination.ip": "10.0.0.2",
                        }
                    }
                ]
            }
        }

        response = ElasticResponse.from_raw_response(raw)

        assert response.results[0].src_ip == "10.0.0.1"  # noqa: S101
        assert response.results[0].dst_ip == "10.0.0.2"  # noqa: S101
