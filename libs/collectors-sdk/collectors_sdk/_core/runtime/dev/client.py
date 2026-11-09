"""Dev client: a local stand-in for the platform client of collectors.

It serves the pending expectations as the platform's expectation endpoints do, and writes
each update and trace to the dev sink instead of sending it; the sink checks it against
the payload the platform accepts and refuses it with a 400 when the platform would. An
answered expectation leaves the feed, as on the platform. Registration calls get ids
back and are not written. Any manager it does not offer raises a ``NeedsPlatformError``
naming it. It never opens a network connection.
"""

from typing import Any, Callable

from xtm_oaev_sdk import DevSinkPort, NeedsPlatformError

__all__ = ["CollectorDevClient"]

_EXPECTATIONS = "/api/injects/expectations"
_TRACES = "/api/inject-expectations-traces"


class _InjectExpectationManager:
    """``inject_expectation``: the pending feed, and the collector's answers."""

    def __init__(
        self,
        feed: list[dict[str, Any]],
        sink: DevSinkPort,
        models_for_source: Callable[..., list[Any]],
    ) -> None:
        self._feed = feed
        self._sink = sink
        self._models_for_source = models_for_source

    def _pending(self, *kinds: str) -> list[dict[str, Any]]:
        return [
            dict(e) for e in self._feed if e.get("inject_expectation_type") in kinds
        ]

    def _answered(self, *expectation_ids: str) -> None:
        # Answered: the platform no longer serves it as pending to this collector.
        answered = {str(i) for i in expectation_ids}
        self._feed[:] = [
            e for e in self._feed if str(e.get("inject_expectation_id")) not in answered
        ]

    def expectations_assets_for_source(
        self, source_id: str, **_: Any
    ) -> list[dict[str, Any]]:
        return self._pending("DETECTION", "PREVENTION")

    def detection_expectations_for_source(
        self, source_id: str, **_: Any
    ) -> list[dict[str, Any]]:
        return self._pending("DETECTION")

    def prevention_expectations_for_source(
        self, source_id: str, **_: Any
    ) -> list[dict[str, Any]]:
        return self._pending("PREVENTION")

    def expectations_models_for_source(self, source_id: str, **kwargs: Any) -> list:
        return self._models_for_source(self, source_id=source_id, **kwargs)

    def update(
        self, inject_expectation_id: str, inject_expectation: dict[str, Any], **_: Any
    ) -> dict[str, Any]:
        self._sink.record(
            "PUT", f"{_EXPECTATIONS}/{inject_expectation_id}", inject_expectation
        )
        self._answered(inject_expectation_id)
        return {}

    def bulk_update(
        self, inject_expectation_input_by_id: dict[str, Any], **_: Any
    ) -> None:
        self._sink.record(
            "PUT",
            f"{_EXPECTATIONS}/bulk",
            {"inputs": inject_expectation_input_by_id},
        )
        self._answered(*inject_expectation_input_by_id)


class _InjectExpectationTraceManager:
    """``inject_expectation_trace``: the traces a collector attaches."""

    def __init__(self, sink: DevSinkPort) -> None:
        self._sink = sink

    def create(self, data: dict[str, Any] | None = None, **_: Any) -> dict[str, Any]:
        self._sink.record("POST", _TRACES, data)
        return {}

    def bulk_create(
        self, payload: dict[str, Any] | None = None, **_: Any
    ) -> dict[str, Any]:
        self._sink.record("POST", f"{_TRACES}/bulk", payload)
        return {}


class _DocumentManager:
    """``document``: the collector's icon, kept local."""

    def upsert(self, *_: Any, **__: Any) -> dict[str, Any]:
        return {"document_id": "dev-document"}


class _SecurityPlatformManager:
    """``security_platform``: the collector's security platform, kept local."""

    def upsert(self, *_: Any, **__: Any) -> dict[str, Any]:
        return {"asset_id": "dev-security-platform"}


class _TagManager:
    """``tag``: the security platform's tags, kept local."""

    def upsert(self, data: dict[str, Any] | None = None, **_: Any) -> dict[str, Any]:
        return {"tag_id": f"dev-tag-{(data or {}).get('tag_name')}"}


class _CollectorManager:
    """``collector``: the registration, kept local."""

    def create(self, *_: Any, **__: Any) -> dict[str, Any]:
        return {}


class CollectorDevClient:
    """The resource managers collectors use, writing to ``sink`` instead of sending.

    Any other manager raises ``NeedsPlatformError`` naming it.
    """

    def __init__(
        self,
        feed: list[dict[str, Any]],
        sink: DevSinkPort,
        models_for_source: Callable[..., list[Any]],
        tape: Any = None,
    ) -> None:
        self.sink = sink
        #: The call tape recording or replaying the run's outside calls, if any.
        self.tape = tape
        self.inject_expectation = _InjectExpectationManager(
            feed, sink, models_for_source
        )
        self.inject_expectation_trace = _InjectExpectationTraceManager(sink)
        self.document = _DocumentManager()
        self.security_platform = _SecurityPlatformManager()
        self.tag = _TagManager()
        self.collector = _CollectorManager()

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        raise NeedsPlatformError(name)
