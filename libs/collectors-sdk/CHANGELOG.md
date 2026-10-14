# Changelog

Every notable change to collectors-sdk lands here. Every seam change too, with the new
version of its seam.

## [0.1.0] - Unreleased

First version. The collector runtime of `pyoaev` 3.260923.0 moves out and into this
SDK. The former `pyoaev` paths keep working, each one firing a `DeprecationWarning`.

### Added

- `daemons`: `CollectorDaemon`, `DEFAULT_PERIOD_SECONDS`, `DEFAULT_PLATFORM_TAG_COLOR`
  (from `pyoaev.daemons`). Seam `1.0.0`.
- `detection`: `OpenAEVDetectionHelper` (from `pyoaev.helpers`). Seam `1.0.0`.
- `expectations`: `Expectation`, `DetectionExpectation`, `PreventionExpectation`,
  `ExpectationSignature`, `ExpectationTypeEnum` (from
  `pyoaev.apis.inject_expectation.model`). Seam `1.0.0`.

### Changed (compared with pyoaev)

- `CollectorDaemon` stops building the API client. Pass `api_client=` yourself.
- `requires-python` moves from `>=3.11` to `>=3.12`, like xtm-oaev-sdk it builds on.
