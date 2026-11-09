# Changelog

Every notable change to collectors-sdk lands here. Every seam change too, with the new
version of its seam.

## [Unreleased]

### Added

- `runtime` (new): the dev options of a collector. `CollectorDevOptions` (seam model)
  extends `xtm_oaev_sdk.DevOptions` with `--expectations` and `--once`;
  `collector_dev_options(argv=None)` reads them and `collector_dev_help()` describes
  them next to the common options. They are read only under their full name; injector
  options and the collector's own flags are left alone. Port `CollectorDevRuntimePort`.
  Seam `runtime` `1.0.0`.
- `daemons`: started with `--dev --help` (or `-h`), `CollectorDaemon` prints the
  collector dev options and exits with code 0, before building the API client or
  reaching the platform. Without `--dev`, `-h` stays the collector's own.
- `runtime`: run a collector without the platform. Started with `--dev`,
  `CollectorDaemon` never builds the API client and starts no heartbeat. It serves the
  `--expectations` list (exactly the platform's pending expectations, a JSON list of
  `xtm_oaev_sdk.InjectExpectationOutput`, from a file or `-` for stdin, as an
  injector's `--emit expectations` writes it) through the expectation endpoints and
  `expectations_models_for_source`, and stops serving an expectation once answered.
  Every update, bulk update and trace goes to the dev sink, one JSON list (`--out`, or
  stdout), checked against what the platform accepts (a call it would reject is
  refused with a 400). Registration calls get ids back and write nothing; any other
  manager raises `xtm_oaev_sdk.NeedsPlatformError` naming it. `--once` runs a single
  cycle. The run exits with code 2 without `--expectations`, or when the list is not
  the platform's pending expectations. Secrets from the configuration and the
  environment are redacted. The port gains `api_client` and `run`. Seam `runtime`
  `1.0.0`.

## [0.1.0] - Unreleased

First version. The collector runtime of `pyoaev` 3.260923.0 moves out and into this
SDK. The former `pyoaev` paths keep working, each one firing a `DeprecationWarning`.

### Added

- `daemons`: `CollectorDaemon`, `DEFAULT_PERIOD_SECONDS`, `DEFAULT_PLATFORM_TAG_COLOR`
  (from `pyoaev.daemons`). Seam `1.0.0`.
- `detection`: `OpenAEVDetectionHelper` (from `pyoaev.helpers`). Seam `1.0.0`.
- `expectations`: `Expectation`, `DetectionExpectation`, `PreventionExpectation`,
  `ExpectationSignature`, `ExpectationTypeEnum` (from
  `pyoaev.apis.inject_expectation.model`), and `expectations_models_for_source` with its
  `ExpectationApiProtocol` (from `InjectExpectationManager.expectations_models_for_source`).
  Seam `1.0.0`.

### Changed (compared with pyoaev)

- `CollectorDaemon` stops building the API client. Pass `api_client=` yourself.
- The client stops building the expectation models. Call
  `expectations_models_for_source(api.inject_expectation, source_id)` instead of
  `api.inject_expectation.expectations_models_for_source(source_id)`, now deprecated.
- `requires-python` moves from `>=3.11` to `>=3.12`, like xtm-oaev-sdk it builds on.
