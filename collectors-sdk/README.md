# collectors-sdk

[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue)](https://www.python.org)
[![mypy strict](https://img.shields.io/badge/mypy-strict-green)](https://mypy.readthedocs.io/)
[![ruff](https://img.shields.io/badge/linter-ruff-purple)](https://docs.astral.sh/ruff/)

OpenAEV Collectors SDK — Base collector, engine, and extension framework for building security data collectors.

## Install

```bash
pip install -e .
```

## Quick Start

```python
from collectors_sdk import BaseCollector, Source

# Define your data fetcher and source data classes
from my_collector.source import MyDataFetcher, MySourceData, SUPPORTED_SIGNATURES

source = Source(
    data_fetcher_model=MyDataFetcher,
    source_data_model=MySourceData,
    signatures=SUPPORTED_SIGNATURES,
)

collector = BaseCollector(
    name="My Collector",
    source=source,
    config=my_config,
    collector_id="my-collector-uuid",
    oaev_api=oaev_client,
)
collector._setup()
```

## Features

- **Base Collector** — Lifecycle class, configuration, source/engine wiring for collector extensions
- **Basic Engine** — Use-case agnostic 7-step expectation processing pipeline
- **Protocols** — 4 `@runtime_checkable` behavioral contracts for engine, data fetcher, source data, and source handler
- **Resilient Uploader** — Bulk-with-fallback upload strategy for expectation results and traces
- **Config Base Classes** — Pydantic-settings models for OAEV, collector, and custom configuration

## Module Map

43 public symbols in `collectors_sdk`:

| Group | Symbols | What it provides |
|---|---|---|
| Errors | `CollectorError`, `CollectorConfigError`, `CollectorEngineConfigError`, `CollectorSetupError`, `CollectorProcessingError`, `ExpectationHandlerError`, `ExpectationProcessingError`, `ExpectationUpdateError`, `BulkUploadError`, `BulkPreparationError`, `APIError`, `TracingError`, `TraceSubmissionError`, `TraceCreationError` | 14-class exception hierarchy |
| Protocols | `CollectorEngineProtocol`, `DataFetcherProtocol`, `SourceDataProtocol`, `SourceHandlerProtocol` | Behavioral contracts for extension points |
| Data Models | `OAEVData`, `TraceData`, `Source`, `SourceHandler`, `ExpectationResult`, `ExpectationTrace`, `ExpectationSummary` | Pydantic models for the processing pipeline |
| Config | `ConfigBaseSettings`, `ConfigLoaderOAEV`, `ConfigLoaderCollector`, `ConfigLoaderCustom` | Pydantic-settings base classes for collector config |
| Type Aliases | `CustomConfig`, `ExpectationsList`, `SignatureGroups`, `BulkData`, `PrepareBulkFunction`, `BulkUploadFunction`, `UnpackBulkFunction`, `IndividualUploadFunction` | Typed aliases for function signatures and data shapes |
| Engine | `BasicCollectorEngine` | 7-step expectation processing pipeline |
| Base | `BaseCollector` | Lifecycle class wiring source, handler, engine, and config |
| Daemon | `DaemonProtocol` | Behavioral contract for the daemon runtime (re-exported from xtm-oaev-sdk) |
| Detection | `SignatureMatcher`, `_decode_value`, `_is_base64_encoded` | Signature-to-alert matching engine for detection/prevention collectors |

## Import Convention

Always import from the package root:

```python
from collectors_sdk import BaseCollector, Source, BasicCollectorEngine
```

Never import from private submodules:

```python
# Wrong — internal layout may change without notice
from collectors_sdk._core.engine.engine import BasicCollectorEngine
```

The 43 symbols in `__all__` are the stable public API. Everything under `_core/` is an implementation detail.

## Documentation

- [Base Collector](docs/base-collector.md) — lifecycle, configuration, source/engine wiring
- [Basic Engine](docs/basic-engine.md) — 7-step processing pipeline, batching, error handling

## Dev

```bash
pip install -e ".[dev]"
pytest                          # run tests
pytest --cov=collectors_sdk     # with coverage
mypy --strict collectors_sdk/   # type check
ruff check collectors_sdk/      # lint
```
