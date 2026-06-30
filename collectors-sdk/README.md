# collectors-sdk

[![Version 0.1.0](https://img.shields.io/badge/version-0.1.0-blue)](pyproject.toml)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue)](https://www.python.org)
[![mypy strict](https://img.shields.io/badge/mypy-strict-green)](https://mypy.readthedocs.io/)
[![ruff](https://img.shields.io/badge/linter-ruff-purple)](https://docs.astral.sh/ruff/)

OpenAEV Collectors SDK (DDD + Light Hex Architecture) — Base collector, engine, and extension framework for building security data collectors.

## Install

```bash
uv add collectors-sdk
# or
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

# Auto-wires config, API client, and collector ID from config.yml / env vars
collector = BaseCollector(
    name="My Collector",
    source=source,
)
collector.start()
```

`BaseCollector` auto-creates the `ConfigBaseSettings` from `config.yml` (expects `openaev` and `collector` YAML sections) or from environment variables. The OpenAEV API client and collector ID are wired automatically through the `DaemonProtocol` parent class — you do not pass them directly.

Custom source handler or engine models can be swapped in:

```python
collector = BaseCollector(
    name="My Collector",
    source=source,
    source_handler_model=MySourceHandler,  # defaults to SourceHandler
    engine_model=MyEngine,                 # defaults to BasicCollectorEngine
)
```

## Features

- **Base Collector** — `DaemonProtocol` subclass; auto-loads config, wires source, handler, and engine
- **Basic Engine** — Use-case agnostic 7-step expectation processing pipeline
- **Protocols** — 4 `@runtime_checkable` behavioral contracts for engine, data fetcher, source data, and source handler
- **Resilient Uploader** — Bulk-with-individual-fallback upload infrastructure (internal)
- **Config Base Classes** — Pydantic models for OAEV, collector, and custom configuration
- **DDD Layout** — `_core/` → `contracts/` → `public/` three-layer architecture aligned with `collectors_template`

## Module Map

43 public symbols in `collectors_sdk`:

| Group | Symbols | What it provides |
|---|---|---|
| Errors | `CollectorError`, `CollectorConfigError`, `CollectorEngineConfigError`, `CollectorSetupError`, `CollectorProcessingError`, `ExpectationHandlerError`, `ExpectationProcessingError`, `ExpectationUpdateError`, `BulkUploadError`, `BulkPreparationError`, `APIError`, `TracingError`, `TraceSubmissionError`, `TraceCreationError` | 14-class exception hierarchy |
| Protocols | `CollectorEngineProtocol`, `DataFetcherProtocol`, `SourceDataProtocol`, `SourceHandlerProtocol`, `DaemonProtocol` | Behavioral contracts for extension points (DaemonProtocol re-exported from xtm-oaev-sdk) |
| Data Models | `OAEVData`, `TraceData`, `Source`, `SourceHandler`, `ExpectationResult`, `ExpectationTrace`, `ExpectationSummary` | Pydantic models for the processing pipeline |
| Config | `ConfigBaseSettings`, `ConfigLoaderOAEV`, `ConfigLoaderCollector`, `ConfigLoaderCustom` | Pydantic-settings base classes for collector config |
| Type Aliases | `CustomConfig`, `ExpectationsList`, `SignatureGroups`, `BulkData`, `PrepareBulkFunction`, `BulkUploadFunction`, `UnpackBulkFunction`, `IndividualUploadFunction` | Typed aliases for function signatures and data shapes |
| Engine | `BasicCollectorEngine` | 7-step expectation processing pipeline |
| Base | `BaseCollector` | Lifecycle class wiring source, handler, engine, and config |
| Detection | `SignatureMatcher`, `_decode_value`, `_is_base64_encoded` | Signature matching with base64-aware value decoding |

## Import Convention

Always import from the package root:

```python
from collectors_sdk import BaseCollector, Source, BasicCollectorEngine
```

Never import from private submodules:

```python
# Wrong — internal layout may change without notice
from collectors_sdk._core.base_collector.engines.basic import BasicCollectorEngine
```

The 43 symbols in `__all__` are the stable public API. Everything under `_core/` is an implementation detail.

## Feature-Aware Import Examples

For DDD consumers who need explicit protocol contracts:

```python
# Protocols only (behavioral contracts)
from collectors_sdk import (
    DataFetcherProtocol,
    SourceDataProtocol,
    SourceHandlerProtocol,
    CollectorEngineProtocol,
)

# Config only (extend to add your tool's settings)
from collectors_sdk import (
    ConfigBaseSettings,
    ConfigLoaderOAEV,
    ConfigLoaderCollector,
    ConfigLoaderCustom,
)

# Data models only (for type annotations)
from collectors_sdk import (
    OAEVData,
    TraceData,
    Source,
    ExpectationResult,
    ExpectationSummary,
)

# Error handling
from collectors_sdk import CollectorError, CollectorProcessingError, BulkUploadError

# Detection utilities
from collectors_sdk import SignatureMatcher, _decode_value
```

## Documentation

- [Base Collector](docs/base-collector.md) — DDD architecture, BaseCollector lifecycle, protocols, models, error hierarchy
- [Basic Engine](docs/basic-engine.md) — 7-step processing pipeline, ResilientUploader, SignatureMatcher, configuration
- [Writing a Collector](docs/writing-a-collector.md) — step-by-step guide with a complete working example

## Deprecation Shim Strategy

`pyoaev.helpers.OpenAEVDetectionHelper` is a deprecated wrapper that proxies to this SDK's `SignatureMatcher`:

```python
# Old path (triggers DeprecationWarning, still works)
from pyoaev.helpers import OpenAEVDetectionHelper

# New path (clean, no warning)
from collectors_sdk import SignatureMatcher
```

The shim in `pyoaev` instantiates `SignatureMatcher` internally and delegates `match_alert_elements` / `match_alert_element_fuzzy` calls. Once all connectors are migrated, the shim and `OpenAEVDetectionHelper` are removed from `pyoaev`.

See [SECOND_README.md § Deprecation Shim Strategy](../../SECOND_README.md#deprecation-shim-strategy) for the full lifecycle.

## Dev

```bash
pip install -e ".[dev]"
pytest                                # run tests
pytest --cov=collectors_sdk    # with coverage
mypy --strict collectors_sdk/  # type check
ruff check collectors_sdk/     # lint
```
