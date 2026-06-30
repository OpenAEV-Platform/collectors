# Basic Collector Engine

Use-case agnostic engine implementing the expectation processing pipeline.

## Architecture

The engine sits between the OpenAEV API (expectations source) and the source handler (data bridge):

```
OpenAEV API ←→ BasicCollectorEngine ←→ SourceHandler ←→ DataFetcher
                      ↕                                      ↕
              ResilientUploader                         Tool/Service
              (bulk + fallback)
```

## Processing Pipeline

Each `run_engine()` call executes one processing cycle in 7 steps:

```
1. Fetch expectations from OpenAEV API (reversed order)
2. Filter: keep only expectations with inject_expectation_id
3. Batch: split into batches of expectation_batch_size (or single batch)
4. Per batch: fetch data via DataFetcher
5. Per expectation × per data element:
      a. Serialize element as OAEVData
      b. Group expectation signatures by type
      c. Match signature groups against OAEVData
      d. On match: serialize as TraceData, evaluate matchflag + breakflag
      e. Build ExpectationResult (valid or error)
6. Aggregate results: update processed and valid counts in ExpectationSummary
7. Log processing summary
```

API fetch failures are handled gracefully — they log and return an empty list, completing the cycle without processing.

## Usage

```python
from collectors_sdk import BasicCollectorEngine, Source, SourceHandler

source = Source(
    data_fetcher_model=MyDataFetcher,
    source_data_model=MySourceData,
    signatures=SUPPORTED_SIGNATURES,
)

handler = SourceHandler(config=my_custom_config)

engine = BasicCollectorEngine(
    name="CrowdStrike",
    collector_id="cs-uuid-001",
    source=source,
    source_handler=handler,
    oaev_api=oaev_client,
)

# Must configure before running
engine.configure_engine(config=my_config, batching=True)

# Execute one processing cycle
engine.run_engine()

# Check results
print(engine.current_summary)
# → 10 expectations received, 8 expectations supported (2 unsupported),
#   8 expectations processed (0 unprocessed), 5 valid expectations (3 invalid)
```

In practice `BaseCollector` constructs and wires the engine automatically — direct instantiation is only needed for custom setups or testing.

## Constructor

| Parameter | Type | Required | Default | Purpose |
|---|---|---|---|---|
| `name` | `str` | Yes | | Collector name for logging |
| `collector_id` | `str` | Yes | | Unique collector instance ID |
| `source` | `Source` | Yes | | Source definition |
| `source_handler` | `SourceHandlerProtocol` | Yes | | Data bridge |
| `oaev_api` | `any` | Yes | | OpenAEV API client |
| `batching` | `bool` | No | `False` | Enable batch processing |

Constructor validates that `source` is a `Source` instance, `source_handler` satisfies `SourceHandlerProtocol`, and `oaev_api` is not `None`. Violations raise `TypeError` (wrapped into `CollectorEngineConfigError` by `BaseCollector`).

## Methods

### `configure_engine(config, batching=False)`

Prepares the engine for processing. Must be called before `run_engine()`. Stores config, sets batching flag, resets the summary, and sets `configured = True`.

### `run_engine()`

Executes one full processing cycle.

**Raises:**
- `CollectorEngineConfigError` — if called before `configure_engine()`
- `CollectorProcessingError` — if the cycle fails (wraps original exception)

`KeyboardInterrupt` and `SystemExit` are caught and call `os._exit(0)` — the engine stops cleanly without raising.

### `fetch_and_filter_expectations()`

Fetches expectations from the API via `oaev_api.inject_expectation.expectations_models_for_source(source_id=collector_id)`, reverses order (oldest-first), then filters to supported types. Updates `current_summary.received` and `current_summary.supported`.

## Batching

When `batching=True`, expectations are split into tuples of size `config.expectation_batch_size` (default: `50`) using the internal `batched()` utility (a Python 3.12 `itertools.batched` backport). Each batch triggers one call to the DataFetcher — useful when the data source is expensive to query.

```python
engine.configure_engine(config=config, batching=True)
```

Without batching (default), all expectations are processed as a single batch with one data fetch.

## ExpectationSummary

The engine maintains a `current_summary` that tracks the processing cycle. It resets at the start of each `run_engine()` call.

```python
summary = engine.current_summary
summary.received      # 10 — total from API
summary.supported     # 8  — passed filter
summary.unsupported   # 2  — skipped (computed)
summary.processed     # 8  — results produced
summary.unprocessed   # 0  — skipped during processing (computed)
summary.valid         # 5  — matched expectations
summary.invalid       # 3  — unmatched (computed)
summary.total_skipped # 2  — received − processed (computed)
```

## Error Handling

| Error | When |
|---|---|
| `CollectorEngineConfigError` | `run_engine()` called before `configure_engine()` |
| `CollectorProcessingError` | Processing cycle fails (wraps original) |
| `ExpectationProcessingError` | Per-expectation failure (captured in `ExpectationResult.error_message`) |
| `BulkUploadError` | Upload failures (from `ResilientUploader`) |
| `BulkPreparationError` | Bulk data preparation failure (from `ResilientUploader`) |

## ResilientUploader (Internal)

`ResilientUploader` is upload infrastructure in `_core/base_collector/internals/resilient_uploader.py`. It is not part of the public API but is the basis for any uploader built on top of the SDK.

### Strategy

```
upload_data(data)
  ↓
prepare_bulk_data(data)       → calls _prepare_bulk_data(data) → (BulkData, skipped_count)
  ↓
bulk_upload_data(bulk_data)   → calls _bulk_upload(bulk_data)
  ↓ (on bulk failure)
individual fallback:          → for index, item in _unpack_bulk_data(bulk_data):
                                    _individual_upload(index, item)
  ↓ (on total failure)
raise BulkUploadError
```

### Constructor

```python
uploader = ResilientUploader(
    data_name="results",
    _prepare_bulk_data=my_prepare_fn,    # (list[Any]) → (BulkData, int)
    _bulk_upload=my_bulk_upload_fn,      # (BulkData) → None
    _unpack_bulk_data=my_unpack_fn,      # (BulkData) → Iterable[tuple[Any, Any]]
    _individual_upload=my_upload_fn,     # (Any, Any) → None
)
uploader.upload_data(results)
```

All callable slots are injected at construction time, matching the `PrepareBulkFunction`, `BulkUploadFunction`, `UnpackBulkFunction`, and `IndividualUploadFunction` type aliases.

### Error Handling

| Error | When |
|---|---|
| `BulkPreparationError` | `_prepare_bulk_data` raises |
| `BulkUploadError` | Both bulk upload and individual fallback fail |
| `APIError` | Per-item API failure during fallback (logged, not re-raised) |

## SignatureMatcher

Utility for matching source data against expectation signature values. Located in `_core/base_collector/utils/detection.py`.

```python
from collectors_sdk import SignatureMatcher
from xtm_oaev_sdk import SignatureTypes

matcher = SignatureMatcher(
    supported_signatures=[
        SignatureTypes.PROCESS_NAME,
        SignatureTypes.SOURCE_IPV4_ADDRESS,
    ]
)

# Case-insensitive equality match with base64-aware decoding
is_match = matcher.match(
    signature_type="process_name",
    expected_value="evil.exe",
    actual_value="EVIL.EXE",
)
# → True

# Check and decode a possibly base64-encoded value
from collectors_sdk import _decode_value, _is_base64_encoded

raw = "ZXZpbC5leGU="
if _is_base64_encoded(raw):
    print(_decode_value(raw))   # → "evil.exe"
```

### API

| Symbol | Signature | Purpose |
|---|---|---|
| `SignatureMatcher.__init__` | `(supported_signatures: list[SignatureTypes])` | Stores supported signature list |
| `SignatureMatcher.match` | `(signature_type: str, expected_value: str, actual_value: str) → bool` | Case-insensitive equality after base64 decode |
| `_decode_value` | `(value: Any) → str` | Returns decoded string; auto-detects base64 |
| `_is_base64_encoded` | `(value: str) → bool` | Returns `True` if value is valid base64 |

`SignatureMatcher.match` decodes both `expected_value` and `actual_value` before comparing. Comparison is case-insensitive (`lower()`).

## Configuration

`ConfigBaseSettings` is the top-level settings class. It inherits `SettingsLoader` from `xtm-oaev-sdk` and loads from `config.yml` + environment variables automatically.

### Class Hierarchy

```
SettingsLoader  (xtm_oaev_sdk)
└── ConfigBaseSettings            top-level loader; reads config.yml + env
```

```
pydantic.BaseModel
├── ConfigLoaderOAEV              openaev.url + openaev.token
├── ConfigLoaderCollector         collector.id/name/platform/log_level/period/icon_filepath
└── ConfigLoaderCustom            custom.key/time_window/expectation_batch_size
```

### ConfigLoaderOAEV

| Field | Type | Purpose |
|---|---|---|
| `url` | `HttpUrl` (serialized as `str`) | OpenAEV platform URL |
| `token` | `str` | Bearer token for the API |

### ConfigLoaderCollector

| Field | Type | Default | Purpose |
|---|---|---|---|
| `id` | `str` | | Unique collector instance identifier |
| `name` | `str` | | Human-readable collector name |
| `platform` | `str \| None` | `"EDR"` | Platform type tag |
| `log_level` | `"debug"\|"info"\|"warn"\|"error"\|None` | `"error"` | Log verbosity |
| `period` | `timedelta \| None` | `timedelta(minutes=2)` | Schedule interval |
| `icon_filepath` | `str \| None` | `"src/img/template-logo.png"` | Collector icon path |

### ConfigLoaderCustom

Subclass this to add tool-specific settings:

```python
from collectors_sdk import ConfigLoaderCustom
from pydantic import Field
from datetime import timedelta

class MyConfig(ConfigLoaderCustom):
    api_key: str = Field(alias="CUSTOM_API_KEY")
    base_url: str = Field(alias="CUSTOM_BASE_URL")
    time_window: timedelta = Field(
        alias="CUSTOM_TIME_WINDOW",
        default=timedelta(hours=1),
    )
```

Base fields:

| Field | Type | Default | Purpose |
|---|---|---|---|
| `key` | `str \| None` | `"value"` | Placeholder example field |
| `time_window` | `timedelta` | `timedelta(hours=1)` | Lookback window for threat searches |
| `expectation_batch_size` | `int` | `50` | Expectations per batch |

### ConfigBaseSettings

Top-level loader. Uses `SettingsLoader` from `xtm-oaev-sdk` as base. Source priority (highest to lowest):

1. Init values
2. Environment variables
3. `config.yml` (auto-discovered at `./config.yml` or `../config.yml`)
4. `.env` file (auto-discovered at `../.env`)

```yaml
# config.yml
openaev:
  url: "http://localhost:8080"
  token: "your-api-token"

collector:
  id: "my-collector-uuid"
  name: "My Vendor Collector"
  log_level: "info"
  period: "PT2M"

custom:
  api_key: "your-vendor-key"
  base_url: "https://vendor-api.example.com"
  time_window: "PT1H"
```

The `custom` section is loaded via the `SettingsLoader` base class. To use a custom `ConfigLoaderCustom` subclass, override `ConfigBaseSettings` in your collector package and declare the `custom` field with your subclass type.

### batched() Utility

`_core/base_collector/utils/retroport_itertools.py` provides `batched(iterable, n)` — a backport of `itertools.batched` from Python 3.12. Returns an iterator of `tuple` batches of length `n` (last batch may be shorter). Raises `ValueError` if `n < 1`.
