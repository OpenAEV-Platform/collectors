# Base Collector

Lifecycle class that wires a source definition, source handler, and collector engine together.
`BaseCollector` is a `DaemonProtocol` subclass — it owns the full collector lifecycle: config loading, API client wiring, daemon scheduling, and engine delegation.

## Architecture

### Three-Layer DDD Layout

```
collectors_sdk/
├── public/                         ← User-facing re-exports (43 symbols)
│   └── __init__.py
├── contracts/                      ← Stable interfaces (copy-safe boundaries)
│   ├── base_collector/
│   │   ├── protocols/              DataFetcherProtocol, EngineProtocol,
│   │   │                           SourceDataProtocol, SourceHandlerProtocol
│   │   ├── models/                 OAEVData, TraceData, Source, SourceHandler,
│   │   │                           ExpectationResult, ExpectationTrace, ExpectationSummary
│   │   └── types/                  CustomConfig, ExpectationsList, SignatureGroups,
│   │                               BulkData, *Function aliases
│   └── common/
│       └── errors.py               All 14 error classes
└── _core/                          ← Implementation (private)
    ├── base_collector/             THE feature (mirrors collectors_template/src/collector/)
    │   ├── collector.py            BaseCollector
    │   ├── engines/
    │   │   └── basic.py            BasicCollectorEngine
    │   ├── internals/
    │   │   └── resilient_uploader.py   ResilientUploader
    │   ├── models/
    │   │   ├── data.py             OAEVData, TraceData
    │   │   ├── exception.py        14-class error hierarchy
    │   │   ├── expectations.py     ExpectationResult, ExpectationTrace, ExpectationSummary
    │   │   └── source.py           Source, SourceHandler
    │   ├── protocols/
    │   │   ├── data_fetcher.py     DataFetcherProtocol
    │   │   ├── engine.py           CollectorEngineProtocol
    │   │   ├── source_data.py      SourceDataProtocol
    │   │   └── source_handler.py   SourceHandlerProtocol
    │   ├── types/
    │   │   ├── collector.py        CustomConfig, ExpectationsList, SignatureGroups
    │   │   └── internals.py        BulkData, *Function aliases
    │   └── utils/
    │       ├── detection.py        SignatureMatcher, _decode_value, _is_base64_encoded
    │       └── retroport_itertools.py  batched()
    └── config/
        └── settings.py             ConfigBaseSettings, ConfigLoader*
```

### Template Alignment

`_core/base_collector/` mirrors `collectors_template/template/src/collector/` 1:1:

```
collectors_template/src/collector/    _core/base_collector/
├── collector.py                      ├── collector.py
├── engines/basic.py                  ├── engines/basic.py
├── internals/                        ├── internals/resilient_uploader.py
├── models/                           ├── models/ (data, exception, expectations, source)
├── protocols/                        ├── protocols/ (data_fetcher, engine, source_data, source_handler)
├── types/                            ├── types/ (collector, internals)
└── utils/                            └── utils/ (retroport_itertools, detection)
```

Developers familiar with the template find the same structure in the SDK.

**Key design principles:**

- **DaemonProtocol subclass**: `BaseCollector` subclasses `DaemonProtocol` (from `xtm-oaev-sdk`). It inherits `start()`, `set_callback()`, `get_id()`, `_setup()`, and `self.api`.
- **Auto-wired config**: Constructor creates `ConfigBaseSettings()` internally. No explicit `config`, `collector_id`, or `oaev_api` parameters.
- **Dependency injection**: Source handler model and engine model are injectable. Defaults are `SourceHandler` and `BasicCollectorEngine`.
- **Fail-fast validation**: Constructor validates types with `isinstance`/`issubclass` checks and raises `CollectorConfigError` immediately on failure.

## Lifecycle

```
__init__(name, source, ...)     → load ConfigBaseSettings, validate + wire components
  ↓
_setup(batching=False)          → configure the engine
  ↓
engine.run_engine()             → process one cycle (called by daemon on schedule)
```

### Constructor

```python
from collectors_sdk import BaseCollector, Source

source = Source(
    data_fetcher_model=MyDataFetcher,
    source_data_model=MySourceData,
    signatures=SUPPORTED_SIGNATURES,
)

collector = BaseCollector(
    name="My Collector",
    source=source,
    source_handler_model=None,   # defaults to SourceHandler
    engine_model=None,           # defaults to BasicCollectorEngine
)
```

| Parameter | Type | Required | Default | Purpose |
|---|---|---|---|---|
| `name` | `str` | Yes | | Human-readable collector name; used for daemon type and log prefixes |
| `source` | `Source` | Yes | | Source definition (fetcher model, data model, signatures) |
| `source_handler_model` | `type[SourceHandlerProtocol]` | No | `SourceHandler` | Custom source handler class |
| `engine_model` | `type[CollectorEngineProtocol]` | No | `BasicCollectorEngine` | Custom engine class |

Config, API client, and collector ID are resolved automatically:

- `ConfigBaseSettings()` is constructed and stored as `self.config`.
- `self.config.to_daemon_config()` is passed to the `DaemonProtocol` parent.
- `self.api` (the OpenAEV client) is provided by `DaemonProtocol` after `super().__init__`.
- `self.get_id()` (the unique collector ID) is provided by `DaemonProtocol`.

### Validation

The constructor validates in order:

1. `source` must be a `Source` instance → `CollectorConfigError`
2. `source_handler_model` (if provided) must be a subclass of `SourceHandlerProtocol` → `CollectorConfigError`
3. `engine_model` (if provided) must be a subclass of `CollectorEngineProtocol` → `CollectorConfigError`
4. Any `ConfigBaseSettings` load failure → `CollectorConfigError`
5. Engine construction failure → `CollectorEngineConfigError`

### Setup

```python
collector._setup(batching=False)
```

Called automatically by the daemon before the first cycle. Calls `engine.configure_engine(config.custom, batching)` to prepare the engine. Raises `CollectorSetupError` on failure.

## Source Definition

### Source

```python
from collectors_sdk import Source

source = Source(
    data_fetcher_model=CrowdStrikeDataFetcher,
    source_data_model=CrowdStrikeAlert,
    signatures=[SignatureTypes.PROCESS_NAME, SignatureTypes.COMMAND_LINE],
)
```

| Field | Type | Purpose |
|---|---|---|
| `data_fetcher_model` | `type[DataFetcherProtocol]` | Class that fetches raw data from the tool |
| `source_data_model` | `type[SourceDataProtocol]` | Class that normalizes fetched data |
| `signatures` | `list[SignatureTypes]` | Supported signature types for matching |

### SourceHandler

Default implementation of `SourceHandlerProtocol`. Bridges the engine and the source by providing:

| Method | Purpose |
|---|---|
| `get_source_data(fetcher)` | Delegates to `fetcher.fetch_data()` |
| `serialize_as_oaevdata(data)` | Calls `data.to_oaev_data()` |
| `serialize_as_tracedata(data)` | Calls `data.to_traces_data()` |
| `get_expectation_signature_groups(signatures, expectation)` | Groups expectation signatures by type (skips `end_date`) |
| `match_signature_groups_and_oaevdata(groups, data, helper)` | Matches grouped signatures against OAEVData fields |
| `match_expectation_and_sourcedata(expectation, data)` | Returns `(matchflag, breakflag)` for prevention/detection |

## Protocols

All four protocols are `@runtime_checkable`.

### DataFetcherProtocol

```python
@runtime_checkable
class DataFetcherProtocol(Protocol):
    def __init__(self, config: CustomConfig) -> None: ...
    def fetch_data(self) -> list[SourceDataProtocol]: ...
```

Implement this to fetch raw data from your security tool (API calls, log reads, etc.). The engine instantiates your fetcher via `data_fetcher_model(config)` on every batch.

### SourceDataProtocol

```python
@runtime_checkable
class SourceDataProtocol(Protocol):
    def to_oaev_data(self) -> OAEVData: ...
    def to_traces_data(self) -> TraceData: ...
    def is_prevented(self) -> bool: ...
    def is_detected(self) -> bool: ...
    def __str__(self) -> str: ...
```

Implement this to define how your tool's alert/event maps to OAEV formats. One instance per alert.

### SourceHandlerProtocol

```python
@runtime_checkable
class SourceHandlerProtocol(Protocol):
    def __init__(self, config: CustomConfig) -> None: ...
    def get_source_data(self, data_fetcher: DataFetcherProtocol) -> list[SourceDataProtocol]: ...
    def serialize_as_oaevdata(self, data: SourceDataProtocol) -> OAEVData: ...
    def get_expectation_signature_groups(
        self, signatures: list[SignatureTypes], expectation: any
    ) -> SignatureGroups: ...
    def match_signature_groups_and_oaevdata(
        self, signature_groups: SignatureGroups, oaev_data: OAEVData, oaev_detection_helper: any
    ) -> bool: ...
    def serialize_as_tracedata(self, data: SourceDataProtocol) -> TraceData: ...
    def match_expectation_and_sourcedata(
        self, expectation: any, data: SourceDataProtocol
    ) -> tuple[bool, bool]: ...
```

The default `SourceHandler` satisfies this protocol. Replace it when you need custom matching or serialization logic.

### CollectorEngineProtocol

```python
@runtime_checkable
class CollectorEngineProtocol(Protocol):
    def __init__(
        self, name: str, collector_id: str, source: Source,
        source_handler: SourceHandlerProtocol, oaev_api: any, batching: bool = False,
    ) -> None: ...
    def configure_engine(self, config: CustomConfig, batching: bool = False) -> None: ...
    def run_engine(self) -> None: ...
```

`BasicCollectorEngine` satisfies this protocol. Implement it to replace the default engine.

## Data Models

### OAEVData

Normalized detection data for signature matching. Fields must be valid `SignatureTypes` values — the model validates field names at construction time.

```python
from collectors_sdk import OAEVData

data = OAEVData(
    parent_process_name="evil.exe",
    source_ipv4_address="10.0.0.1",
)
```

Unknown field names raise `ValueError` via a `model_validator`. Extra fields are allowed only if they are valid signature type values.

### TraceData

Trace metadata produced per matched alert.

| Field | Type | Required | Default | Purpose |
|---|---|---|---|---|
| `alert_name` | `str` | Yes | | Human-readable alert name |
| `alert_link` | `AnyUrl` | Yes | | Link to the alert in the source system |
| `alert_date` | `datetime` | No | `datetime.now(UTC)` | Alert timestamp |

### Source

See [Source Definition](#source-definition) above.

### SourceHandler

See [SourceHandler](#sourcehandler) above.

### ExpectationResult

Result of processing one expectation.

| Field | Type | Purpose |
|---|---|---|
| `expectation_id` | `str` | ID of the processed expectation |
| `is_valid` | `bool` | Whether the expectation was satisfied |
| `expectation` | `Any \| None` | The original expectation object |
| `matched_alerts` | `list[dict]` | Alerts that matched this expectation |
| `error_message` | `str \| None` | Error message if processing failed |
| `processing_time` | `float \| None` | Processing duration in seconds |

**Class methods:**

- `ExpectationResult.from_error(error, expectation)` — creates a failed result from an exception

**Instance methods:**

- `result.to_result_text()` — returns `"Prevented"` / `"Not Prevented"` / `"Detected"` / `"Not Detected"` based on expectation type and `is_valid`

### ExpectationTrace

Pydantic model for submitting a trace to the OpenAEV API. Built from an `ExpectationResult` via `ExpectationTrace.from_result(result, collector_id, collector_name)`.

| Field | Purpose |
|---|---|
| `inject_expectation_trace_expectation` | Expectation ID |
| `inject_expectation_trace_source_id` | Collector/source ID |
| `inject_expectation_trace_alert_name` | Matched alert name |
| `inject_expectation_trace_alert_link` | Alert link in the source system |
| `inject_expectation_trace_date` | ISO 8601 timestamp |

All fields are validated as non-empty strings. `to_api_dict()` returns a `dict[str, str]` ready for API submission.

### ExpectationSummary

Tracks one processing cycle. `NOT` frozen — the engine updates fields in-place.

| Field / Property | Type | Kind | Purpose |
|---|---|---|---|
| `received` | `int` | field | Total expectations fetched from API |
| `supported` | `int` | field | Expectations that passed the filter |
| `processed` | `int` | field | Expectations with a result produced |
| `valid` | `int` | field | Expectations satisfied |
| `total_processing_time` | `float \| None` | field | Total cycle duration |
| `unsupported` | `int` | property | `received − supported` |
| `unprocessed` | `int` | property | `supported − processed` |
| `invalid` | `int` | property | `processed − valid` |
| `total_skipped` | `int` | property | `received − processed` |

## Error Hierarchy

All exceptions inherit from `CollectorError`. Catch the base to handle any SDK error.

```
CollectorError
├── CollectorConfigError          Constructor validation fails (source, handler, engine types)
├── CollectorEngineConfigError    Engine initialization or run_engine() before configure_engine()
├── CollectorSetupError           _setup() fails
├── CollectorProcessingError      Processing cycle fails
├── ExpectationHandlerError       Expectation handler failure
├── ExpectationProcessingError    Per-expectation processing failure
├── ExpectationUpdateError        Expectation update failure
│   ├── BulkUploadError           Bulk upload and individual fallback both fail
│   └── BulkPreparationError      Bulk data preparation fails
├── APIError                      API operation failure
└── TracingError                  Tracing operation failure
    ├── TraceSubmissionError      Trace submission fails
    └── TraceCreationError        Trace creation fails
```

## Type Aliases

### Collector domain (`_core/base_collector/types/collector.py`)

| Alias | Definition | Purpose |
|---|---|---|
| `CustomConfig` | `any` | Config object passed to handlers and engine |
| `ExpectationsList` | `Sequence[any]` | List of expectation objects from the API |
| `SignatureGroups` | `dict[str, list[dict[str, str]]]` | Grouped signatures keyed by type value |

### Internals domain (`_core/base_collector/types/internals.py`)

| Alias | Definition | Purpose |
|---|---|---|
| `BulkData` | `Mapping[str, Any] \| Sequence[Any]` | Payload for bulk API operations |
| `PrepareBulkFunction` | `Callable[[list[Any]], tuple[BulkData, int]]` | Prepares bulk payload, returns `(data, skipped)` |
| `BulkUploadFunction` | `Callable[[BulkData], None]` | Performs bulk API upload |
| `UnpackBulkFunction` | `Callable[[BulkData], Iterable[tuple[Any, Any]]]` | Unpacks bulk data into `(index, item)` pairs |
| `IndividualUploadFunction` | `Callable[[Any, Any], None]` | Uploads a single item as fallback |

## Configuration

`ConfigBaseSettings` is loaded automatically inside `BaseCollector.__init__`. See [Basic Engine — Configuration](basic-engine.md#configuration) for the full class reference and YAML/env var setup.

## Scope Boundary

| Concern | Owner |
|---|---|
| BaseCollector lifecycle | `collectors-sdk` |
| DaemonProtocol (`start`, `set_callback`, `get_id`, `self.api`) | `xtm-oaev-sdk` (re-exported) |
| 4 Protocols | `collectors-sdk` |
| Data models | `collectors-sdk` |
| Error hierarchy | `collectors-sdk` |
| Config base classes | `collectors-sdk` |
| BasicCollectorEngine | `collectors-sdk` |
| ResilientUploader | `collectors-sdk` (internal) |
| CollectorDaemon (concrete) | `pyoaev` |
| Concrete config loader | Per-collector |
| Tool-specific data fetchers | Per-collector |
