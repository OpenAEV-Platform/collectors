# Base Collector

Lifecycle class that wires a source definition, source handler, and collector engine together.

## Architecture

```
BaseCollector
├── Source (data_fetcher_model, source_data_model, signatures)
├── SourceHandler (bridges source data and engine)
└── BasicCollectorEngine (7-step processing pipeline)
```

**Key design principles:**

- **Class, not Protocol**: `BaseCollector` is a concrete class that collectors subclass or instantiate directly. The behavioral contracts for its components (engine, source handler, data fetcher, source data) are Protocols.
- **Dependency injection**: Engine model, source handler model, and config are all injectable. Defaults are provided (`BasicCollectorEngine`, `SourceHandler`).
- **Fail-fast validation**: Constructor validates types with `isinstance`/`issubclass` checks and raises `CollectorConfigError` or `CollectorEngineConfigError` immediately.

## Lifecycle

```
__init__(name, source, config, ...)  → validate + wire components
  ↓
_setup(batching=False)               → configure the engine
  ↓
engine.run_engine()                  → process one cycle (called by daemon)
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
    name="CrowdStrike",
    source=source,
    config=my_custom_config,         # passed to SourceHandler
    collector_id="cs-uuid-001",      # unique instance ID
    oaev_api=oaev_client,            # OpenAEV API client
    source_handler_model=None,       # defaults to SourceHandler
    engine_model=None,               # defaults to BasicCollectorEngine
)
```

| Parameter | Type | Required | Default | Purpose |
|---|---|---|---|---|
| `name` | `str` | Yes | | Human-readable collector name |
| `source` | `Source` | Yes | | Source definition (fetcher, data model, signatures) |
| `config` | `Any` | No | `None` | Custom configuration object |
| `collector_id` | `str` | No | `""` | Unique collector instance identifier |
| `oaev_api` | `Any` | No | `None` | OpenAEV API client instance |
| `source_handler_model` | `type` | No | `SourceHandler` | Custom source handler class |
| `engine_model` | `type` | No | `BasicCollectorEngine` | Custom engine class |

### Validation

The constructor validates:

1. `source` must be a `Source` instance → `CollectorConfigError`
2. `source_handler_model` (if provided) must be a subclass of `SourceHandlerProtocol` → `CollectorConfigError`
3. `engine_model` (if provided) must be a subclass of `CollectorEngineProtocol` → `CollectorConfigError`
4. Engine construction must succeed → `CollectorEngineConfigError`

### Setup

```python
collector._setup(batching=False)
```

Calls `engine.configure_engine(config, batching)` to prepare the engine for processing. Raises `CollectorSetupError` on failure.

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
| `source_data_model` | `type[SourceDataProtocol]` | Class that serializes fetched data |
| `signatures` | `list[Any]` | Supported signature types for matching |

### SourceHandler

Default implementation of `SourceHandlerProtocol`. Bridges fetched data and the engine by providing:

- `get_source_data(fetcher)` — delegates to the data fetcher
- `serialize_as_oaevdata(data)` — converts to OAEVData format
- `serialize_as_tracedata(data)` — converts to TraceData format
- `get_expectation_signature_groups(signatures, expectation)` — groups expectation signatures by type
- `match_signature_groups_and_oaevdata(groups, data, helper)` — matches signatures against data
- `match_expectation_and_sourcedata(expectation, data)` — determines if an expectation is satisfied

## Protocols

### DataFetcherProtocol

```python
@runtime_checkable
class DataFetcherProtocol(Protocol):
    def fetch_data(self) -> list[Any]: ...
```

Implement this to fetch raw data from your security tool (API calls, log reads, etc.).

### SourceDataProtocol

```python
@runtime_checkable
class SourceDataProtocol(Protocol):
    def to_oaev_data(self) -> Any: ...
    def to_traces_data(self) -> Any: ...
    def is_prevented(self) -> bool: ...
    def is_detected(self) -> bool: ...
```

Implement this to define how your tool's data maps to OAEV formats.

## Error Handling

| Error | When |
|---|---|
| `CollectorConfigError` | Constructor validation fails |
| `CollectorEngineConfigError` | Engine initialization fails |
| `CollectorSetupError` | `_setup()` fails |

All inherit from `CollectorError` — catch the base to handle any SDK error.

## Configuration

### Config Base Classes

The SDK provides base Pydantic-settings classes for common collector configuration:

```python
from collectors_sdk import ConfigLoaderOAEV, ConfigLoaderCollector, ConfigLoaderCustom

# OAEV connection
class MyOAEVConfig(ConfigLoaderOAEV):
    pass  # inherits url + token from env vars

# Collector identity
class MyCollectorConfig(ConfigLoaderCollector):
    id: str = Field(default="my-collector-uuid")
    name: str = Field(default="My Collector")

# Custom integration settings
class MyCustomConfig(ConfigLoaderCustom):
    api_key: str = Field(alias="MY_API_KEY")
```

| Base Class | Fields | Purpose |
|---|---|---|
| `ConfigBaseSettings` | (base) | Frozen BaseSettings with env nesting |
| `ConfigLoaderOAEV` | `url`, `token` | OpenAEV platform connection |
| `ConfigLoaderCollector` | `id`, `name`, `platform`, `log_level`, `period`, `icon_filepath` | Collector identity and scheduling |
| `ConfigLoaderCustom` | `key`, `time_window`, `expectation_batch_size` | Per-tool custom settings |

## Scope Boundary

| Concern | Owner | Why |
|---|---|---|
| BaseCollector lifecycle | `collectors-sdk` | Shared by all collectors |
| 4 Protocols | `collectors-sdk` | Behavioral contracts |
| Data models (OAEVData, TraceData, etc.) | `collectors-sdk` | Pipeline data shapes |
| Error hierarchy | `collectors-sdk` | Exception handling contract |
| Config base classes | `collectors-sdk` | Common settings structure |
| BasicCollectorEngine | `collectors-sdk` | Reusable processing pipeline |
| ResilientUploader | `collectors-sdk` (internal) | Upload strategy |
| CollectorDaemon | `pyoaev` | Platform runtime |
| Concrete ConfigLoader | Per-collector | Tool-specific config sources |
| Tool-specific data fetchers | Per-collector | Integration code |
