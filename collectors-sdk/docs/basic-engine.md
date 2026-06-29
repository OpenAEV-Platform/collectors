# Basic Collector Engine

Use-case agnostic engine implementing the 7-step expectation processing pipeline.

## Architecture

The engine sits between the OpenAEV API (expectations source) and the source handler (data bridge):

```
OpenAEV API ←→ BasicCollectorEngine ←→ SourceHandler ←→ DataFetcher
                      ↕                                     ↕
              ResilientUploader                        Tool/Service
              (bulk + fallback)
```

## Processing Pipeline

Each `run_engine()` call executes one processing cycle:

```
1. Fetch expectations from OpenAEV API
2. Filter: keep only Detection/Prevention types
3. Batch: split into batches (or single batch)
4. Per batch:
   a. Fetch data using DataFetcher
   b. Per expectation:
      i.   Serialize data as OAEVData
      ii.  Group expectation signatures
      iii. Match signatures against OAEVData
      iv.  On match: serialize as TraceData
      v.   Match expectation against source data
      vi.  Build ExpectationResult
5. Upload results via ExpectationUploader
6. Upload traces via TraceUploader
7. Log summary
```

## Usage

```python
from collectors_sdk import BasicCollectorEngine, Source, SourceHandler

source = Source(
    data_fetcher_model=MyDataFetcher,
    source_data_model=MySourceData,
    signatures=SUPPORTED_SIGNATURES,
)

handler = SourceHandler(config=my_config)

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
# → 10 expectations received, 8 supported (2 unsupported),
#   8 processed (0 unprocessed), 5 valid (3 invalid)
```

## Constructor

| Parameter | Type | Required | Default | Purpose |
|---|---|---|---|---|
| `name` | `str` | Yes | | Collector name for logging |
| `collector_id` | `str` | Yes | | Unique collector instance ID |
| `source` | `Source` | Yes | | Source definition |
| `source_handler` | `SourceHandler` | Yes | | Data bridge |
| `oaev_api` | `Any` | Yes | | OpenAEV API client |
| `batching` | `bool` | No | `False` | Enable batch processing |

## Methods

### `configure_engine(config, batching=False)`

Prepares the engine for processing. Must be called before `run_engine()`.

### `run_engine()`

Executes one full processing cycle.

**Raises:**
- `CollectorEngineConfigError` — if called before `configure_engine()`
- `CollectorProcessingError` — if the cycle fails (non-interrupt)

### `fetch_and_filter_expectations()`

Fetches expectations from the API and filters to supported types. Updates `current_summary`.

## Batching

When `batching=True`, expectations are split into batches of size `config.expectation_batch_size` (default: 50). Each batch shares one data fetch — useful when the data source is expensive to query.

```python
engine.configure_engine(config=config, batching=True)
```

Without batching (default), all expectations are processed in a single batch.

## ExpectationSummary

The engine maintains a `current_summary` that tracks the processing cycle:

```python
summary = engine.current_summary
summary.received      # 10 — total from API
summary.supported     # 8  — Detection/Prevention only
summary.unsupported   # 2  — skipped types (computed)
summary.processed     # 8  — results produced
summary.unprocessed   # 0  — skipped during processing (computed)
summary.valid         # 5  — matched expectations
summary.invalid       # 3  — unmatched (computed)
summary.total_skipped # 2  — unsupported + unprocessed (computed)
```

`ExpectationSummary` is intentionally NOT frozen — the engine updates fields in-place during processing.

## Error Handling

| Error | When |
|---|---|
| `CollectorEngineConfigError` | `run_engine()` called before `configure_engine()` |
| `CollectorProcessingError` | Processing cycle fails (wraps original) |
| `ExpectationProcessingError` | Per-expectation failure (captured in result) |
| `BulkUploadError` | Upload failures (from ResilientUploader) |

API fetch failures are handled gracefully — they log the error and return an empty list, allowing the cycle to complete without processing.

## ResilientUploader (Internal)

The engine uses two internal uploaders for results and traces:

- **ExpectationUploader** — bulk-updates expectation results via API
- **TraceUploader** — bulk-creates traces via API

Both inherit from `ResilientUploader`, which implements:

1. Prepare bulk data from results
2. Attempt bulk upload
3. On failure: unpack and upload individually
4. On total failure: raise `BulkUploadError`

These are internal (`_core/`) and not part of the public API.

## CollectorEngineProtocol

The engine satisfies `CollectorEngineProtocol`:

```python
@runtime_checkable
class CollectorEngineProtocol(Protocol):
    def configure_engine(self, config: Any, batching: bool = False) -> None: ...
    def run_engine(self) -> None: ...
```

Custom engines can implement this Protocol to replace `BasicCollectorEngine`.
