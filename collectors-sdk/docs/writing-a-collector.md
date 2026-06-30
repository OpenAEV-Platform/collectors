# Writing a Collector from Scratch

This guide walks you through building a new collector using `collectors-sdk`. By the end you'll have a fully working collector that fetches data from a vendor API, matches it against OpenAEV expectations, and reports results.

## Prerequisites

- Python 3.12+
- Access to `collectors-sdk` and `xtm-oaev-sdk` packages
- A vendor API to collect alerts or events from

## Project Structure

```
my_collector/
├── pyproject.toml
├── config.yml               # Config file (auto-discovered by SDK)
├── my_collector/
│   ├── __init__.py
│   ├── __main__.py          # Entry point
│   ├── collector.py         # BaseCollector wiring
│   ├── config.py            # ConfigBaseSettings subclass (custom section)
│   ├── source/
│   │   ├── __init__.py
│   │   ├── signatures.py    # SUPPORTED_SIGNATURES list
│   │   ├── source_data.py   # SourceDataProtocol implementation
│   │   └── data_fetcher.py  # DataFetcherProtocol implementation
│   └── services/
│       ├── __init__.py
│       └── vendor_client.py # HTTP client for the vendor API
└── tests/
    ├── __init__.py
    └── test_source_data.py
```

## Step 1: Define Supported Signatures

Signatures declare which expectation signature types your collector can match. Import `SignatureTypes` from `xtm_oaev_sdk`:

```python
# my_collector/source/signatures.py
from xtm_oaev_sdk import SignatureTypes

SUPPORTED_SIGNATURES = [
    SignatureTypes.SIG_TYPE_SOURCE_IPV4_ADDRESS,
    SignatureTypes.SIG_TYPE_TARGET_IPV4_ADDRESS,
    SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME,
    SignatureTypes.SIG_TYPE_START_DATE,
    SignatureTypes.SIG_TYPE_END_DATE,
]
```

Choose only the types your vendor data actually contains. The engine skips signature groups whose type is not in this list (and always skips `end_date`).

## Step 2: Implement SourceDataProtocol

Each vendor alert or event becomes one `SourceData` instance. The engine uses this protocol to serialize data for matching and tracing:

```python
# my_collector/source/source_data.py
from collectors_sdk import OAEVData, TraceData


class MySourceData:
    """One normalized vendor alert. Implements SourceDataProtocol."""

    def __init__(self, alert: dict) -> None:
        self.alert = alert

    def to_oaev_data(self) -> OAEVData:
        """Map vendor fields to OpenAEV normalized fields."""
        return OAEVData(
            parent_process_name=self.alert.get("process"),
            source_ipv4_address=self.alert.get("src_ip"),
            target_ipv4_address=self.alert.get("dst_ip"),
        )

    def to_traces_data(self) -> TraceData:
        """Build trace metadata for the reporting pipeline."""
        return TraceData(
            alert_name=f"Alert: {self.alert.get('title', 'unknown')}",
            alert_link=f"https://vendor.example.com/alerts/{self.alert.get('id')}",
        )

    def is_prevented(self) -> bool:
        """Return True if the threat was actively blocked."""
        return self.alert.get("action") == "blocked"

    def is_detected(self) -> bool:
        """Return True if the threat was detected but not blocked."""
        return self.alert.get("action") == "detected"

    def __str__(self) -> str:
        return f"[{self.alert.get('id')}] {self.alert.get('title', '')[:60]}"
```

### OAEVData field names

`OAEVData` accepts only field names that correspond to `SignatureTypes` values. Pass only fields your vendor data actually has:

| OAEVData field | SignatureTypes value |
|---|---|
| `parent_process_name` | `SIG_TYPE_PARENT_PROCESS_NAME` |
| `source_ipv4_address` | `SIG_TYPE_SOURCE_IPV4_ADDRESS` |
| `target_ipv4_address` | `SIG_TYPE_TARGET_IPV4_ADDRESS` |
| `target_hostname_address` | `SIG_TYPE_TARGET_HOSTNAME_ADDRESS` |
| *(see `SignatureTypes` enum for full list)* | |

Any field name not in `SignatureTypes` raises `ValueError` at construction time.

### is_prevented vs is_detected

The engine checks expectation type to decide which flag to evaluate:

- Expectations with `inject_expectation_prevention` → calls `is_prevented()`; sets `breakflag=True` on match (stops scanning remaining data elements)
- All other expectations → calls `is_detected()`; continues scanning after a match

## Step 3: Implement DataFetcherProtocol

The data fetcher retrieves raw vendor data and returns a list of `SourceData` objects. The engine instantiates your fetcher class with `data_fetcher_model(config)` on every batch:

```python
# my_collector/source/data_fetcher.py
from collectors_sdk import CustomConfig
from my_collector.source.source_data import MySourceData
from my_collector.services.vendor_client import VendorClient


class MyDataFetcher:
    """Fetches alerts from vendor API. Implements DataFetcherProtocol."""

    def __init__(self, config: CustomConfig) -> None:
        self.config = config
        self.client = VendorClient(
            base_url=self.config.base_url,
            api_key=self.config.api_key,
        )

    def fetch_data(self) -> list[MySourceData]:
        """Fetch and normalize vendor alerts."""
        raw_alerts = self.client.get_alerts(
            time_window=self.config.time_window
        )
        return [MySourceData(alert=a) for a in raw_alerts]
```

The `config` argument is `self.config.custom` from `ConfigBaseSettings` — the `ConfigLoaderCustom` instance (see Step 4).

## Step 4: Custom Configuration

Subclass `ConfigLoaderCustom` to add vendor-specific settings, then declare it as the `custom` field in your `ConfigBaseSettings` subclass:

```python
# my_collector/config.py
from datetime import timedelta
from collectors_sdk import ConfigBaseSettings, ConfigLoaderCustom
from pydantic import Field


class MyCustomConfig(ConfigLoaderCustom):
    """Vendor-specific configuration.

    Env vars (with YAML equivalents under custom:):
        CUSTOM_API_KEY      Vendor API authentication key
        CUSTOM_BASE_URL     Vendor API base URL
        CUSTOM_TIME_WINDOW  Lookback window (ISO 8601 duration, e.g. PT1H)
    """

    api_key: str = Field(alias="CUSTOM_API_KEY")
    base_url: str = Field(alias="CUSTOM_BASE_URL")
    time_window: timedelta = Field(
        alias="CUSTOM_TIME_WINDOW",
        default=timedelta(hours=1),
    )


class MyCollectorSettings(ConfigBaseSettings):
    """Top-level settings with custom section bound to MyCustomConfig."""

    custom: MyCustomConfig
```

With `MyCollectorSettings` in place, `self.config.custom` in `BaseCollector` resolves to a `MyCustomConfig` instance, so `self.config.custom.api_key` and `self.config.custom.base_url` are available to your `DataFetcher`.

All fields use a `CUSTOM_` prefix for environment variable names. The base class handles loading from `config.yml` and environment variables automatically.

## Step 5: Wire the Collector

```python
# my_collector/collector.py
import os
import sys

from collectors_sdk import BaseCollector, Source
from my_collector.source.data_fetcher import MyDataFetcher
from my_collector.source.source_data import MySourceData
from my_collector.source.signatures import SUPPORTED_SIGNATURES


def main() -> None:
    """Start the collector."""
    try:
        source = Source(
            data_fetcher_model=MyDataFetcher,
            source_data_model=MySourceData,
            signatures=SUPPORTED_SIGNATURES,
        )
        # Config, API client, and collector ID are auto-wired from ConfigBaseSettings
        collector = BaseCollector(
            name="My Vendor Collector",
            source=source,
        )
        collector.start()
    except KeyboardInterrupt:
        os._exit(0)
    except Exception as err:
        print(f"Fatal: {err}")
        sys.exit(1)
```

Entry point:

```python
# my_collector/__main__.py
from my_collector.collector import main

if __name__ == "__main__":
    main()
```

## Step 6: Configuration File

Create `config.yml` next to your package. The SDK auto-discovers it at `./config.yml` or `../config.yml`:

```yaml
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

Alternatively, use environment variables: `OPENAEV_URL`, `OPENAEV_TOKEN`, `COLLECTOR_ID`, `COLLECTOR_NAME`, `CUSTOM_API_KEY`, `CUSTOM_BASE_URL`, `CUSTOM_TIME_WINDOW`.

Provide `.env.sample` and `config.yml.sample` in your repository for documentation.

## Step 7: Detection Matching (Optional)

Use `SignatureMatcher` for explicit value matching when implementing a custom `SourceHandler`:

```python
from collectors_sdk import SignatureMatcher
from xtm_oaev_sdk import SignatureTypes

matcher = SignatureMatcher(
    supported_signatures=[
        SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME,
        SignatureTypes.SIG_TYPE_TARGET_HOSTNAME_ADDRESS,
    ]
)

# Case-insensitive equality with base64-aware decoding
is_match = matcher.match(
    signature_type="parent_process_name",
    expected_value="evil.exe",
    actual_value="EVIL.EXE",   # → True
)
```

`SignatureMatcher.match` decodes both values (base64 if detected) and compares case-insensitively. There is no fuzzy scoring — values must match exactly after normalization.

## Step 8: Running

```bash
# Direct
python -m my_collector

# Docker
docker run \
  -e OPENAEV_URL=http://oaev:8080 \
  -e OPENAEV_TOKEN=... \
  -e CUSTOM_API_KEY=... \
  -e CUSTOM_BASE_URL=... \
  my-collector
```

## SDK Components Reference

| Component | Import | Purpose |
|---|---|---|
| `BaseCollector` | `collectors_sdk` | Daemon lifecycle, config auto-wiring, API + ID from DaemonProtocol |
| `BasicCollectorEngine` | `collectors_sdk` | Default engine: fetch → filter → match → result |
| `Source` | `collectors_sdk` | Bundles data_fetcher + source_data + signatures |
| `ConfigBaseSettings` | `collectors_sdk` | Top-level loader (subclass to bind custom section) |
| `ConfigLoaderCustom` | `collectors_sdk` | Base for tool-specific Pydantic config |
| `SignatureMatcher` | `collectors_sdk` | Case-insensitive value matching with base64 decode |
| `OAEVData` | `collectors_sdk` | Normalized detection data model |
| `TraceData` | `collectors_sdk` | Trace metadata model |
| `SignatureTypes` | `xtm_oaev_sdk` | Enum of all signature type identifiers |
| `DaemonProtocol` | `collectors_sdk` | Behavioral contract for daemon runtime (re-exported) |

## Testing

Unit tests should validate your protocol implementations independently:

```python
# tests/test_source_data.py
from my_collector.source.source_data import MySourceData


def test_to_oaev_data_maps_vendor_fields():
    sd = MySourceData(alert={"process": "evil.exe", "src_ip": "10.0.0.1"})
    oaev = sd.to_oaev_data()
    assert oaev.parent_process_name == "evil.exe"
    assert oaev.source_ipv4_address == "10.0.0.1"


def test_is_prevented_when_action_blocked():
    sd = MySourceData(alert={"id": "1", "action": "blocked"})
    assert sd.is_prevented() is True
    assert sd.is_detected() is False


def test_is_detected_when_action_detected():
    sd = MySourceData(alert={"id": "2", "action": "detected"})
    assert sd.is_detected() is True
    assert sd.is_prevented() is False


def test_str_includes_id():
    sd = MySourceData(alert={"id": "abc123", "title": "Test Alert"})
    assert "abc123" in str(sd)


def test_no_deprecated_imports():
    """Ensure no legacy pyoaev paths are used."""
    import importlib
    import pkgutil
    import my_collector

    for _, name, _ in pkgutil.walk_packages(my_collector.__path__, "my_collector."):
        mod = importlib.import_module(name)
        if mod.__file__:
            content = open(mod.__file__).read()
            assert "pyoaev.configuration" not in content
            assert "pyoaev.exceptions" not in content
```
