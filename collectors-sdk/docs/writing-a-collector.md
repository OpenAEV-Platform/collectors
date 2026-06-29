# Writing a Collector from Scratch

This guide walks you through building a new collector using `collectors-sdk`. By the end you'll have a fully working collector that fetches data from a vendor API, matches it against OpenAEV expectations, and reports traces.

## Prerequisites

- Python 3.11+
- Access to `collectors-sdk` and `xtm-oaev-sdk` packages
- A vendor API to collect alerts/events from

## Project Structure

```
my_collector/
├── pyproject.toml
├── my_collector/
│   ├── __init__.py
│   ├── __main__.py          # Entry point
│   ├── collector.py          # BaseCollector wiring
│   ├── config.py             # Custom configuration (extends ConfigLoaderCustom)
│   ├── source/
│   │   ├── __init__.py
│   │   ├── signatures.py    # Supported SignatureTypes
│   │   ├── source_data.py   # SourceDataProtocol implementation
│   │   └── data_fetcher.py  # DataFetcherProtocol implementation
│   └── services/
│       ├── __init__.py
│       └── vendor_client.py  # HTTP client for the vendor API
└── tests/
    ├── __init__.py
    └── test_collector.py
```

## Step 1: Define Supported Signatures

Signatures declare which expectation types your collector can match. Import from `xtm_oaev_sdk`:

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

Choose only the types your vendor data actually contains.

## Step 2: Implement SourceDataProtocol

Each vendor alert/event becomes one `SourceData` object. The SDK engine uses this protocol:

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
        """Was the threat actively blocked?"""
        return self.alert.get("action") == "blocked"

    def is_detected(self) -> bool:
        """Was the threat detected but not blocked?"""
        return self.alert.get("action") == "detected"

    def __str__(self) -> str:
        return f"[{self.alert.get('id')}] {self.alert.get('title', '')[:60]}"
```

### Available OAEVData fields

| Field | Maps to |
|-------|---------|
| `parent_process_name` | `SIG_TYPE_PARENT_PROCESS_NAME` |
| `source_ipv4_address` | `SIG_TYPE_SOURCE_IPV4_ADDRESS` |
| `target_ipv4_address` | `SIG_TYPE_TARGET_IPV4_ADDRESS` |
| `target_hostname_address` | `SIG_TYPE_TARGET_HOSTNAME_ADDRESS` |
| *(see OAEVData class for full list)* | |

## Step 3: Implement DataFetcherProtocol

The data fetcher retrieves raw vendor data and returns a list of `SourceData`:

```python
# my_collector/source/data_fetcher.py
from collectors_sdk import CustomConfig
from my_collector.source.source_data import MySourceData
from my_collector.services.vendor_client import VendorClient


class MyDataFetcher:
    """Fetches alerts from vendor API. Implements DataFetcherProtocol."""

    def __init__(self, custom_config: CustomConfig) -> None:
        self.config = custom_config
        self.client = VendorClient(
            base_url=self.config.base_url,
            api_key=self.config.api_key.get_secret_value(),
        )

    def fetch_data(self) -> list[MySourceData]:
        """Fetch and normalize vendor alerts."""
        raw_alerts = self.client.get_alerts(
            time_window=self.config.time_window
        )
        return [MySourceData(alert=a) for a in raw_alerts]
```

The engine calls `fetch_data()` on each collection cycle.

## Step 4: Custom Configuration

Extend `ConfigLoaderCustom` to add vendor-specific settings:

```python
# my_collector/config.py
from datetime import timedelta
from collectors_sdk import ConfigLoaderCustom
from pydantic import Field, SecretStr


class MyConfig(ConfigLoaderCustom):
    """Vendor-specific configuration loaded from env vars.

    Env vars:
        CUSTOM_BASE_URL: Vendor API base URL
        CUSTOM_API_KEY: API authentication key (secret)
        CUSTOM_TIME_WINDOW: Lookback window (ISO 8601 duration)
    """

    base_url: str = Field(alias="CUSTOM_BASE_URL")
    api_key: SecretStr = Field(alias="CUSTOM_API_KEY")
    time_window: timedelta = Field(
        alias="CUSTOM_TIME_WINDOW",
        default=timedelta(hours=1),
    )
```

All fields use `CUSTOM_` prefix for environment variable names. The base class handles loading from `.env` files and environment.

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

And the entry point:

```python
# my_collector/__main__.py
from my_collector.collector import main

if __name__ == "__main__":
    main()
```

## Step 6: Detection Matching (Optional)

If your collector needs fuzzy matching between expectation signatures and alert data, use `SignatureMatcher`:

```python
from collectors_sdk import SignatureMatcher
from xtm_oaev_sdk import SignatureTypes

matcher = SignatureMatcher(
    relevant_signature_types=[
        SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME,
        SignatureTypes.SIG_TYPE_TARGET_HOSTNAME_ADDRESS,
    ]
)

# Exact + fuzzy match against alert fields
is_match = matcher.match(
    signatures=expectation.signatures,
    alert_data={"process_name": "evil.exe", "hostname": "server-01"},
)

# Direct fuzzy comparison
is_fuzzy_match = matcher.match_fuzzy(
    signature_value="evil.exe",
    alert_values=["evil.exe", "evil2.exe"],
    fuzzy_scoring=80,
)
```

## Step 7: Environment Configuration

The collector daemon expects these base environment variables (handled by `ConfigLoaderCollector` + `ConfigLoaderOAEV`):

| Variable | Description |
|----------|-------------|
| `OAEV_URL` | OpenAEV platform API URL |
| `OAEV_TOKEN` | Authentication token |
| `COLLECTOR_ID` | Collector identifier |
| `COLLECTOR_PERIOD` | Collection interval (seconds) |
| `COLLECTOR_LOG_LEVEL` | Logging level (DEBUG/INFO/WARN/ERROR) |

Your custom config adds vendor-specific vars with the `CUSTOM_` prefix.

## Step 8: Running

```bash
# Direct
python -m my_collector

# Docker
docker run -e OAEV_URL=... -e OAEV_TOKEN=... -e CUSTOM_BASE_URL=... my-collector
```

## SDK Components Reference

| Component | Import | Purpose |
|-----------|--------|---------|
| `BaseCollector` | `collectors_sdk` | Daemon lifecycle, scheduling, API wiring |
| `BasicCollectorEngine` | `collectors_sdk` | Default engine: fetch → match → trace |
| `Source` | `collectors_sdk` | Bundles data_fetcher + source_data + signatures |
| `ConfigLoaderCustom` | `collectors_sdk` | Base for custom Pydantic config |
| `SignatureMatcher` | `collectors_sdk` | Fuzzy/exact signature matching |
| `OAEVData` | `collectors_sdk` | Normalized detection data model |
| `TraceData` | `collectors_sdk` | Trace metadata model |
| `SignatureTypes` | `xtm_oaev_sdk` | Enum of all signature type identifiers |
| `Configuration` | `xtm_oaev_sdk` | Core daemon configuration model |

## Testing

Write unit tests that validate your protocol implementations:

```python
def test_source_data_protocol():
    sd = MySourceData(alert={"id": "1", "process": "test.exe", "action": "blocked"})
    assert sd.to_oaev_data().parent_process_name == "test.exe"
    assert sd.is_prevented() is True
    assert "1" in str(sd)

def test_no_deprecated_imports():
    """Ensure no legacy pyoaev paths are used."""
    import importlib, pkgutil
    import my_collector

    for _, name, _ in pkgutil.walk_packages(my_collector.__path__, "my_collector."):
        mod = importlib.import_module(name)
        if mod.__file__:
            content = open(mod.__file__).read()
            assert "pyoaev.configuration" not in content
            assert "pyoaev.exceptions" not in content
            assert "pyoaev.helpers" not in content
```

## Migration from Legacy

If migrating from a legacy collector using `pyoaev` directly:

| Legacy | SDK Replacement |
|--------|----------------|
| `from pyoaev.configuration import Configuration` | `from xtm_oaev_sdk import Configuration` |
| `from pyoaev.exceptions import OpenAEVError` | `from xtm_oaev_sdk import OpenAEVError` |
| `from pyoaev.helpers import OpenAEVDetectionHelper` | `from collectors_sdk import SignatureMatcher` |
| `from pyoaev.signatures.types import SignatureTypes` | `from xtm_oaev_sdk import SignatureTypes` |
| `from pyoaev.daemons import CollectorDaemon` | `from collectors_sdk import BaseCollector` |
| Custom daemon `__init__` + `_setup` | Just provide `Source` to `BaseCollector` |

The SDK handles daemon lifecycle, scheduling, and engine orchestration. You only write the vendor-specific logic.
