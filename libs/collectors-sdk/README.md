# collectors-sdk

OpenAEV Collectors SDK: the collector daemon runtime and detection helpers,
built on the shared [`xtm-oaev-sdk`](https://github.com/OpenAEV-Platform/client-python/tree/main/libs/xtm-oaev-sdk).

It never depends on the `pyoaev` client: the OpenAEV API client is injected.

```python
from pyoaev import OpenAEV
from xtm_oaev_sdk import Configuration
from collectors_sdk import CollectorDaemon

configuration = Configuration(config_hints={...})
api = OpenAEV(
    url=configuration.get("openaev_url"),
    token=configuration.get("openaev_token"),
    tenant_id=configuration.get("openaev_tenant_id"),
)
CollectorDaemon(
    configuration=configuration,
    callback=collect,
    api_client=api,
    collector_type="openaev_my_collector",
).start()
```

| Symbol | Former `pyoaev` path |
|---|---|
| `CollectorDaemon` | `pyoaev.daemons.CollectorDaemon` |
| `DEFAULT_PERIOD_SECONDS`, `DEFAULT_PLATFORM_TAG_COLOR` | `pyoaev.daemons.collector_daemon` |
| `OpenAEVDetectionHelper` | `pyoaev.helpers.OpenAEVDetectionHelper` |

## Development

```bash
pip install -e ../../../client-python/libs/xtm-oaev-sdk -e .
pytest test
```
