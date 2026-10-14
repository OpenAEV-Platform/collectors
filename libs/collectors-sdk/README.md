# collectors-sdk

The **collector runtime** of the OpenAEV connector ecosystem. Every collector needs
the same moves: register on the platform, run on a schedule, pull its expectations,
and match them against the alerts of the security tool it watches. This is where
those moves live.

It stands on [`xtm-oaev-sdk`](https://github.com/OpenAEV-Platform/client-python/tree/main/libs/xtm-oaev-sdk)
(configuration, signatures, daemon runtime, errors) and never depends on `pyoaev`.
The OpenAEV API client gets **injected** (`xtm_oaev_sdk.BaseClient`); `pyoaev.OpenAEV`
is one implementation of it, nothing more.

```
xtm-oaev-sdk  ←  collectors-sdk  ←  your collector
                                    (+ pyoaev for the API client)
```

## What's inside

| Capability | Public API | Former `pyoaev` path |
|---|---|---|
| daemons | `CollectorDaemon`, `DEFAULT_PERIOD_SECONDS`, `DEFAULT_PLATFORM_TAG_COLOR` | `pyoaev.daemons` |
| expectations | `Expectation`, `DetectionExpectation`, `PreventionExpectation`, `ExpectationSignature`, `ExpectationTypeEnum` | `pyoaev.apis.inject_expectation.model` |
| detection | `OpenAEVDetectionHelper` | `pyoaev.helpers` |

## Quickstart

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


def collect(collector: CollectorDaemon) -> None:
    for expectation in collector.api.inject_expectation.expectations_models_for_source(
        source_id=collector.get_id()
    ):
        ...  # expectation.match_alert(...), then expectation.update(...)


CollectorDaemon(
    configuration=configuration,
    callback=collect,
    api_client=api,
    collector_type="openaev_my_collector",
).start()
```

`CollectorDaemon` registers the collector (icon, security platform with its
description and tags), lights up the heartbeat, then fires the callback every
`collector_period` seconds.

## Architecture

Same layering as `xtm-oaev-sdk`, cut capability by capability:

```
public/<capability>.py   adapters: what users import; delegate to _core through the seam ports
seam/<capability>/       contracts: data models, constants, Protocol ports (closed, versioned)
_core/<capability>/      implementations of the seam ports
```

The seam imports nothing from `_core` or `public`. The core never touches `public`.
And `public` never hands a core object to users. The full rationale lives in
`xtm-oaev-sdk`'s `docs/seam_strategy.md`.

## Migrating from pyoaev

The former `pyoaev` paths still work, and each one fires a `DeprecationWarning`.
During the deprecation window `pyoaev` depends on this SDK and serves the very same
objects (`pyoaev.daemons.CollectorDaemon` still builds the `OpenAEV` client on its
own). New code should depend on `collectors-sdk` and import from `collectors_sdk`.

## Development

```bash
pip install -e ../../../client-python/libs/xtm-oaev-sdk -e .
python -m pytest test
```

Runtime dependencies: `xtm-oaev-sdk`, pydantic, thefuzz.
