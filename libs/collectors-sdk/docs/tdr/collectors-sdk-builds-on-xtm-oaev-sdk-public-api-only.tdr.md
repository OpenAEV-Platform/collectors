# collectors-sdk builds on the xtm-oaev-sdk public API only
---
scope: [collectors-sdk, dependencies, architecture]
status: draft
superseded_by:
supersedes:
Aliases:
Creation Date: 2026/10/14 16:25:31
Modification Date: 2026/10/14 16:25:31
---

## ELI5

collectors-sdk sits on top of xtm-oaev-sdk and only uses what xtm-oaev-sdk offers
publicly. It never touches pyoaev or anything meant only for injectors, and you hand it
the API client to use.

---

## **Why This Exists**
| *The forcing reality that demanded this TDR.*

> collectors-sdk is the collector runtime. xtm-oaev-sdk is the common SDK under it, and
> `pyoaev` is the API client sitting on top of both. And a collector has no business
> inheriting the injector runtime.

---

## **The TDR**
| **collectors-sdk must import xtm-oaev-sdk only through its package root and never import pyoaev, injectors-sdk, pika or requests; the API client is injected.**

> Specialises xtm-oaev-sdk TDR [sdks-never-import-pyoaev](https://github.com/OpenAEV-Platform/client-python/blob/main/libs/xtm-oaev-sdk/docs/tdr/sdks-never-import-pyoaev.tdr.md) (no `pyoaev`, injected client) and [import-from-the-package-root](https://github.com/OpenAEV-Platform/client-python/blob/main/libs/xtm-oaev-sdk/docs/tdr/import-from-the-package-root.tdr.md)
> (package-root imports) for collectors-sdk.

---

## **In Practice**
| *How this TDR manifests in the real world.*

- Runtime dependencies: `xtm-oaev-sdk`, pydantic, thefuzz.
- `CollectorDaemon(configuration=..., callback=..., api_client=api, collector_type=...)`; without `api_client`, the inherited `_create_default_api_client()` hook raises unless overridden (as `pyoaev`'s adapter does).
- `test/test_boundaries.py` fails on imports of `pyoaev`, `requests`, `pika` and on any `xtm_oaev_sdk._core` reference.

---

## **Alternatives Explored**
| *The paths we tried and why they failed.*

No alternative was explored for this decision.

---

## **Mutation Trigger**
| *When this TDR should be reconsidered.*

This TDR becomes questionable if:
- collectors and injectors converge on a shared runtime;
- xtm-oaev-sdk exposes a public sub-namespace that collectors-sdk should use instead of the root.

## **Hansei**
| *Scars, surprises, and extracted wisdom.*

What we learned while forging this TDR:
- No material lesson beyond the TDR itself.

---

## **Resources**
- [Boundaries test](../../test/test_boundaries.py)
- [xtm-oaev-sdk TDR sdks-never-import-pyoaev](https://github.com/OpenAEV-Platform/client-python/blob/main/libs/xtm-oaev-sdk/docs/tdr/sdks-never-import-pyoaev.tdr.md)
