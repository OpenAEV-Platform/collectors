# The collector runtime builds the expectation models, not the client
---
scope: [collectors-sdk, pyoaev, expectations, dependencies]
status: draft
superseded_by:
supersedes:
Aliases:
Creation Date: 2026/10/14 23:09:17
Modification Date: 2026/10/14 23:09:17
---

## ELI5

The OpenAEV client fetches the expectations a collector has to check, as plain data.
That's its job, and it stops there. Turning the data into objects that match alerts and
report results is the collector toolkit's job, so collectors-sdk does it. The old client
method still works, but all it does now is pass the job on, with a warning.

---

## **Why This Exists**
| *The forcing reality that demanded this TDR.*

> `InjectExpectationManager.expectations_models_for_source` in `pyoaev` built the
> `collectors_sdk` `DetectionExpectation` / `PreventionExpectation` models itself, and
> imported `collectors_sdk` at module level. Outside the deprecation shims, it was the one
> piece of client code wired to a connector runtime SDK. `pyoaev` could never drop
> `collectors-sdk`, and the client and collectors-sdk each knew about the other.

---

## **The TDR**
| **The OpenAEV client must return platform data only; collectors-sdk builds the expectation models from it, through `expectations_models_for_source(api, source_id)`.**

> `api` is the client's inject expectation manager, typed by `ExpectationApiProtocol`. It
> brings `expectations_assets_for_source`, and `update`, the call the models use to report
> their outcome.

---

## **In Practice**
| *How this TDR manifests in the real world.*

```python
from collectors_sdk import expectations_models_for_source

for expectation in expectations_models_for_source(api.inject_expectation, source_id=source_id):
    ...  # expectation.match_alert(...), then expectation.update(...)
```

- `ExpectationLoadingPort` / `ExpectationLoader` own the type dispatch. The public adapter
  hands the `DetectionExpectation` / `PreventionExpectation` classes to the core.
- `InjectExpectationManager.expectations_models_for_source` warns, then delegates to
  `collectors_sdk.expectations_models_for_source`. Its result matches the released
  implementation exactly, HTTP call included.
- The three model names that `pyoaev.apis`, `pyoaev.apis.inject_expectation` and its module
  used to expose now come from deprecation shims.

---

## **Alternatives Explored**
| *The paths we tried and why they failed.*

| Approach | Result | Lesson |
| --- | --- | --- |
| Keep the client building the models, and document a permanent `pyoaev` → `collectors-sdk` dependency | Every client install, injectors included, keeps dragging collectors-sdk along, and the shim removal plan could never drop it | A client has no business owning a connector runtime's domain objects |
| Make the client return the seam data (`ExpectationData`) instead of the models | Still a dependency on collectors-sdk, plus a change to what the method returns | Moving a dependency is not removing it |

---

## **Mutation Trigger**
| *When this TDR should be reconsidered.*

This TDR becomes questionable if:
- the platform API returns typed expectation payloads that the client itself must model;
- collectors-sdk and the client are merged into one package;
- the deprecated client method is removed: the TDR then only governs collectors-sdk.

## **Hansei**
| *Scars, surprises, and extracted wisdom.*

What we learned while forging this TDR:
- The legacy surface includes what a module merely imports. The three model names reached
  `pyoaev.apis` through two star-imports, and the legacy-surface guard caught them
  vanishing.
- `from pyoaev.apis.inject_expectation import *` (and the same on its module) no longer
  exports the three names. Giving those modules an `__all__` would make `import pyoaev.apis`
  warn, which is worse. No connector star-imports from `pyoaev`.

---

## **Resources**
- [Expectations adapter](../../collectors_sdk/public/expectations.py)
- [Expectation loader](../../collectors_sdk/_core/expectations/loader.py)
- [Migration guide](https://github.com/OpenAEV-Platform/client-python/blob/main/libs/xtm-oaev-sdk/docs/migration_guide.md)
