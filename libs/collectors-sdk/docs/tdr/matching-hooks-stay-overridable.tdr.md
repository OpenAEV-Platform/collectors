# Alert-matching hooks stay overridable
---
scope: [collectors-sdk, detection, expectations, compatibility]
status: draft
superseded_by:
supersedes:
Aliases:
Creation Date: 2026/10/14 16:25:31
Modification Date: 2026/10/14 16:25:31
---

## ELI5

The logic that compares security alerts with what we expected moved into the core. But
the core still calls the matching methods (`match_fuzzy`, `match_simple`…), so override
one or fake it, and the match result follows.

---

## **Why This Exists**
| *The forcing reality that demanded this TDR.*

> Matching logic moved into the core, but `Expectation` and `OpenAEVDetectionHelper`
> dispatched through their own methods. Let the core reimplement those calls and it
> silently walks past every subclass override and test patch.

---

## **The TDR**
| **Expectation and OpenAEVDetectionHelper must pass their matching methods to the core as callables, so overriding or patching them keeps changing the match result.**

> Applies xtm-oaev-sdk TDR [pass-bound-callables-to-keep-dispatch](https://github.com/OpenAEV-Platform/client-python/blob/main/libs/xtm-oaev-sdk/docs/tdr/pass-bound-callables-to-keep-dispatch.tdr.md) to collectors-sdk.

---

## **In Practice**
| *How this TDR manifests in the real world.*

- `Expectation.match_alert` passes `self.match_fuzzy` and `self.match_simple`.
- `OpenAEVDetectionHelper` passes `self.match_alert_element_fuzzy` and `self._decode_value`.

---

## **Alternatives Explored**
| *The paths we tried and why they failed.*

No alternative was explored for this decision.

---

## **Mutation Trigger**
| *When this TDR should be reconsidered.*

This TDR becomes questionable if:
- these methods are formally deprecated as extension points;
- matching becomes a pluggable strategy object.

## **Hansei**
| *Scars, surprises, and extracted wisdom.*

What we learned while forging this TDR:
- No material lesson beyond the TDR itself.

---

## **Resources**
- [Detection adapter](../../collectors_sdk/public/detection.py)
- [Expectations adapter](../../collectors_sdk/public/expectations.py)
