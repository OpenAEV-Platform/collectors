# CollectorDaemon stays a BaseDaemon customised through its hooks
---
scope: [collectors-sdk, daemons, compatibility]
status: draft
superseded_by:
supersedes:
Aliases:
Creation Date: 2026/10/14 16:25:31
Modification Date: 2026/10/14 16:25:31
---

## ELI5

`CollectorDaemon` is still a kind of `BaseDaemon` from xtm-oaev-sdk, with the same life
cycle. You customise it by overriding its usual hook methods. Registration and
scheduling happen in the core now, and that changes nothing in how you use or extend it.

---

## **Why This Exists**
| *The forcing reality that demanded this TDR.*

> Collectors subclass and patch `CollectorDaemon` (`CollectorDaemon._setup`, for one), and
> `pyoaev`'s legacy adapter extends it. Registration and scheduling moved to the core; the
> lifecycle had to stay the inherited `BaseDaemon` one regardless.

---

## **The TDR**
| **CollectorDaemon must remain a subclass of xtm-oaev-sdk's BaseDaemon whose lifecycle is customised only through the inherited hooks, with registration and scheduling delegated to seam ports.**

> Applies xtm-oaev-sdk TDR [adapters-keep-the-user-facing-shape](https://github.com/OpenAEV-Platform/client-python/blob/main/libs/xtm-oaev-sdk/docs/tdr/adapters-keep-the-user-facing-shape.tdr.md) to collectors-sdk.

---

## **In Practice**
| *How this TDR manifests in the real world.*

- `_setup` registers the collector (icon, security platform with description and tags) through `CollectorRegistrationPort` and starts xtm's `PingAlive`.
- `_start_loop` hands `self._try_callback` and `collector_period` to `CollectorSchedulePort`.
- `pyoaev.daemons.CollectorDaemon` overrides `_create_default_api_client()` to build the `OpenAEV` client.

---

## **Alternatives Explored**
| *The paths we tried and why they failed.*

No alternative was explored for this decision.

---

## **Mutation Trigger**
| *When this TDR should be reconsidered.*

This TDR becomes questionable if:
- collectors move to a different runtime model (e.g. event-driven instead of periodic);
- `BaseDaemon`'s hooks change in an xtm-oaev-sdk major version.

## **Hansei**
| *Scars, surprises, and extracted wisdom.*

What we learned while forging this TDR:
- No material lesson beyond the TDR itself.

---

## **Resources**
- [Daemons adapter](../../collectors_sdk/public/daemons.py)
- [Collector daemon tests](../../test/test_collector_daemon.py)
