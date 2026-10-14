# Technical Decision Records

The technical decision records that belong to collectors-sdk alone. The decisions all
three SDKs share live in the [xtm-oaev-sdk TDRs](https://github.com/OpenAEV-Platform/client-python/blob/main/libs/xtm-oaev-sdk/docs/tdr/TDR_ToC.md).

| TDR | Status | Rule |
|---|---|---|
| [collectors-sdk builds on the xtm-oaev-sdk public API only](collectors-sdk-builds-on-xtm-oaev-sdk-public-api-only.tdr.md) | draft | collectors-sdk must import xtm-oaev-sdk only through its package root and never import pyoaev, injectors-sdk, pika or requests; the API client is injected. |
| [Alert-matching hooks stay overridable](matching-hooks-stay-overridable.tdr.md) | draft | Expectation and OpenAEVDetectionHelper must pass their matching methods to the core as callables, so overriding or patching them keeps changing the match result. |
| [CollectorDaemon stays a BaseDaemon customised through its hooks](collector-daemon-is-a-base-daemon.tdr.md) | draft | CollectorDaemon must remain a subclass of xtm-oaev-sdk's BaseDaemon whose lifecycle is customised only through the inherited hooks, with registration and scheduling delegated to seam ports. |

## Adding a TDR

Create `<slug>.tdr.md`, the slug naming the rule. Same header as the other records,
`status: draft`, then a row in this table. A TDR moves to `accepted` once validated. The
day it stops governing, it goes `superseded` (with `superseded_by` / `supersedes` set on
both records) or `revoked`.
