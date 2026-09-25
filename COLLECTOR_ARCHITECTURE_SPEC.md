# OpenAEV Collectors — Architecture Analysis & SDK Spec

Status: draft for review · Scope: correlation collectors (SIEM/EDR) · Reference implementation: `elastic`

This document analyses the current collector architecture (elastic, splunk-es, crowdstrike + the
shared framework), lists what works and what blocks correctness & scale, and specifies the target
architecture for the planned SDK extraction.

---

## 1. Executive summary

Three collectors, three different maturity levels:

- **elastic** (reworked): the **strongest correlation** — deterministic per-inject attribution via the
  implant marker, process-ancestry drilldown, safe fallback, canonical alert deep-link. Still carries
  the **vendored, blocking framework**.
- **splunk-es**: editable SPL + implant marker, but **loose matching** (any single content signature,
  or IP+time) → can cross-attribute; no drilldown; trace is a re-runnable search, not a permalink.
- **crowdstrike**: **weakest correlation** — fuzzy process-name only, no host/agent/time binding →
  cross-contamination; **no pagination** (silently drops >~100 detections/poll). But it is the only one
  that consumes the framework as the **`pyoaev` package** instead of a vendored copy.

The dominant problems are **not** in the connector-specific code — they are in the **shared framework**
(`src/collector/*`), which is **copy-pasted into 8 repos and has silently diverged**, is **fully
sequential/blocking**, has **no concurrency, no prioritization, no idempotency**, and **aborts the whole
cycle on a single write failure**. This is the SDK-extraction target; `crowdstrike` (package-based) and
`template/` (refactored `collector/{engines,helpers,internals,protocols}`) show the intended direction.

**Bottom line:** correlation quality is a *solved problem* (elastic is the reference to standardise on);
**throughput, resilience and de-duplication of the framework are the real work.**

---

## 2. Comparative matrix

| Dimension | elastic (reworked) | splunk-es | crowdstrike |
|---|---|---|---|
| Shared framework | vendored `collector/*` (drifted copy) | vendored `collector/*` (drifted copy) | **`pyoaev` package** (shared) |
| Correlation key | implant marker (deterministic) | implant marker (regex) **or** IP+time | fuzzy process-name only |
| Determinism | **strict** — no cross-attribution | weak — `min_matches=1`, IP+time fallback | **very weak** — host-agnostic |
| Host / agent binding | host + process lineage + agent in marker | IP + host (query only) | **none** (`device.hostname` unused) |
| Per-inject time binding | yes (window + alert time) | yes (window) | **no** (one global 45-min window) |
| Process ancestry / drilldown | **yes** — entity_id climb + pid-seed + fallback | no (literal marker in `_raw`) | no (flattens 3 image names) |
| Editable query (catalog) | **yes** (Lucene `query_string`) | **yes** (SPL template) | **no** (hardcoded FQL) |
| Trace link | **canonical `kibana.alert.url`** (exact alert) | re-runnable SPL search (not a permalink) | Falcon deep-link (exact detection) |
| Fetch model | `_search` on alerts index, per expectation | oneshot SPL, per expectation × retry | poll alerts API (2-step) |
| Pagination | ES size cap (bounded) | `count=0` (unbounded pull) | **none — ~100 cap, drops surplus** |
| "Not Detected" decision | retry exhaustion (bounded, catalog) | retry exhaustion + 5-min fetch gate | **expiry (45 min)** |
| Retry | per-expectation blocking `sleep` | per-expectation blocking `sleep` | none (next cycle) |
| Concurrency | **none** | **none** | **none** |
| Rate-limit / backoff | no | no | **no** (429 → dropped cycle) |
| Registration | blocking, no backoff | blocking, no backoff | blocking, no backoff |
| Auth | API key / basic | **basic, `verify=False`** | OAuth2 (FalconPy) |

---

## 3. elastic collector — strengths & weaknesses

### 3.1 Strengths (keep / standardise on these)
- **Deterministic per-inject correlation.** An implant inject is credited only by its
  `oaev-implant-<inject>-agent-<agent>` marker; an endpoint alert without a matching marker is never
  credited on IP → no same-host cross-attribution. (`services/expectation_service.py`)
- **Process-ancestry drilldown** by `process.entity_id` (reuse-safe), so the marker is recovered even
  when the implant is not the alert's direct parent (`implant → cmd.exe → reg.exe`).
  (`services/client_api.py::_fetch_source_event_marker`)
- **pid-instance-by-time seeding** for PowerShell ScriptBlock alerts (pid but no entity_id) →
  resistant to pid reuse across concurrent injects.
- **Safe unique-host fallback** when telemetry is incomplete (missing intermediate process events):
  credits only when exactly one implant lineage is present → never guesses on an ambiguous host.
- **Retry-until-match** absorbs detection latency even when a concurrent inject's alerts are present.
- **Canonical trace link** — reads `kibana.alert.url` (the deep link Elastic itself emits; what a
  connector/SOAR uses), host-rebased onto `ELASTIC_KIBANA_URL` only when set. (`services/trace_service.py`)
- **Editable query + drilldown index**, catalog-configurable; deterministic algorithm kept in code.
- Traces submitted **before** verdict updates (evidence never lost). Good test coverage.

### 3.2 Weaknesses to tackle (connector-level, this collector)
- **Drilldown cost:** the ancestry climb is *N ES queries per alert per expectation*, and there is no
  cache of recovered markers **across expectations within a cycle** (only within a single enrich pass).
  Under load, correlation dominates cycle time.
- **Broad fetch:** the default query matches on IP/host, so it returns many candidate alerts (worse
  before noise-rule tuning); each is drilled. Needs candidate capping / marker-first narrowing.
- **Signature-vocabulary coupling:** unknown signature types (e.g. injector emitting `source_ipv4`
  instead of `source_ipv4_address`) are rejected by the pyoaev enum and can abort the fetch. Needs
  graceful skip of unknown types.
- **ECS field shape:** alerts mix flat dotted keys and nested objects; the code handles both but this
  is fragile and duplicated.
- Package **circular import** in `src/` (services ↔ collector) — bites tooling/tests.
- **Trace link correctness depends on Kibana `server.publicBaseUrl`** (documented; rebase escape hatch).

### 3.3 Inherited from the shared framework (see §4)
Blocking sequential batch, per-expectation blocking retry, no prioritisation, no idempotency,
whole-cycle abort on write failure — **do not fix these in the elastic PR; they are the SDK's job.**

---

## 4. Shared framework — the real problems (SDK extraction target)

The `src/collector/*` framework is the root cause of the throughput and resilience issues, and is
duplicated with drift.

1. **Copy-paste across 8 repos, silently drifted.** `expectation_manager.py` has **4 distinct versions**;
   the trace-before-verdict fix (avoids "Detected with 0 alerts") exists **only in elastic** — splunk-es,
   logrhythm, netwitness, qradar still have the reversed order and the bug. A fix must be hand-ported ×8.
2. **Fully sequential, single-threaded processing.** `process_expectations` → `handle_batch_expectations`
   is a plain `for` loop; each expectation runs `time.sleep(offset)` between retries. Cost ≈
   **N × (max_retry × offset)** serial. ~100 undetected injects × ~90s ≈ **~2.5 h per cycle**. The daemon
   scheduler runs to completion then waits `period` → **cycles cannot overlap**; a slow batch stalls
   everything.
3. **Up-front 5-minute blocking fetch gate** waiting for expectations carrying an `end_date` signature.
4. **FIFO, no prioritisation, no per-cycle budget.** Fresh injects **starve** behind a stale backlog —
   each stale expectation burns its full retry budget first.
5. **No idempotency / no persistence.** All state is in-memory and lost on restart; relies entirely on
   the **server** not re-serving graded expectations. A crash between "submit traces" and "update
   verdicts" leaves traces with no verdict; next cycle re-runs the full retry budget.
6. **Whole-cycle abort on write failure.** A failed bulk-verdict-update (after individual fallback) or a
   trace-submit failure **re-raises** and aborts the whole cycle — computed results are dropped.
7. **Transient SIEM outage → silent "Not Detected".** After retry exhaustion, a network error surfaces as
   an error/Not-Detected result rather than "unknown/retry later" → outages are graded as failures.
8. **Dual config representations.** A typed pydantic model (read by the service) **and** a stringly-typed
   `config_hints` dict (read by the daemon), hand-synced per collector; misnamed fields **silently fall
   back to defaults** instead of failing.
9. **Blocking registration at boot**, no backoff — if OpenAEV is unreachable at start, the collector
   never starts.

`crowdstrike` avoids #1 (uses the `pyoaev` package) but has its own gaps (no pagination, no backoff,
expiry-only Not-Detected). `template/` is a refactor (`collector/{engines,helpers,internals,protocols}`)
that looks like the intended SDK shape.

---

## 5. Target architecture (SDK spec)

Goal: **one shared, versioned SDK package** (extend `pyoaev`) that every connector depends on; connectors
implement only source-specific fetch + normalise + marker-recovery + trace-link. The SDK owns
scheduling, concurrency, matching, retry, resilience, config.

### 5.1 Processing model — non-blocking, concurrent, prioritised
- **Concurrency:** process expectations with a **bounded worker pool** (async or `concurrent.futures`),
  configurable degree. Correlation and per-expectation waits must not serialise.
- **Non-blocking retry (replaces per-expectation `sleep`):** do **one** fetch+match attempt per
  expectation per cycle. If no match, leave the expectation **pending** (do **not** block, do **not**
  mark Not Detected). Re-evaluate next cycle. This absorbs detection latency **without** per-expectation
  blocking and removes the N×budget stall.
- **Not-Detected by age, not by per-cycle exhaustion:** mark Not Detected only when an expectation's age
  exceeds a configurable threshold (aligned with OpenAEV expiry), not because a single cycle's retries
  ran out. Distinguish **"no match yet"** (stay pending) from **"failed"** (aged out).
- **Prioritisation:** newest / still-open expectations first; **per-cycle budget/cap** so a backlog never
  starves fresh injects or overruns the period.

### 5.2 Resilience & idempotency
- **Isolate write failures:** a failed verdict/trace write for one expectation (or the bulk call) must not
  abort the cycle; retry that item next cycle. Always submit **traces before verdicts** (the elastic fix),
  standardised in the SDK.
- **Distinguish transient outage from Not-Detected:** on SIEM/API errors, keep the expectation **pending**
  (retry later), never grade it as failed.
- **Idempotency / cursor:** keep a lightweight local watermark of already-graded expectations so a restart
  doesn't re-run full retry budgets; make verdict/trace writes idempotent (dedup by expectation+source).
- **Registration with backoff;** heartbeat already threaded (fine).

### 5.3 Fetch utilities (SDK-provided)
- **Pagination** (mandatory — fixes crowdstrike's silent cap), **rate-limit handling + exponential
  backoff + jitter**, bounded result sizes, and a shared HTTP session with TLS verification **on** by
  default.

### 5.4 Correlation contract (standardise on the elastic model)
- SDK defines the deterministic matching contract; each connector provides:
  1. `fetch(window, criteria)` → raw alerts/detections (paginated),
  2. `normalise(raw)` → typed alert with host, process context, ids, timestamp,
  3. `recover_marker(alert)` → the `oaev-implant-<inject>-agent-<agent>` marker (drilldown/lineage hook),
  4. `trace_link(alert)` → canonical deep-link to the **exact** alert/detection.
- **Deterministic rule (default):** implant inject ⇒ require the marker; endpoint alert without a matching
  marker ⇒ reject (no IP substitute); network/agentless ⇒ IP+time. Loose IP/host+time is opt-in only.
- Bring splunk (enforce marker, add lineage where possible) and crowdstrike (add host+agent+time binding,
  drilldown) up to this contract.

### 5.5 Config
- **Single typed config** representation; drop the parallel `config_hints` dict. **Fail on misconfig**
  (unknown/misnamed field) instead of silently defaulting. Keep catalog env-var piloting; the SDK reads
  the typed model directly.

---

## 6. Prioritised action plan

**P0 — unblock scale (SDK):**
- Extract the vendored `collector/*` into the shared package; migrate all 8 collectors off the copies
  (crowdstrike/template show the path). Kills drift (#4/§4-1) at the source.
- Non-blocking, concurrent processing + retry redesign (§5.1). This is the fix for the throughput wall
  (issue #605) that is currently making live grading impossible under load.
- Pagination + rate-limit/backoff in the SDK fetch layer (fixes crowdstrike data loss).

**P1 — correctness & resilience (SDK):**
- Write-failure isolation + traces-before-verdicts standardised (§5.2).
- Transient-outage vs Not-Detected distinction; Not-Detected by age.
- Idempotency/cursor + restart safety.
- Prioritisation / per-cycle budget (fresh-first).

**P2 — standardise the connector contract:**
- Adopt the deterministic marker-based correlation contract (§5.4) across connectors.
- Canonical exact-alert trace links everywhere (elastic/crowdstrike already do; fix splunk).
- Editable query where the source supports it (crowdstrike: expose the FQL filter).
- Single typed config (§5.5).

**P3 — per-connector hardening:**
- elastic: cache recovered markers across expectations per cycle; cap candidate alerts; skip unknown
  signature types gracefully; resolve the circular import.
- splunk: enforce the marker (`require_all`/marker-required), permalink traces, TLS verify, robust web-URL
  derivation.
- crowdstrike: bind host + agent/sensor + per-inject time; add drilldown; pagination.

### This PR (#597) scope
The elastic correlation rework (deterministic marker, drilldown, pid-reuse, fallback, canonical trace,
retry-until-match with a sane catalog-piloted budget) is the **reference implementation** and ships as-is.
Everything in §4 and §5 is **framework/SDK work, out of scope for this PR** (tracked separately, incl. the
throughput issue #605).

---

## 7. Appendix — key references

- elastic correlation: `elastic/src/services/expectation_service.py`, `client_api.py`
  (`_fetch_source_event_marker`, `_fetch_pid_seed`, `_fallback_unique_host_marker`,
  `_execute_query_with_retry`), `trace_service.py` (`_resolve_alert_url`).
- shared framework: `*/src/collector/expectation_manager.py` (4 drifted versions),
  `trace_manager.py`, `expectation_handler.py`, `signature_registry.py`.
- splunk: `splunk-es/src/services/expectation_service.py` (`_match`, `RegexSignatureEngine`
  `min_matches=1/require_all=False`), `client_api.py` (SPL template, blocking retry),
  `trace_service.py` (re-run-search link).
- crowdstrike: `crowdstrike/openaev_crowdstrike.py` (`_fetch_expectations`, `_match_expectations`,
  `_process`), `crowdstrike_api_handler.py` (no pagination), `query_strategy/alert.py`.
- SDK direction: `crowdstrike` (pyoaev package), `template/src/collector/{engines,helpers,internals,protocols}`.
