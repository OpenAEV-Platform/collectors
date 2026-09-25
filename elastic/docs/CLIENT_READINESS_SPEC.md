# Elastic Security Collector — Client-Readiness Spec (consolidated)

Consolidates the product, staff-engineering and security reviews into one actionable spec.
**Hard constraint:** no change to the shared framework `src/collector/*` (SDK's job). Every code change
lives in `src/services/*` or `src/models/configs/*`. Framework/throughput items are documented as known
limitations, not reimplemented.

Ship gate: **all P0 done**; P1 gates GA; P2 ships as documented known limitations where not done.

---

## Key verified facts

- **pyoaev vocabulary is NOT released.** Neither the pinned `3.260904.0` nor the latest `3.260923.0`
  contains `source_ipv4`/`start_time`/… nor an enum `_missing_` fallback. The working `.venv` was
  hand-edited — **unreproducible; the real blocker**. A pin bump does not help → the fix is a **shipped
  compat shim** in the collector (fail-soft enum + alias-to-canonical), plus service-layer normalization.
- The manager grades **every returned `ExpectationResult`** (`is_valid` → Detected/Not Detected); it has
  no "pending" concept. The only framework-free way to leave an expectation ungraded is to **omit it from
  the returned list** → the server re-serves it next cycle. This lever backs Gaps 1 & 2.
- Transient SIEM outage today is affirmatively graded **"Not Detected"** (false negative).
- Empty `events_index` disables drilldown, but the matcher still **rejects** markerless endpoint alerts →
  implant injects false-negative in SIEM-only mode.

---

## P0 — blockers (no ship without these)

### DoD-1 · Signature vocabulary: never abort; agentless correlates
- **1a Compat shim** (`src/services/signature_compat.py`, imported by the services package): install a
  `SignatureTypes._missing_` that (i) returns the **canonical** member for known aliases
  (`source_ipv4→source_ipv4_address`, `…ipv6…`, `target_…`, `start_time→start_date`, `end_time→end_date`),
  and (ii) for any other unknown value registers a **pass-through** member so pydantic never raises →
  **the whole-tenant fetch can never be aborted by one signature**. Idempotent; a no-op once pyoaev ships
  native support. Removes the `.venv` hand-edit dependency.
- **1b Normalization** in `expectation_service._extract_signatures`: fold alias spellings onto canonical
  types (belt-and-suspenders even if the shim is bypassed).
- **1c Graceful skip**: if after normalization an expectation has **no usable signature**, raise
  `ElasticUngradableExpectation` → **omit from results (pending)**, WARN; never grade "Not Detected".
- **AC:** one bogus/unknown signature does not abort the batch (others still process); an agentless
  NetExec inject (`source_ipv4`+`target_ipv4`+`start_time`/`end_time`, no marker) correlates via IP+time
  and is graded Detected when a matching alert exists; no dependency on any `site-packages` edit.

### DoD-2 · Transient outage must NOT be graded "Not Detected"
- In `handle_batch_expectations`, add an **outage branch before** the generic `except ElasticServiceError`
  for `(ElasticAPIError, ElasticNetworkError, ElasticAuthenticationError)` → log + `continue` **without
  appending a result** (leave pending). Keep `NoAlerts`/`NoMatching` → "Not Detected" (query succeeded).
- **AC:** mocked connection/API/auth error across the retry budget → returned list omits that expectation
  (no verdict written); a real "queried, nothing matched" still yields "Not Detected".

### DoD-3 · Deployment prerequisites & least-privilege (docs + preflight)
- README: min Elastic/Kibana version; **copy-paste least-privilege API-key role** granting
  `read`+`view_index_metadata` on **both** the alerts index and the events index patterns, **no** cluster
  / write / Kibana privileges; API-key-first guidance; which detection rules/integrations must be enabled.
- **Fail-loud on unreadable index (implemented in the query path, not a boot preflight).** A dedicated
  boot-time self-check would require wiring into the shared collector bootstrap (`src/collector/*`), which is
  off-limits (Ferdinand's SDK owns it). Equivalent protection is achieved where the query runs: the alerts
  query already raises actionable `401/403/404` errors, and the events-index drilldown now does the same
  (`client_api._events_search`) instead of swallowing them. A denied/nonexistent index therefore surfaces a
  named error **and leaves the affected expectations pending** (via `LEAVE_PENDING_ERRORS`) rather than
  grading a silent false "Not Detected" — the operator fixes the privilege or unsets `ELASTIC_EVENTS_INDEX`.
- **AC:** a fresh operator can stand it up from docs; a missing events-index privilege yields a named
  error and pending expectations, not silent under-correlation. ✅ (see `TestEventsIndexDrilldownAuthz`).

### DoD-3b · SIEM-only (no process telemetry) behavior defined
- When `events_index` is **empty** (SIEM-only, explicitly configured), the deterministic **endpoint-reject is
  disabled** and implant expectations degrade to **IP+time** (documented lower confidence), with a WARNING.
  When `events_index` is set but **unreadable** (privilege/404), the drilldown fails loud and the expectation
  is left **pending** (see DoD-3) rather than silently degraded — the two cases are deliberately distinct.
  Never a blanket silent "Not Detected".
- **AC:** with `ELASTIC_EVENTS_INDEX=""`, an implant inject with a matching host-IP alert is graded
  Detected (IP+time); default (events index set) keeps strict determinism.

---

## P1 — gate GA

- **DoD-4 · Latency tuning docs.** Budget = `max_retry × offset` (default 3×30s ≈ 90s), blocking &
  per-expectation; document the trade-off + a tuning table; note `time_window` (not offset widening)
  governs coverage.
- **DoD-5 · Trace-link topologies.** Document Kibana `server.publicBaseUrl` requirement + `ELASTIC_KIBANA_URL`
  override (reverse-proxy example). (Code already: verbatim / rebase / port-rewrite.)
- **SEC-1 · Redact exceptions.** Run `redact_userinfo` over any requests-exception text before
  logging/re-raising in `_execute_query`/`_execute_query_with_retry` (prevents `user:pass@host` leak).
- **SEC-2 · TLS warning.** Emit a prominent WARNING at client init when `verify_ssl=false`; reframe README
  (trust-the-CA is the recommended path; add optional `ELASTIC_CA_CERT`). Default stays `true`.
- **SEC-3 · Cap drilldown fan-out.** Cap candidate alerts drilled per expectation (`MAX_DRILLDOWN_ALERTS`)
  and promote the marker cache to **per-cycle** (`self._marker_cache`, reset at the top of
  `handle_batch_expectations`) so retries/expectations don't re-drill the same `(host,seed)`.
- **SEC-4 · Supply chain.** Commit a lockfile + `pip-audit` in CI; add a non-root `USER` to
  `Dockerfile_ubi9`.

---

## P2 — hardening (do the cheap ones; else document)

- **SEC-5 · Validate `kibana.alert.url`** before storing as a trace link: scheme ∈ {http,https}; when
  `ELASTIC_KIBANA_URL` set, host must match; else fall back to the collector-built `kibana.alert.uuid`
  link. (Blocks a rogue-alert `javascript:`/phishing link reaching a SOC analyst.)
- **SEC-6 · Lucene escaping.** Escape backslash (and reserved metachars) in `_lucene_values`; test
  adversarial values.
- **SEC-7 · Reduce debug exposure.** Stop logging whole `data_item`/`matching_data`; log ids/counts.
  Document that debug logs record hostnames/IPs/links.
- **ENG-4c · Circular import.** `TYPE_CHECKING` + function-local imports of `collector.models` in the two
  service modules (no framework edit).
- **ENG-4d · ECS helper.** Extract `src/services/utils/ecs.py` (`ecs_first/ecs_all/ecs_get`) and refactor
  `models.py` + `client_api._event_entity_ids/_collect_process_text` onto it.
- Pin base-image digests; reconcile the Python version story (README/pyproject/Dockerfiles); add `.env` to
  `.gitignore`.

---

## Out-of-scope (SDK — documented known limitations)

Blocking single-threaded sequential batch + per-expectation `sleep` retry (throughput wall, #605);
non-blocking/concurrent processing, prioritization, per-cycle budget, fresh-before-stale;
Not-Detected-by-age; whole-cycle abort on total write failure; idempotency/cursor/restart safety;
extraction of `collector/*` into shared `pyoaev`; pagination/backoff primitives; fail-soft signature
parsing at the model layer; single typed config (drop `config_hints`).

---

## File map

- `src/services/signature_compat.py` (new) — DoD-1a.
- `src/services/expectation_service.py` — DoD-1b/1c, DoD-2, DoD-3b, SEC-3 cache reset.
- `src/services/exception.py` — `ElasticUngradableExpectation`.
- `src/services/client_api.py` — SEC-1, SEC-3 (entity_id-only cache + cap), TLS(SEC-2) at `_create_session`, DoD-3 fail-loud drilldown (`_events_search`).
- `src/services/trace_service.py` — SEC-5.
- `src/services/models.py` + `src/services/utils/ecs.py` — ENG-4d.
- `src/models/configs/elastic_configs.py` — SEC-2/DoD-4 docs, `ELASTIC_CA_CERT`.
- `README.md` — DoD-3/3b/4/5, SEC docs, known limitations.
- `Dockerfile_ubi9`, `pyproject.toml`/lockfile, CI — SEC-4.
