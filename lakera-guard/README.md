# OpenAEV Lakera Guard Collector

Validates that **Lakera Guard** (Check Point AI Security) detects or prevents the AI adversarial
injects launched by the `ai-redteam` injector, and fills the corresponding DETECTION / PREVENTION
expectations. Registers a `SecurityPlatform` of type `LLM_FIREWALL`.

## How it works (re-scan / replay model)

1. Polls agentless DETECTION/PREVENTION expectations for this collector
   (`GET /api/injects/expectations/ai/{collectorId}`).
2. For each expectation, fetches the inject's attack content (`GET /api/injects/{injectId}` ->
   `inject_content.attack_prompt`) and substitutes the per-inject marker.
3. Replays the attack content through the Lakera screening API
   (`POST {base_url}/guard`, `Authorization: Bearer <api_key>`, optional `project_id` policy).
4. Maps `flagged` -> DETECTION; under a blocking policy a flagged prompt -> PREVENTION. Fills the
   expectations and posts traces.

This validates the efficacy of the Lakera policy against each simulated attack without requiring
Lakera to be inline in the test path.

## Configuration

See `lakera_guard/config.yml.sample` / `.env.sample`: `base_url`, `api_key`, optional `project_id`,
`platform` (`LLM_FIREWALL` or `AI_GATEWAY`).

## Dependency

Requires the pyoaev AI support (`inject_expectation.ai_expectations_for_source`) and the openaev AI
domain (`/api/injects/expectations/ai/{sourceId}`, `LLM_FIREWALL` platform).

## Run (dev)

```bash
poetry install --extras dev
poetry run python -m lakera_guard.openaev_lakera_guard
```

## Logo

The collector icon (`lakera_guard/img/icon-lakera-guard.png`) is provided at build/deploy time, as
with the other connectors in this repository. Use the authentic Lakera / Check Point AI Security
brand asset from https://www.lakera.ai/ (or Check Point brand resources). Do not substitute a
look-alike.
