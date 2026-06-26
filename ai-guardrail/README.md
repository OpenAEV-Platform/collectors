# OpenAEV AI Guardrail Collector

Closes the AI adversarial validation loop: it validates whether an **AI defense** (LLM firewall /
guardrail / AI gateway - e.g. Lakera Guard, NVIDIA NeMo Guardrails, Protect AI LLM Guard) **detected**
or **prevented** the attacks launched by the `ai-redteam` injector, and fills the corresponding
DETECTION / PREVENTION expectations.

It registers a `SecurityPlatform` of type **LLM_FIREWALL** (or `AI_GATEWAY`).

## How it works

```
ai-redteam injector --(request + X-OAEV-Inject-Marker)--> AI gateway / firewall --> model
                                                              |
                                                         logs decision (keyed by marker)
                                                              |
ai-guardrail collector --(poll AI expectations)--> derive marker --> query decisions --> fill DETECTION/PREVENTION
```

1. Polls agentless DETECTION/PREVENTION expectations for this collector
   (`GET /api/injects/expectations/ai/{collectorId}`).
2. Derives the per-inject canary marker (`pyoaev.signatures.ai_marker.build_marker`, identical to the
   injector) - or reads an `ai_request_marker` signature if present.
3. Queries the guardrail events API for that marker (`events_url`).
4. Fills DETECTION (`flagged`) and PREVENTION (`blocked`) and posts expectation traces.

## Providers

- `generic` - any AI gateway/firewall exposing decisions queryable by the marker (recommended).
- `lakera` - Lakera Guard (Check Point) field mapping.
- `nemo` - NVIDIA NeMo Guardrails field mapping (input/output rail actions).

The gateway/firewall in front of the model must log each request's `X-OAEV-Inject-Marker` and expose
those decisions at `events_url` (filtered by `marker_param`). This is the portable, vendor-neutral
correlation contract.

## Configuration

See `ai_guardrail/config.yml.sample` and `.env.sample`. Key settings: `provider`, `events_url`,
`api_key`, `lookback_minutes`, `marker_param`, `flagged_field`, `blocked_field`, and `platform`
(`LLM_FIREWALL` or `AI_GATEWAY`).

## Run (dev)

```bash
poetry install --extras dev
poetry run python -m ai_guardrail.openaev_ai_guardrail
```

> As with the other connectors in this repository, the icon
> (`ai_guardrail/img/icon-ai-guardrail.png`) is provided at build/deploy time.
