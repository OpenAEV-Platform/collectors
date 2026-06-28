# OpenAEV HiddenLayer AIDR Collector

Validates that **HiddenLayer AI Runtime Security (AIDR)** detects or blocks the AI adversarial
injects launched by the `ai-redteam` injector, and fills the DETECTION / PREVENTION expectations.
Registers a `SecurityPlatform` of type `LLM_FIREWALL`.

## How it works (re-scan / replay model)

1. Polls agentless DETECTION/PREVENTION expectations (`GET /api/injects/expectations/ai/{collectorId}`).
2. Fetches each inject's attack content (`GET /api/injects/{injectId}` -> `inject_content.attack_prompt`).
3. Replays it through the HiddenLayer Interactions endpoint
   (`POST {base_url}/detection/v1/interactions`).
4. Maps the verdict to the expectations: any returned detection satisfies DETECTION, and a
   block action satisfies PREVENTION. Because prevention implies detection, a block also
   satisfies DETECTION (the blocked verdict is OR'ed into the detection result), so a blocked
   attack fills both the DETECTION and PREVENTION expectations.

## Authentication

- SaaS: OAuth2 client-credentials (`client_id` / `client_secret` -> bearer via `auth_url`).
- Self-hosted AIDR container: set `base_url` to the container and leave `client_id` / `client_secret` empty.

## Dependency

Requires the pyoaev AI support and the openaev AI domain endpoints.

## Run (dev)

```bash
poetry install --extras dev
poetry run python -m hiddenlayer.openaev_hiddenlayer
```

## Logo

The collector icon (`hiddenlayer/img/icon-hiddenlayer.png`) is provided at build/deploy time. Use the
authentic HiddenLayer brand asset from https://hiddenlayer.com/. Do not substitute a look-alike.
