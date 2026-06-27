# OpenAEV Cisco AI Defense Collector

Validates that **Cisco AI Defense** (built on the acquired Robust Intelligence engine) detects or
blocks the AI adversarial injects launched by the `ai-redteam` injector, and fills the DETECTION /
PREVENTION expectations. Registers a `SecurityPlatform` of type `LLM_FIREWALL`.

## How it works (re-scan / replay model)

1. Polls agentless DETECTION/PREVENTION expectations (`GET /api/injects/expectations/ai/{collectorId}`).
2. Fetches each inject's attack content (`GET /api/injects/{injectId}` -> `inject_content.attack_prompt`).
3. Replays it through the Cisco AI Defense inspection API (`POST {base_url}/api/v1/inspect/prompt`).
4. Maps an unsafe verdict / classification -> DETECTION; a block action -> PREVENTION.

## Configuration

`base_url` (region/tenant inspection API), `api_key`, `auth_header` (default
`X-Cisco-AI-Defense-Api-Key`).

> Note: the Cisco AI Defense public API surface is still consolidating post-acquisition. The
> endpoint path and auth header are configurable; verify them against your tenant's API reference.

## Dependency

Requires the pyoaev AI support and the openaev AI domain endpoints.

## Run (dev)

```bash
poetry install --extras dev
poetry run python -m cisco_ai_defense.openaev_cisco_ai_defense
```

## Logo

The collector icon (`cisco_ai_defense/img/icon-cisco-ai-defense.png`) is provided at build/deploy
time. Use the authentic Cisco / Cisco AI Defense brand asset from
https://www.cisco.com/site/us/en/products/security/ai-defense/. Do not substitute a look-alike.
