# OpenAEV Prompt Security Collector

Validates that **Prompt Security** (SentinelOne) detects or blocks the AI adversarial injects
launched by the `ai-redteam` injector, and fills the DETECTION / PREVENTION expectations. Registers a
`SecurityPlatform` of type `LLM_FIREWALL`.

## How it works (re-scan / replay model)

1. Polls agentless DETECTION/PREVENTION expectations (`GET /api/injects/expectations/ai/{collectorId}`).
2. Fetches each inject's attack content (`GET /api/injects/{injectId}` -> `inject_content.attack_prompt`).
3. Replays it through the Prompt Security protect API (`POST {base_url}/api/protect`).
4. Maps any violation -> DETECTION; a block action -> PREVENTION.

## Configuration

`base_url` (tenant URL, e.g. `https://<tenant>.prompt.security`), `app_id` (application id / API
key), `auth_header` (header carrying the id; default `APP-ID`).

> Note: Prompt Security was acquired by SentinelOne (2025). The protect endpoint and auth header are
> configurable; verify them against your tenant / the SentinelOne integration of Prompt Security.

## Dependency

Requires the pyoaev AI support and the openaev AI domain endpoints.

## Run (dev)

```bash
poetry install --extras dev
poetry run python -m prompt_security.openaev_prompt_security
```

## Logo

The collector icon (`prompt_security/img/icon-prompt-security.png`) is provided at build/deploy time.
Use the authentic Prompt Security / SentinelOne brand asset from https://www.prompt.security/. Do not
substitute a look-alike.
