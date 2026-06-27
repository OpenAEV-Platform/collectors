# OpenAEV Palo Alto Prisma AIRS Collector

Validates that **Palo Alto Prisma AIRS** (AI Runtime Security) detects or blocks the AI adversarial
injects launched by the `ai-redteam` injector, and fills the DETECTION / PREVENTION expectations.
Registers a `SecurityPlatform` of type `LLM_FIREWALL`.

## How it works (re-scan / replay model)

1. Polls agentless DETECTION/PREVENTION expectations (`GET /api/injects/expectations/ai/{collectorId}`).
2. Fetches each inject's attack content (`GET /api/injects/{injectId}` -> `inject_content.attack_prompt`).
3. Replays it through the Prisma AIRS Scan API
   (`POST {base_url}/v1/scan/sync/request`, header `x-pan-token`, `ai_profile.profile_name`).
4. Maps `category=malicious` / `prompt_detected` -> DETECTION; `action=block` -> PREVENTION.

## Configuration

`base_url` (region-specific Scan API), `api_key` (x-pan-token), `ai_profile` (security profile name).
See `prisma_airs/config.yml.sample` / `.env.sample`.

## Dependency

Requires the pyoaev AI support and the openaev AI domain endpoints.

## Run (dev)

```bash
poetry install --extras dev
poetry run python -m prisma_airs.openaev_prisma_airs
```

## Logo

The collector icon (`prisma_airs/img/icon-prisma-airs.png`) is provided at build/deploy time. Use
the authentic Palo Alto Networks / Prisma brand asset from
https://www.paloaltonetworks.com/company/brand. Do not substitute a look-alike.
