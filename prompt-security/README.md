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

The collector configuration is set either in `docker-compose.yml` / the environment (for Docker) or in `config.yml` (for manual deployment). Copy `prompt_security/config.yml.sample` to `config.yml`, or `.env.sample` to `.env`, and fill in the values.

### OpenAEV environment variables

| Parameter         | config.yml        | Docker environment variable | Mandatory | Description                                           |
|-------------------|-------------------|-----------------------------|-----------|-------------------------------------------------------|
| OpenAEV URL       | openaev.url       | `OPENAEV_URL`               | Yes       | The URL of the OpenAEV platform.                      |
| OpenAEV Token     | openaev.token     | `OPENAEV_TOKEN`             | Yes       | The default admin token set in the OpenAEV platform.  |
| OpenAEV Tenant ID | openaev.tenant_id | `OPENAEV_TENANT_ID`         | No        | Identifier of the tenant within the OpenAEV platform. |

### Base collector environment variables

| Parameter        | config.yml          | Docker environment variable | Default         | Mandatory | Description                                                                   |
|------------------|---------------------|-----------------------------|-----------------|-----------|-------------------------------------------------------------------------------|
| Collector ID     | collector.id        | `COLLECTOR_ID`              |                 | Yes       | A unique `UUIDv4` identifier for this collector instance.                     |
| Collector Name   | collector.name      | `COLLECTOR_NAME`            | Prompt Security | No        | Name of the collector.                                                        |
| Collector Period | collector.period    | `COLLECTOR_PERIOD`          | PT120S          | No        | The interval at which the collector runs (ISO 8601 duration, e.g. `PT120S`).  |
| Log Level        | collector.log_level | `COLLECTOR_LOG_LEVEL`       | error           | No        | Verbosity of the logs. One of `debug`, `info`, `warn`, `error`.               |
| Platform         | collector.platform  | `COLLECTOR_PLATFORM`        | LLM_FIREWALL    | No        | Type of security platform registered for this collector.                     |

### Prompt Security extra parameters

| Parameter      | config.yml            | Docker environment variable | Default | Mandatory | Description                                                               |
|----------------|-----------------------|-----------------------------|---------|-----------|---------------------------------------------------------------------------|
| Base URL       | collector.base_url    | `COLLECTOR_BASE_URL`        |         | Yes       | Prompt Security tenant base URL, e.g. `https://<tenant>.prompt.security`. |
| Application ID | collector.app_id      | `COLLECTOR_APP_ID`          |         | Yes       | Prompt Security application id / API key.                                 |
| Auth Header    | collector.auth_header | `COLLECTOR_AUTH_HEADER`     | APP-ID  | No        | HTTP header used to carry the application id / API key.                   |

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
