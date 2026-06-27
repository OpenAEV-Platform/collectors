# OpenAEV Cisco AI Defense Collector

Validates that **Cisco AI Defense** (built on the acquired Robust Intelligence engine) detects or
blocks the AI adversarial injects launched by the `ai-redteam` injector, and fills the DETECTION /
PREVENTION expectations. Registers a `SecurityPlatform` of type `LLM_FIREWALL`.

## How it works (re-scan / replay model)

1. Polls agentless DETECTION/PREVENTION expectations (`GET /api/injects/expectations/ai/{sourceId}`).
2. Fetches each inject's attack content (`GET /api/injects/{injectId}` -> `inject_content.attack_prompt`).
3. Replays it through the Cisco AI Defense inspection API (`POST {base_url}/api/v1/inspect/prompt`).
4. Maps an unsafe verdict / classification -> DETECTION; a block action -> PREVENTION.

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker)
or in `cisco_ai_defense/config.yml` (for manual deployment).

### OpenAEV environment variables

Below are the parameters you'll need to set for OpenAEV:

| Parameter         | config.yml        | Docker environment variable | Mandatory | Description                                           |
|-------------------|-------------------|-----------------------------|-----------|-------------------------------------------------------|
| OpenAEV URL       | openaev.url       | `OPENAEV_URL`               | Yes       | The URL of the OpenAEV platform.                      |
| OpenAEV Token     | openaev.token     | `OPENAEV_TOKEN`             | Yes       | The default admin token set in the OpenAEV platform.  |
| OpenAEV Tenant ID | openaev.tenant_id | `OPENAEV_TENANT_ID`         | No        | Identifier of the tenant within the OpenAEV platform. |

### Base collector environment variables

Below are the parameters you'll need to set for running the collector properly:

| Parameter        | config.yml              | Docker environment variable | Default                                         | Mandatory | Description                                                                             |
|------------------|-------------------------|-----------------------------|-------------------------------------------------|-----------|----------------------------------------------------------------------------------------|
| Collector ID     | collector.id            | `COLLECTOR_ID`              | openaev_cisco_ai_defense                        | Yes       | A unique identifier for this collector instance.                                       |
| Collector Name   | collector.name          | `COLLECTOR_NAME`            | Cisco AI Defense                                | No        | Name of the collector.                                                                  |
| Collector Period | collector.period        | `COLLECTOR_PERIOD`          | PT2M                                            | No        | Collection interval (ISO 8601 format, e.g. 'PT2M': 2 minutes).                          |
| Log Level        | collector.log_level     | `COLLECTOR_LOG_LEVEL`       | error                                           | No        | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.  |
| Platform         | collector.platform      | `COLLECTOR_PLATFORM`        | LLM_FIREWALL                                    | No        | Type of security platform this collector works for.                                     |
| Icon Filepath    | collector.icon_filepath | `COLLECTOR_ICON_FILEPATH`   | cisco_ai_defense/img/icon-cisco-ai-defense.png  | No        | Path to the collector icon file (see Logo below).                                       |

### Cisco AI Defense environment variables

Below are the parameters you'll need to set for the collector:

| Parameter   | config.yml            | Docker environment variable | Default                    | Mandatory | Description                                                        |
|-------------|-----------------------|-----------------------------|----------------------------|-----------|--------------------------------------------------------------------|
| Base URL    | collector.base_url    | `COLLECTOR_BASE_URL`        |                            | Yes       | Cisco AI Defense inspection API base URL (region/tenant specific). |
| API Key     | collector.api_key     | `COLLECTOR_API_KEY`         |                            | Yes       | Cisco AI Defense API key.                                          |
| Auth Header | collector.auth_header | `COLLECTOR_AUTH_HEADER`     | X-Cisco-AI-Defense-Api-Key | No        | HTTP header used to carry the API key.                             |

> Note: the Cisco AI Defense public API surface is still consolidating post-acquisition. The endpoint
> path and auth header are configurable; verify them against your tenant's API reference.

## Deployment

### Docker Deployment

Build a Docker image using the provided `Dockerfile`, then start the container with the provided
`docker-compose.yml`. Make sure to set the environment variables for your environment first.

```shell
docker compose up -d
# -d for detached
```

### Manual deployment

Install the production environment and run the collector:

```shell
poetry install --extras prod
poetry run python -m cisco_ai_defense.openaev_cisco_ai_defense
```

For development against a local `pyoaev` checkout (see
[these instructions](../README.md#simultaneous-development-on-pyoaev-and-a-collector)):

```shell
poetry install --extras dev
poetry run python -m cisco_ai_defense.openaev_cisco_ai_defense
```

## Dependency

Requires the pyoaev AI support (`inject_expectation.ai_expectations_for_source`) and the openaev AI
domain endpoints (`/api/injects/expectations/ai/{sourceId}`, `LLM_FIREWALL` platform).

## Logo

The collector icon (`cisco_ai_defense/img/icon-cisco-ai-defense.png`) is provided at build/deploy
time, as with the other connectors in this repository. Use the authentic Cisco / Cisco AI Defense
brand asset from https://www.cisco.com/site/us/en/products/security/ai-defense/. Do not substitute a
look-alike.
