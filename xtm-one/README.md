# XTM One Collector

The XTM One collector imports [XTM One](https://filigran.io/solutions/xtm-one/) agents into OpenAEV as AI targets so
they can be exercised by adversarial AI injects. On each run it reads the XTM One agents catalog (optionally scoped to a
set of tags) and upserts one OpenAEV AI target per agent, wired to XTM One's OpenAI-compatible proxy. It can optionally
also mirror the bare LLM models exposed by the same proxy. This is an importer: it does not register a security platform
and does not validate detection or prevention expectations.

## Table of Contents

- [XTM One Collector](#xtm-one-collector)
  - [Table of Contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Requirements](#requirements)
  - [Configuration variables](#configuration-variables)
    - [OpenAEV environment variables](#openaev-environment-variables)
    - [Base collector environment variables](#base-collector-environment-variables)
    - [XTM One collector environment variables](#xtm-one-collector-environment-variables)
  - [Deployment](#deployment)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment](#manual-deployment)
  - [Usage](#usage)
  - [Behavior](#behavior)
  - [Data source](#data-source)
  - [Debugging](#debugging)
  - [Additional information](#additional-information)

## Introduction

XTM One runs autonomous AI agents and exposes them (plus the underlying LLM models) through an OpenAI-compatible proxy.
OpenAEV (Breach and Attack Simulation) can exercise those AI systems with adversarial injects, but it first needs an AI
target describing how to reach each one. This collector keeps the OpenAEV AI target catalog in sync with XTM One: every
run it lists the agents, filters them by tag (when configured), and creates or updates one AI target per agent pointing
at `{XTM_ONE_URL}/v1` with model `agent:<slug>`. When bare-model collection is enabled it additionally creates one AI
target per bare LLM model (e.g. `gpt-4o`, `claude-3-5-sonnet`), reusing the same proxy endpoint with the raw model id.

Targets are matched on a stable external reference (`xtm-one:agent:<slug>` / `xtm-one:model:<id>`), so the collector is
idempotent and updates existing targets in place instead of creating duplicates.

The XTM One API key (`collector.xtm_one_token`) is written onto each seeded AI target (`ai_target_token`), so the AI red
team injector authenticates to XTM One directly using the credential carried by the target.

## Requirements

- A running OpenAEV platform, reachable from where the collector runs, with an administrator API token
- A running XTM One platform, reachable from where the collector runs
- An XTM One API key (`fcp-...`) with access to the agents you want to import (create one in XTM One under Profile > API
  Keys)
- For a manual (non-Docker) deployment: Python >= 3.11 and [Poetry](https://python-poetry.org/) >= 2.1

## Configuration variables

The collector is configured either through environment variables (recommended, read from `docker-compose.yml` / the
`.env` file for a Docker deployment) or through a `config.yml` file (for a manual deployment). Copy the provided
`.env.sample` / `config.yml.sample` and fill in the values flagged with `ChangeMe`.

### OpenAEV environment variables

| Parameter         | config.yml          | Docker environment variable | Mandatory | Description                                                                        |
|-------------------|---------------------|-----------------------------|-----------|------------------------------------------------------------------------------------|
| OpenAEV URL       | `openaev.url`       | `OPENAEV_URL`               | Yes       | The URL of the OpenAEV platform. Must be reachable from where the collector runs.  |
| OpenAEV Token     | `openaev.token`     | `OPENAEV_TOKEN`             | Yes       | The administrator token of the OpenAEV platform.                                   |
| OpenAEV Tenant ID | `openaev.tenant_id` | `OPENAEV_TENANT_ID`         | No        | Tenant identifier for multi-tenant deployments. When set, it must be a valid UUID. |

### Base collector environment variables

| Parameter        | config.yml            | Docker environment variable | Default | Mandatory | Description                                                              |
|------------------|-----------------------|-----------------------------|---------|-----------|--------------------------------------------------------------------------|
| Collector ID     | `collector.id`        | `COLLECTOR_ID`              | /       | Yes       | A unique `UUIDv4` identifier for this collector instance.                |
| Collector Name   | `collector.name`      | `COLLECTOR_NAME`            | XTM One | No        | The name of the collector as shown in OpenAEV.                          |
| Collector Period | `collector.period`    | `COLLECTOR_PERIOD`          | PT1H    | No        | Interval between two runs, as an ISO 8601 duration (e.g. `PT1H` = 1h).   |
| Log Level        | `collector.log_level` | `COLLECTOR_LOG_LEVEL`       | error   | No        | Verbosity of the logs. One of `debug`, `info`, `warn`, `error`.         |

### XTM One collector environment variables

| Parameter          | config.yml                        | Docker environment variable          | Default         | Mandatory | Description                                                                                                                                                        |
|--------------------|-----------------------------------|--------------------------------------|-----------------|-----------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| XTM One URL        | `collector.xtm_one_url`           | `COLLECTOR_XTM_ONE_URL`              | /               | Yes       | Base URL of the XTM One platform (e.g. `https://xtm-one.example.com`). The collector talks to `/api/v1/agents` and `/v1/models`.                                    |
| XTM One Token      | `collector.xtm_one_token`         | `COLLECTOR_XTM_ONE_TOKEN`            | /               | Yes       | XTM One API key (`fcp-...`) used to read the agents and models catalog and stored on each seeded AI target so the injector can authenticate to XTM One directly.    |
| Include bare models | `collector.include_bare_models`  | `COLLECTOR_INCLUDE_BARE_MODELS`      | `false`         | No        | When `true`, also create an AI target for each bare LLM model exposed by the proxy (in addition to the agents).                                                     |
| Agent tags         | `collector.agent_tags`            | `COLLECTOR_AGENT_TAGS`               | (empty)         | No        | Comma-separated list of XTM One agent tags to scope on. Empty means all agents are collected. Tag matching is case-insensitive.                                     |

## Deployment

### Docker Deployment

Build the Docker image (or use the published `openaev/collector-xtm-one` image):

```shell
docker build . -t openaev/collector-xtm-one:latest
```

Create a `.env` file from `.env.sample` and fill in your values, then start the collector with the provided
`docker-compose.yml` (which reads those variables):

```shell
docker compose up -d
```

### Manual Deployment

Create a `config.yml` file from `config.yml.sample` and fill in your values, then install and run the collector:

```shell
poetry install --extras prod
poetry run python -m xtm_one.openaev_xtm_one
```

> For local development against a checkout of [client-python](https://github.com/OpenAEV-Platform/client-python)
> (cloned next to this repository), use `poetry install --extras dev` instead.

## Usage

Once started, the collector registers itself in OpenAEV and then runs automatically every `COLLECTOR_PERIOD` (1 hour by
default). Each run re-reads the XTM One agents catalog and upserts the corresponding AI targets. No manual interaction is
required.

By default (`COLLECTOR_INCLUDE_BARE_MODELS=false` and an empty `COLLECTOR_AGENT_TAGS`) the collector imports **all**
chat-capable agents and **no** bare models. Set `COLLECTOR_AGENT_TAGS` to a comma-separated list to scope on specific
tags, and set `COLLECTOR_INCLUDE_BARE_MODELS=true` to also mirror the bare LLM models.

## Behavior

```mermaid
flowchart LR
    subgraph XTM One
        A["GET /api/v1/agents"]
        M["GET /v1/models"]
    end
    C(XTM One collector)
    subgraph OpenAEV
        T[AI targets]
        G[Tags]
    end
    A -->|list agents| C
    M -->|list bare models (optional)| C
    C -->|upsert tags| G
    C -->|create / update AI targets| T
```

On each run, the collector:

1. Reads `GET /api/v1/agents` from XTM One and keeps only chat-capable agents (enabled, not `disable_chat`, with a
   slug).
2. Filters the agents by `COLLECTOR_AGENT_TAGS` when set (case-insensitive; empty = all agents).
3. Upserts one AI target per agent with provider `OPENAI_COMPATIBLE`, endpoint `{XTM_ONE_URL}/v1`, and model
   `agent:<slug>`, tagged `source:xtm-one` and `type:agent` (plus the agent's own tags).
4. When `COLLECTOR_INCLUDE_BARE_MODELS=true`, reads `GET /v1/models`, skips the `agent:*` / copilot-owned entries, and
   upserts one AI target per remaining model (tagged `source:xtm-one` and `type:model`).

Existing targets are matched on their external reference (`xtm-one:agent:<slug>` / `xtm-one:model:<id>`) and updated in
place, so repeated runs never create duplicates.

## Data source

- Source: the XTM One platform configured through `COLLECTOR_XTM_ONE_URL`.
- Endpoints used: `GET {XTM_ONE_URL}/api/v1/agents` (agents catalog) and, when bare-model collection is enabled,
  `GET {XTM_ONE_URL}/v1/models` (OpenAI-compatible models listing).
- Authentication: `Authorization: Bearer <COLLECTOR_XTM_ONE_TOKEN>` (an XTM One `fcp-...` API key).
- Agent targets use the `XTM_ONE` provider and point back at `{XTM_ONE_URL}`; the AI red team injector calls
  `POST /api/v1/platform/chat/messages` with the recorded `agent:<slug>`. Bare-model targets use the
  `OPENAI_COMPATIBLE` provider at `{XTM_ONE_URL}/v1` (the injector appends `/chat/completions`).

## Debugging

Set `COLLECTOR_LOG_LEVEL=debug` to get verbose logs, including each AI target as it is created or updated. Common issues:

- Connectivity errors point to `COLLECTOR_XTM_ONE_URL` not being routable from the collector container (avoid
  `localhost` inside Docker) or to the OpenAEV URL being unreachable.
- `401`/`403` errors when reading agents usually mean the `COLLECTOR_XTM_ONE_TOKEN` is invalid, inactive, or lacks
  access to the agents.
- An empty AI target catalog after a run usually means every agent was filtered out by `COLLECTOR_AGENT_TAGS`, or all
  agents are disabled / `disable_chat`.
- If injects against the imported targets fail to authenticate, verify that `COLLECTOR_XTM_ONE_TOKEN` holds a valid XTM
  One `fcp-...` key (it is stored on each target as `ai_target_token` and used by the injector at execution time).

## Additional information

- The collector is idempotent: it upserts AI targets on every run (keyed by their external reference), so it is safe to
  run repeatedly.
- Agents scoping is tag-based; bare models have no tags in XTM One, so `COLLECTOR_AGENT_TAGS` only affects agents.
- The credential used to reach XTM One at inject execution time is resolved by the injector from the environment
  variable named on the target; it is never read from or stored by the platform.
