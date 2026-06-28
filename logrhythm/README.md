# OpenAEV LogRhythm Collector

A LogRhythm SIEM integration for OpenAEV that validates detection expectations by running searches against the LogRhythm Search API and matching the returned events against expected outcomes.

**Note**: Requires access to a LogRhythm deployment with the Search API (lr-search-api) reachable through the API gateway.

## Overview

This collector validates OpenAEV expectations by querying your LogRhythm environment for matching events via the Search API. When OpenAEV runs security exercises, this collector automatically checks whether the expected activity was detected by LogRhythm, providing visibility into your detection capabilities.

The collector builds a query filter from the attack signatures, initiates a search task, polls it until completion, and parses the returned events, with support for IP-based matching and parent process tracking through the URL field.

## Features

- **Detection Validation**: Runs LogRhythm Search API tasks to verify detections
- **IP-based Matching**: Supports both source and destination IPv4 / IPv6 address matching (SIP / DIP fields)
- **Parent Process Tracking**: Extracts inject/agent identifiers from parent process names and matches them against the URL field
- **Flexible Authentication**: API bearer token (preferred) or HTTP basic authentication
- **Retry Mechanism**: Built-in retry logic with a configurable offset to handle event ingestion latency
- **Trace Generation**: Creates traces with links back to the LogRhythm Web Console
- **Flexible Configuration**: Support for YAML, environment variables, and multiple deployment scenarios

## Required permissions

The LogRhythm collector requires credentials (API token or user) with:
- Permission to initiate and read searches via the Search API (`/lr-search-api/actions/*`)

See the LogRhythm documentation on the Search API (available on your deployment at `https://<host>:8505/lr-search-api/docs`).

## Requirements

- OpenAEV Platform
- A LogRhythm deployment with the Search API reachable through the API gateway
- Python 3.11+ (for manual deployment)
- An API bearer token or user account with the permissions described above

## Configuration

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or in `config.yml` (for manual deployment).

The collector loads configuration from a single source, selected in this order (the first one found wins; sources are not merged):
1. `.env` file (`src/.env`), if present
2. YAML configuration file (`src/config.yml`), if present
3. Environment variables

Any value not provided by the selected source falls back to its default.

### OpenAEV environment variables

Below are the parameters you'll need to set for OpenAEV:

| Parameter         | config.yml        | Docker environment variable | Mandatory | Description                                           |
|-------------------|-------------------|-----------------------------|-----------|-------------------------------------------------------|
| OpenAEV URL       | openaev.url       | `OPENAEV_URL`               | Yes       | The URL of the OpenAEV platform.                      |
| OpenAEV Token     | openaev.token     | `OPENAEV_TOKEN`             | Yes       | The default admin token set in the OpenAEV platform.  |
| OpenAEV Tenant ID | openaev.tenant_id | `OPENAEV_TENANT_ID`         | No        | Identifier of the tenant within the OpenAEV platform. |

> Warning
>
> The `tenant_id` parameter is a new configuration option. A period of backward compatibility is ensured: if this key is not defined,
> existing configurations will not be affected, and the default value will be `None`. However, if a value is provided, it will be
> validated by Pydantic and must conform to a valid UUID format, otherwise a validation error will be returned.

### Base collector environment variables

Below are the parameters you'll need to set for running the collector properly:

| Parameter        | config.yml          | Docker environment variable | Default                                        | Mandatory | Description                                                                                   |
|------------------|---------------------|-----------------------------|------------------------------------------------|-----------|-----------------------------------------------------------------------------------------------|
| Collector ID     | collector.id        | `COLLECTOR_ID`              | logrhythm--0b13e3f7-5c9e-46f5-acc4-33032e9b... | No\*      | A unique `UUIDv4` identifier for this collector instance. A default is provided; override it per deployment (see note below).                  |
| Collector Name   | collector.name      | `COLLECTOR_NAME`            | LogRhythm                                      | No        | Name of the collector.                                                                        |
| Collector Period | collector.period    | `COLLECTOR_PERIOD`          | PT1M                                           | No        | Collection interval (ISO 8601 format).                                                        |
| Log Level        | collector.log_level | `COLLECTOR_LOG_LEVEL`       | error                                          | No        | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.        |
| Platform         | collector.platform  | `COLLECTOR_PLATFORM`        | SIEM                                           | No        | Type of security platform this collector works for. One of: `EDR, XDR, SIEM, SOAR, NDR, ISPM` |

> \* `COLLECTOR_ID` is not strictly required - a built-in default lets the collector start out of the box - but every collector instance MUST use a unique `UUIDv4`. Override the default (via `COLLECTOR_ID` or `collector.id`) for each deployment: if two collectors share the same id they report under the same `source_id` and collide in OpenAEV.

### Collector extra parameters environment variables

Below are the parameters you'll need to set for the collector:

| Parameter           | config.yml                  | Docker environment variable    | Default                          | Mandatory | Description                                                                              |
|---------------------|-----------------------------|--------------------------------|----------------------------------|-----------|-----------------------------------------------------------------------------------------|
| Base URL            | logrhythm.base_url          | `LOGRHYTHM_BASE_URL`           | https://logrhythm.company.com:8501 | Yes     | Base URL of the LogRhythm API gateway.                                                   |
| Token               | logrhythm.token             | `LOGRHYTHM_TOKEN`              |                                  | No*       | API bearer token (preferred).                                                            |
| Username            | logrhythm.username          | `LOGRHYTHM_USERNAME`          |                                  | No*       | Username for HTTP basic authentication (used when no token is set).                      |
| Password            | logrhythm.password          | `LOGRHYTHM_PASSWORD`          |                                  | No*       | Password for HTTP basic authentication.                                                  |
| Query Event Manager | logrhythm.query_event_manager | `LOGRHYTHM_QUERY_EVENT_MANAGER` | true                          | No        | Whether to query the Event Manager (events) in addition to raw logs.                    |
| Max Messages        | logrhythm.max_msgs          | `LOGRHYTHM_MAX_MSGS`          | 100                              | No        | Maximum number of messages to query per search.                                         |
| Console URL         | logrhythm.console_url       | `LOGRHYTHM_CONSOLE_URL`       |                                  | No        | LogRhythm Web Console URL used to build trace links (defaults to base_url).              |
| Verify SSL          | logrhythm.verify_ssl        | `LOGRHYTHM_VERIFY_SSL`        | true                             | No        | Whether to verify the LogRhythm TLS certificate.                                         |
| Time Window         | logrhythm.time_window       | `LOGRHYTHM_TIME_WINDOW`       | PT1H                             | No        | Default search window when no date signatures are provided (ISO 8601 format).            |
| Offset              | logrhythm.offset            | `LOGRHYTHM_OFFSET`            | PT30S                            | No        | Delay between retry attempts to account for event ingestion latency (ISO 8601 format).   |
| Max Retry           | logrhythm.max_retry         | `LOGRHYTHM_MAX_RETRY`         | 3                                | No        | Maximum number of retry attempts after the initial search fails or returns no results.   |
| Search Timeout      | logrhythm.search_timeout    | `LOGRHYTHM_SEARCH_TIMEOUT`    | PT5M                             | No        | Maximum time to wait for a search task to complete (ISO 8601 format).                    |
| Poll Interval       | logrhythm.poll_interval     | `LOGRHYTHM_POLL_INTERVAL`     | PT5S                             | No        | Interval between search result status polls (ISO 8601 format).                           |

> \* Authentication is required: provide either `LOGRHYTHM_TOKEN` or both `LOGRHYTHM_USERNAME` and `LOGRHYTHM_PASSWORD`.

### Example Configuration Files

#### YAML Configuration (`src/config.yml`)
```yaml
openaev:
  url: "https://your-openaev-instance.com"
  token: "your-openaev-token"
# tenant_id: "your-openaev-tenant-id"
collector:
  id: "logrhythm--your-unique-uuid"
  name: "LogRhythm Production"
  period: "PT10M"
  log_level: "info"

logrhythm:
  base_url: "https://your-logrhythm.company.com:8501"
  token: "your-api-bearer-token"
  query_event_manager: true
  verify_ssl: true
  offset: "PT45S"
  max_retry: 5
```

#### Environment Variables
```bash
export OPENAEV_URL="https://your-openaev-instance.com"
export OPENAEV_TOKEN="your-openaev-token"
export OPENAEV_TENANT_ID="your-openaev-tenant-id"
export COLLECTOR_ID="logrhythm--your-unique-uuid"
export LOGRHYTHM_BASE_URL="https://your-logrhythm.company.com:8501"
export LOGRHYTHM_TOKEN="your-api-bearer-token"
```

## API endpoints used

- **Authentication**: API bearer token (`Authorization: Bearer ...`) or HTTP basic
- **Initiate search**: `POST /lr-search-api/actions/search-task`
- **Fetch results**: `POST /lr-search-api/actions/search-result`
- **LogRhythm field IDs used for matching**: SIP (`18`), DIP (`19`), URL (`42`)
- **Reference**: LogRhythm Search API documentation (`https://<host>:8505/lr-search-api/docs`)

> **Note**: The required permissions and endpoints listed above are based on the current code and documentation. LogRhythm may change API requirements at any time. Always check the official LogRhythm documentation for the latest requirements before deploying.
