# OpenAEV NetWitness Collector

A NetWitness integration for OpenAEV that validates detection expectations by querying the NetWitness Core SDK and matching the returned sessions against expected outcomes.

**Note**: Requires network access to a NetWitness Core service (Broker or Concentrator) with the RESTful API enabled.

## Overview

This collector validates OpenAEV expectations by querying your NetWitness environment for matching sessions via the Core SDK query API (NWQL). When OpenAEV runs security exercises, this collector automatically checks whether the expected activity was observed by NetWitness, providing visibility into your detection capabilities.

The collector builds an NWQL query from the attack signatures, executes it against the Core SDK, and parses the returned session metadata, with support for IP-based matching and parent process tracking through the URL meta.

## Features

- **Detection Validation**: Runs NetWitness Core SDK queries to verify detections
- **IP-based Matching**: Supports both source and destination IPv4 / IPv6 address matching (`ip.src` / `ip.dst`)
- **Parent Process Tracking**: Extracts inject/agent identifiers from parent process names and matches them against the `url` meta
- **Flexible Authentication**: HTTP basic authentication (Core SDK) or a bearer token (NetWitness Platform API)
- **Retry Mechanism**: Built-in retry logic with a configurable offset to handle ingestion latency
- **Trace Generation**: Creates traces with links back to NetWitness Investigate
- **Flexible Configuration**: Support for YAML, environment variables, and multiple deployment scenarios

## Required permissions

The NetWitness collector requires credentials (a Core service user or token) with:
- Permission to run queries against the Core SDK (`/sdk?msg=query`)

See the NetWitness documentation on the [Core RESTful API](https://community.netwitness.com/s/article/SDKCommands).

## Requirements

- OpenAEV Platform
- A NetWitness Core service (Broker on port 50103 or Concentrator on port 50105) with the RESTful API reachable
- Python 3.11+ (for manual deployment)
- A user account or token with permission to query the Core SDK

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

| Parameter        | config.yml          | Docker environment variable | Default                                         | Mandatory | Description                                                                                   |
|------------------|---------------------|-----------------------------|-------------------------------------------------|-----------|-----------------------------------------------------------------------------------------------|
| Collector ID     | collector.id        | `COLLECTOR_ID`              | netwitness--0b13e3f7-5c9e-46f5-acc4-33032e9b... | Yes       | A unique `UUIDv4` identifier for this collector instance.                                     |
| Collector Name   | collector.name      | `COLLECTOR_NAME`            | NetWitness                                      | No        | Name of the collector.                                                                        |
| Collector Period | collector.period    | `COLLECTOR_PERIOD`          | PT1M                                            | No        | Collection interval (ISO 8601 format).                                                        |
| Log Level        | collector.log_level | `COLLECTOR_LOG_LEVEL`       | error                                           | No        | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.        |
| Platform         | collector.platform  | `COLLECTOR_PLATFORM`        | SIEM                                            | No        | Type of security platform this collector works for. One of: `EDR, XDR, SIEM, SOAR, NDR, ISPM` |

### Collector extra parameters environment variables

Below are the parameters you'll need to set for the collector:

| Parameter    | config.yml              | Docker environment variable | Default                              | Mandatory | Description                                                                              |
|--------------|-------------------------|-----------------------------|--------------------------------------|-----------|-----------------------------------------------------------------------------------------|
| Base URL     | netwitness.base_url     | `NETWITNESS_BASE_URL`       | https://netwitness.company.com:50103 | Yes       | Base URL of a NetWitness Core service (Broker/Concentrator).                             |
| Username     | netwitness.username     | `NETWITNESS_USERNAME`       |                                      | No*       | Username for HTTP basic authentication to the Core SDK.                                  |
| Password     | netwitness.password     | `NETWITNESS_PASSWORD`       |                                      | No*       | Password for HTTP basic authentication.                                                  |
| Token        | netwitness.token        | `NETWITNESS_TOKEN`          |                                      | No*       | Bearer token for the NetWitness Platform API (optional).                                 |
| Max Results  | netwitness.max_results  | `NETWITNESS_MAX_RESULTS`    | 100                                  | No        | Maximum number of sessions to return per query.                                         |
| Console URL  | netwitness.console_url  | `NETWITNESS_CONSOLE_URL`    |                                      | No        | NetWitness console URL used to build trace links (defaults to base_url).                 |
| Verify SSL   | netwitness.verify_ssl   | `NETWITNESS_VERIFY_SSL`     | true                                 | No        | Whether to verify the NetWitness TLS certificate.                                       |
| Time Window  | netwitness.time_window  | `NETWITNESS_TIME_WINDOW`    | PT1H                                 | No        | Default search window when no date signatures are provided (ISO 8601 format).            |
| Offset       | netwitness.offset       | `NETWITNESS_OFFSET`         | PT30S                                | No        | Delay between retry attempts to account for ingestion latency (ISO 8601 format).         |
| Max Retry    | netwitness.max_retry    | `NETWITNESS_MAX_RETRY`      | 3                                    | No        | Maximum number of retry attempts after the initial query fails or returns no results.    |

> \* Authentication is required: provide either `NETWITNESS_TOKEN` or both `NETWITNESS_USERNAME` and `NETWITNESS_PASSWORD`.

### Example Configuration Files

#### YAML Configuration (`src/config.yml`)
```yaml
openaev:
  url: "https://your-openaev-instance.com"
  token: "your-openaev-token"
# tenant_id: "your-openaev-tenant-id"
collector:
  id: "netwitness--your-unique-uuid"
  name: "NetWitness Production"
  period: "PT10M"
  log_level: "info"

netwitness:
  base_url: "https://your-netwitness.company.com:50103"
  username: "api"
  password: "your-password"
  max_results: 100
  verify_ssl: true
  offset: "PT45S"
  max_retry: 5
```

#### Environment Variables
```bash
export OPENAEV_URL="https://your-openaev-instance.com"
export OPENAEV_TOKEN="your-openaev-token"
export OPENAEV_TENANT_ID="your-openaev-tenant-id"
export COLLECTOR_ID="netwitness--your-unique-uuid"
export NETWITNESS_BASE_URL="https://your-netwitness.company.com:50103"
export NETWITNESS_USERNAME="api"
export NETWITNESS_PASSWORD="your-password"
```

## API endpoints used

- **Authentication**: HTTP basic (Core SDK) or bearer token
- **Query**: `GET /sdk?msg=query&query=<NWQL>&force-content-type=application/json`
- **NWQL meta used for matching**: `ip.src`, `ip.dst`, `url`, `time`
- **Reference**: [NetWitness Core SDK commands](https://community.netwitness.com/s/article/SDKCommands)

> **Note**: The required permissions and endpoints listed above are based on the current code and documentation. NetWitness may change API requirements at any time. Always check the official NetWitness documentation for the latest requirements before deploying.
