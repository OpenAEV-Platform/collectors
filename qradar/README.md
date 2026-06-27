# OpenAEV IBM QRadar Collector

An IBM QRadar integration for OpenAEV that validates detection expectations by running Ariel (AQL) searches against QRadar and matching the returned events against expected outcomes.

**Note**: Requires access to an IBM QRadar console with the REST API enabled.

## Overview

This collector validates OpenAEV expectations by querying your QRadar environment for matching events via the Ariel search REST API. When OpenAEV runs security exercises, this collector automatically checks whether the expected activity was detected by QRadar, providing visibility into your detection capabilities.

The collector builds an AQL query from the attack signatures, creates an Ariel search, polls it until completion, and parses the returned events, with support for IP-based matching and parent process tracking through the URL property.

## Features

- **Detection Validation**: Runs Ariel (AQL) searches to verify QRadar detections
- **IP-based Matching**: Supports both source and destination IPv4 / IPv6 address matching (`sourceip` / `destinationip`)
- **Parent Process Tracking**: Extracts inject/agent identifiers from parent process names and matches them against the `URL` property
- **Flexible Authentication**: Authorized service token (SEC header, preferred) or HTTP basic authentication
- **Retry Mechanism**: Built-in retry logic with a configurable offset to handle event ingestion latency
- **Trace Generation**: Creates traces with links back to the QRadar Log Activity view
- **Flexible Configuration**: Support for YAML, environment variables, and multiple deployment scenarios

## Required permissions

The QRadar collector requires credentials (authorized service token or user) with:
- Permission to create and read Ariel searches (`/api/ariel/searches`)
- Read access to the configured data source (events or flows)

See the IBM documentation on [authorized services](https://www.ibm.com/docs/en/qsip/7.5?topic=app-creating-authorized-service-token) and the [QRadar REST API](https://www.ibm.com/docs/en/qsip/7.5?topic=api-rest-overview).

## Requirements

- OpenAEV Platform
- An IBM QRadar console with the REST API enabled
- Python 3.11+ (for manual deployment)
- An authorized service token or user account with the permissions described above

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

| Parameter        | config.yml          | Docker environment variable | Default                                       | Mandatory | Description                                                                                   |
|------------------|---------------------|-----------------------------|-----------------------------------------------|-----------|-----------------------------------------------------------------------------------------------|
| Collector ID     | collector.id        | `COLLECTOR_ID`              | qradar--0b13e3f7-5c9e-46f5-acc4-33032e9b4921  | Yes       | A unique `UUIDv4` identifier for this collector instance.                                     |
| Collector Name   | collector.name      | `COLLECTOR_NAME`            | QRadar                                        | No        | Name of the collector.                                                                        |
| Collector Period | collector.period    | `COLLECTOR_PERIOD`          | PT1M                                          | No        | Collection interval (ISO 8601 format).                                                        |
| Log Level        | collector.log_level | `COLLECTOR_LOG_LEVEL`       | error                                         | No        | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.        |
| Platform         | collector.platform  | `COLLECTOR_PLATFORM`        | SIEM                                          | No        | Type of security platform this collector works for. One of: `EDR, XDR, SIEM, SOAR, NDR, ISPM` |

### Collector extra parameters environment variables

Below are the parameters you'll need to set for the collector:

| Parameter      | config.yml            | Docker environment variable | Default                     | Mandatory | Description                                                                              |
|----------------|-----------------------|-----------------------------|-----------------------------|-----------|-----------------------------------------------------------------------------------------|
| Base URL       | qradar.base_url       | `QRADAR_BASE_URL`           | https://qradar.company.com  | Yes       | Base URL of the QRadar console.                                                          |
| Token          | qradar.token          | `QRADAR_TOKEN`              |                             | No*       | Authorized service token (preferred). Sent in the SEC header.                            |
| Username       | qradar.username       | `QRADAR_USERNAME`           |                             | No*       | Username for HTTP basic authentication (used when no token is set).                      |
| Password       | qradar.password       | `QRADAR_PASSWORD`           |                             | No*       | Password for HTTP basic authentication.                                                  |
| API Version    | qradar.api_version    | `QRADAR_API_VERSION`        | 20.0                        | No        | QRadar REST API version sent in the Version header.                                      |
| Data Source    | qradar.data_source    | `QRADAR_DATA_SOURCE`        | events                      | No        | Ariel data source to query (events or flows).                                            |
| Console URL    | qradar.console_url    | `QRADAR_CONSOLE_URL`        |                             | No        | QRadar console URL used to build trace links (defaults to base_url).                     |
| Verify SSL     | qradar.verify_ssl     | `QRADAR_VERIFY_SSL`         | true                        | No        | Whether to verify the QRadar TLS certificate.                                            |
| Time Window    | qradar.time_window    | `QRADAR_TIME_WINDOW`        | PT1H                        | No        | Default search window when no date signatures are provided (ISO 8601 format).            |
| Offset         | qradar.offset         | `QRADAR_OFFSET`             | PT30S                       | No        | Delay between retry attempts to account for event ingestion latency (ISO 8601 format).   |
| Max Retry      | qradar.max_retry      | `QRADAR_MAX_RETRY`          | 3                           | No        | Maximum number of retry attempts after the initial search fails or returns no results.   |
| Search Timeout | qradar.search_timeout | `QRADAR_SEARCH_TIMEOUT`     | PT5M                        | No        | Maximum time to wait for an Ariel search to complete (ISO 8601 format).                  |
| Poll Interval  | qradar.poll_interval  | `QRADAR_POLL_INTERVAL`      | PT5S                        | No        | Interval between Ariel search status polls (ISO 8601 format).                            |

> \* Authentication is required: provide either `QRADAR_TOKEN` or both `QRADAR_USERNAME` and `QRADAR_PASSWORD`.

### Example Configuration Files

#### YAML Configuration (`src/config.yml`)
```yaml
openaev:
  url: "https://your-openaev-instance.com"
  token: "your-openaev-token"
# tenant_id: "your-openaev-tenant-id"
collector:
  id: "qradar--your-unique-uuid"
  name: "IBM QRadar Production"
  period: "PT10M"
  log_level: "info"

qradar:
  base_url: "https://your-qradar.company.com"
  token: "your-authorized-service-token"
  api_version: "20.0"
  data_source: "events"
  verify_ssl: true
  offset: "PT45S"
  max_retry: 5
```

#### Environment Variables
```bash
export OPENAEV_URL="https://your-openaev-instance.com"
export OPENAEV_TOKEN="your-openaev-token"
export OPENAEV_TENANT_ID="your-openaev-tenant-id"
export COLLECTOR_ID="qradar--your-unique-uuid"
export QRADAR_BASE_URL="https://your-qradar.company.com"
export QRADAR_TOKEN="your-authorized-service-token"
export QRADAR_DATA_SOURCE="events"
```

## API endpoints used

- **Authentication**: authorized service token (`SEC` header) or HTTP basic
- **Create search**: `POST /api/ariel/searches?query_expression=<AQL>`
- **Poll status**: `GET /api/ariel/searches/{search_id}`
- **Fetch results**: `GET /api/ariel/searches/{search_id}/results`
- **AQL fields used for matching**: `sourceip`, `destinationip`, `"URL"`, `qidname`, `categoryname`, `starttime`
- **Reference**: [QRadar Ariel API](https://www.ibm.com/docs/en/qsip/7.5?topic=api-rest-overview)

> **Note**: The required permissions and endpoints listed above are based on the current code and documentation. IBM may change API requirements at any time. Always check the [official IBM QRadar documentation](https://www.ibm.com/docs/en/qsip) for the latest requirements before deploying.
