# OpenAEV SentinelOne Collector

A SentinelOne EDR integration for OpenAEV that validates security expectations by querying SentinelOne's Deep Visibility and Threats APIs.

**Note**: Requires access to a SentinelOne Management Console with appropriate API permissions.

**⚠️ Deep Visibility License Warning**: All static engine alerts rely on Deep Visibility, which is only compatible with Complete licenses. However, behavioral detection will be properly handled even with Core or Control licenses. The `enable_deep_visibility_search` configuration option (defaulted to False) allows you to enable this feature when you have the appropriate license.

## Overview

This collector validates OpenAEV expectations by querying your SentinelOne environment for threat data via the SentinelOne API. When OpenAEV runs security exercises, this collector automatically checks if the expected security threats were detected in your EDR by matching threat information and associated events, providing visibility into your detection capabilities.

The collector uses SentinelOne's Threats API to fetch threat data and correlates it with threat events to validate expectations.

## Features

- **Threat-Based Validation**: Queries SentinelOne Threats API to validate security expectations against detected threats
- **Batch Processing**: Processes expectations in configurable batches for improved performance
- **Event Correlation**: Correlates threat data with threat events to extract process execution details
- **Trace Generation**: Creates detailed traces with links back to SentinelOne console
- **Flexible Configuration**: Support for YAML, environment variables, and multiple deployment scenarios


## Required API Permissions

The SentinelOne collector requires:
- API token with "Threats" and "Threat Events" permissions.
  - See [SentinelOne API documentation](https://developer.sentinelone.com/reference).

## Requirements

- OpenAEV Platform
- SentinelOne Management Console with API access
- Python 3.12+ (for manual deployment)

## Configuration

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or
in `config.yml` (for manual deployment).

The collector supports multiple configuration sources in order of precedence:
1. `.env` file (if present in src directory)
2. YAML configuration file (`src/config.yml`, if present)
3. Environment variables (fallback)

### OpenAEV environment variables

Below are the parameters you'll need to set for OpenAEV:

| Parameter     | config.yml    | Docker environment variable | Mandatory | Description                                          |
|---------------|---------------|-----------------------------|-----------|------------------------------------------------------|
| OpenAEV URL   | openaev.url   | `OPENAEV_URL`               | Yes       | The URL of the OpenAEV platform.                    |
| OpenAEV Token | openaev.token | `OPENAEV_TOKEN`             | Yes       | The default admin token set in the OpenAEV platform.|

### Base collector environment variables

Below are the parameters you'll need to set for running the collector properly:

| Parameter        | config.yml          | Docker environment variable | Default                 | Mandatory | Description                                                                                   |
|------------------|---------------------|-----------------------------|-------------------------|-----------|-----------------------------------------------------------------------------------------------|
| Collector ID     | collector.id        | `COLLECTOR_ID`              | sentinelone--0b13e3f7-5c9e-46f5-acc4-33032e9b4921 | Yes       | A unique `UUIDv4` identifier for this collector instance.                                     |
| Collector Name   | collector.name      | `COLLECTOR_NAME`            | SentinelOne             | No        | Name of the collector.                                                                        |
| Collector Period | collector.period    | `COLLECTOR_PERIOD`          | PT2M                    | No        | Collection interval (ISO 8601 format).                                                       |
| Log Level        | collector.log_level | `COLLECTOR_LOG_LEVEL`       | error                   | No        | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.      |
| Platform         | collector.platform  | `COLLECTOR_PLATFORM`        | EDR                     | No        | Type of security platform this collector works for. One of: `EDR, XDR, SIEM, SOAR, NDR, ISPM` |
| Icon Filepath    | collector.icon_filepath | `COLLECTOR_ICON_FILEPATH` | src/img/sentinelone-logo.png | No        | Path to the icon file of the collector.                                           |

### Collector extra parameters environment variables

Below are the parameters you'll need to set for the collector:

| Parameter                | config.yml                           | Docker environment variable            | Default                     | Mandatory | Description                                                                                        |
|--------------------------|--------------------------------------|----------------------------------------|-----------------------------|-----------|----------------------------------------------------------------------------------------------------|
| Base URL                 | sentinelone.base_url                 | `SENTINELONE_BASE_URL`                 | https://api.sentinelone.com | No        | SentinelOne Management Console URL                                                                 |
| API Key                  | sentinelone.api_key                  | `SENTINELONE_API_KEY`                  |                             | Yes       | SentinelOne API token with Threats and Threat Events permissions                                  |
| Time Window              | sentinelone.time_window              | `SENTINELONE_TIME_WINDOW`              | PT1H                        | No        | Default search time window when no date signatures are provided (ISO 8601 format)                |
| Expectation Batch Size   | sentinelone.expectation_batch_size   | `SENTINELONE_EXPECTATION_BATCH_SIZE`   | 50                          | No        | Number of expectations to process in each batch for batch-based processing                         |
| Enable Deep Visibility   | sentinelone.enable_deep_visibility_search | `SENTINELONE_ENABLE_DEEP_VISIBILITY_SEARCH` | false                  | No        | Enable Deep Visibility search for advanced threat detection (requires Complete license)           |

### Example Configuration Files

#### YAML Configuration (`src/config.yml`)
```yaml
openaev:
  url: "https://your-openaev-instance.com"
  token: "your-openaev-token"

collector:
  id: "sentinelone--your-unique-uuid"
  name: "SentinelOne Production"
  period: "PT10M"
  log_level: "info"

sentinelone:
  base_url: "https://your-sentinelone-console.sentinelone.net"
  api_key: "your-sentinelone-api-token"
  time_window: "PT1H"
  expectation_batch_size: 50
  enable_deep_visibility_search: false
```

#### Environment Variables
```bash
export OPENAEV_URL="https://your-openaev-instance.com"
export OPENAEV_TOKEN="your-openaev-token"
export COLLECTOR_ID="sentinelone--your-unique-uuid"
export SENTINELONE_BASE_URL="https://your-sentinelone-console.sentinelone.net"
export SENTINELONE_API_KEY="your-sentinelone-api-token"
export SENTINELONE_ENABLE_DEEP_VISIBILITY_SEARCH="false"
```

## Deployment

### Manual Deployment with Poetry

1. **Clone and Install Dependencies**:
   ```bash
   git clone <repository-url>
   cd sentinelone
   poetry install --extras local
   ```

2. **Configure the Collector**:
   - Copy `src/config.yml.sample` to `src/config.yml`
   - Update configuration values or set environment variables

3. **Run the Collector**:
   ```bash
   # Using Poetry
   poetry run python -m src

   # Or direct execution after installation
   SentinelOneCollector
   ```

### Docker Deployment

```bash
# Build the container
docker build -t openaev-sentinelone-collector .

# Run with environment variables
docker run -d \
  -e OPENAEV_URL="https://your-openaev-instance.com" \
  -e OPENAEV_TOKEN="your-token" \
  -e COLLECTOR_ID="sentinelone--your-uuid" \
  -e SENTINELONE_BASE_URL="https://your-console.sentinelone.net" \
  -e SENTINELONE_API_KEY="your-api-key" \
  openaev-sentinelone-collector

# Or run with configuration file mounted
docker run -d \
  -v /path/to/config.yml:/app/src/config.yml:ro \
  openaev-sentinelone-collector
```

## API Permissions and Endpoints Used

- **API Permissions Required:**
  - Threats: Read access to query threat information
  - Threat Events: Read access to retrieve threat event details
  - Console Access: General API access to the Management Console
  - Deep Visibility (Optional): Required when `enable_deep_visibility_search` is enabled, needs Complete license
- **API Endpoints Used:**
  - `GET /web/api/v2.1/threats`
  - `GET /web/api/v2.1/threat-events`
  - Deep Visibility endpoints (when enabled):
    - `POST /web/api/v2.1/dv/init-query`
    - `GET /web/api/v2.1/dv/query-status`
    - `GET /web/api/v2.1/dv/events`
- **Reference:** [SentinelOne API documentation](https://developer.sentinelone.com/reference)

> **Warning** _(as of April 14, 2026)_: The required permissions and endpoints listed above are based on the current code and documentation. SentinelOne may change API requirements or endpoints at any time. **Always check the [official documentation](https://developer.sentinelone.com/reference) for the latest requirements before deploying.**
