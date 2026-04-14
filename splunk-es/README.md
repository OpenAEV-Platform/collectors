# OpenAEV Splunk Enterprise Security Collector

A Splunk Enterprise Security (ES) integration for OpenAEV that validates security expectations by querying Splunk ES for detection alerts and matching them against expected outcomes.

**Note**: Requires access to a Splunk Enterprise Security instance.

## Overview

This collector validates OpenAEV expectations by querying your Splunk ES environment for matching security alerts via the Splunk REST API. When OpenAEV runs security exercises, this collector automatically checks if the expected security threats were actually detected in your SIEM, providing visibility into your detection capabilities.

The collector uses Splunk's notable events and security alerts to validate detection expectations, with support for IP-based matching and parent process tracking through URL path analysis.

## Features

- **Detection Validation**: Queries Splunk ES notable events to verify security detections
- **IP-based Matching**: Supports both source and destination IPv4/IPv6 address matching
- **Parent Process Tracking**: Extracts and matches parent process names from URL paths
- **Retry Mechanism**: Built-in retry logic with configurable delays to handle alert ingestion latency
- **Trace Generation**: Creates detailed traces with links back to Splunk ES search results
- **Flexible Configuration**: Support for YAML, environment variables, and multiple deployment scenarios


## Required API Permissions

The Splunk ES collector requires a user account with:
- Search access via REST API
- Read access to the configured events index (e.g., `main`)
- REST API access

See [Splunk Roles and Capabilities](https://docs.splunk.com/Documentation/Splunk/latest/Security/Aboutusersandroles).

## Requirements

- OpenAEV Platform
- Splunk Enterprise Security instance.
- Python 3.11+ (for manual deployment)

## Configuration

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or
in `config.yml` (for manual deployment).

The collector supports multiple configuration sources in order of precedence:
1. Environment variables
2. YAML configuration file (`src/config.yml`)
3. Default values

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
| Collector ID     | collector.id        | `COLLECTOR_ID`              | splunk-es--0b13e3f7-5c9e-46f5-acc4-33032e9b4921 | Yes       | A unique `UUIDv4` identifier for this collector instance.                                     |
| Collector Name   | collector.name      | `COLLECTOR_NAME`            | Splunk ES               | No        | Name of the collector.                                                                        |
| Collector Period | collector.period    | `COLLECTOR_PERIOD`          | PT1M                    | No        | Collection interval (ISO 8601 format).                                                       |
| Log Level        | collector.log_level | `COLLECTOR_LOG_LEVEL`       | error                   | No        | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.      |
| Platform         | collector.platform  | `COLLECTOR_PLATFORM`        | SIEM                    | No        | Type of security platform this collector works for. One of: `EDR, XDR, SIEM, SOAR, NDR, ISPM` |

### Collector extra parameters environment variables

Below are the parameters you'll need to set for the collector:

| Parameter         | config.yml                    | Docker environment variable | Default                     | Mandatory | Description                                                                                        |
|-------------------|-------------------------------|-----------------------------|-----------------------------|-----------|----------------------------------------------------------------------------------------------------|
| Base URL          | splunk_es.base_url            | `SPLUNKES_BASE_URL`         | https://localhost:8089      | Yes       | Splunk ES Management URL (typically port 8089 for REST API)                                       |
| Username          | splunk_es.username            | `SPLUNKES_USERNAME`         |                             | Yes       | Splunk username with search permissions                                                            |
| Password          | splunk_es.password            | `SPLUNKES_PASSWORD`         |                             | Yes       | Splunk user password                                                                               |
| Alerts Index      | splunk_es.alerts_index        | `SPLUNKES_ALERTS_INDEX`     | main                    | No        | Splunk index to search for security alerts                                                        |
| Time Window       | splunk_es.time_window         | `SPLUNKES_TIME_WINDOW`      | PT1H                        | No        | Default search time window when no date signatures are provided (ISO 8601 format)                |
| Offset            | splunk_es.offset              | `SPLUNKES_OFFSET`           | PT30S                       | No        | Delay between retry attempts to account for alert ingestion latency (ISO 8601 format)            |
| Max Retry         | splunk_es.max_retry           | `SPLUNKES_MAX_RETRY`        | 3                           | No        | Maximum number of retry attempts after the initial API call fails or returns no results          |

### Example Configuration Files

#### YAML Configuration (`src/config.yml`)
```yaml
openaev:
  url: "https://your-openaev-instance.com"
  token: "your-openaev-token"

collector:
  id: "splunk-es--your-unique-uuid"
  name: "Splunk ES Production"
  period: "PT10M"
  log_level: "info"

splunk_es:
  base_url: "https://your-splunk-es.company.com:8089"
  username: "splunk-user"
  password: "your-splunk-password"
  alerts_index: "main"
  offset: "PT45S"
  max_retry: 5
```

#### Environment Variables
```bash
export OPENAEV_URL="https://your-openaev-instance.com"
export OPENAEV_TOKEN="your-openaev-token"
export COLLECTOR_ID="splunk-es--your-unique-uuid"
export SPLUNKES_BASE_URL="https://your-splunk-es.company.com:8089"
export SPLUNKES_USERNAME="splunk-user"
export SPLUNKES_PASSWORD="your-splunk-password"
export SPLUNKES_ALERTS_INDEX="main"
```

## API Permissions and Endpoints Used

- **API Permissions Required:**
  - Search access via REST API
  - Read access to the configured events index (e.g., `main`)
  - REST API access
- **API Endpoints Used:**
  - `POST /services/search/jobs`
- **Reference:** [Splunk Roles and Capabilities](https://docs.splunk.com/Documentation/Splunk/latest/Security/Aboutusersandroles)

> **Warning** _(as of April 14, 2026)_: The required permissions and endpoints listed above are based on the current code and documentation. Splunk may change API requirements or endpoints at any time. **Always check the [official documentation](https://docs.splunk.com/Documentation/Splunk/latest/Security/Aboutusersandroles) for the latest requirements before deploying.**
