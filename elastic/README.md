# OpenAEV Elastic Security Collector

An Elastic Security integration for OpenAEV that validates detection expectations by querying Elastic (Elasticsearch) for detection alerts and matching them against expected outcomes.

**Note**: Requires access to an Elasticsearch cluster that stores Elastic Security detection alerts.

## Overview

This collector validates OpenAEV expectations by querying your Elastic Security environment for matching detection alerts via the Elasticsearch `_search` API. When OpenAEV runs security exercises, this collector automatically checks whether the expected activity was detected by your Elastic Security rules, providing visibility into your detection capabilities.

The collector queries the Elastic Security detection alerts index (default `.alerts-security.alerts-*`) using ECS fields, with support for IP-based matching and parent process tracking through URL path analysis.

## Features

- **Detection Validation**: Queries Elastic Security detection alerts to verify security detections
- **IP-based Matching**: Supports both source and destination IPv4/IPv6 address matching (ECS `source.ip` / `destination.ip`)
- **Parent Process Tracking**: Extracts inject/agent identifiers from parent process names and matches them against the ECS `url.path` field
- **Flexible Authentication**: API key (preferred) or HTTP basic authentication
- **Retry Mechanism**: Built-in retry logic with a configurable offset to handle alert ingestion latency
- **Trace Generation**: Creates traces with links back to the Elastic Security alerts view in Kibana
- **Flexible Configuration**: Support for YAML, environment variables, and multiple deployment scenarios

## Required permissions

The Elastic Security collector requires credentials (API key or user) with:
- `read` privileges on the configured alerts index/pattern (default `.alerts-security.alerts-*`)
- Permission to run search (`_search`) requests against that index

See the Elastic documentation on [API keys](https://www.elastic.co/guide/en/elasticsearch/reference/current/security-api-create-api-key.html) and [security privileges](https://www.elastic.co/guide/en/elasticsearch/reference/current/security-privileges.html).

## Requirements

- OpenAEV Platform
- An Elasticsearch cluster storing Elastic Security detection alerts
- Python 3.11+ (for manual deployment)
- An API key or user account with the permissions described above

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
| Collector ID     | collector.id        | `COLLECTOR_ID`              | elastic--0b13e3f7-5c9e-46f5-acc4-33032e9b4921 | Yes       | A unique `UUIDv4` identifier for this collector instance.                                     |
| Collector Name   | collector.name      | `COLLECTOR_NAME`            | Elastic                                       | No        | Name of the collector.                                                                        |
| Collector Period | collector.period    | `COLLECTOR_PERIOD`          | PT1M                                          | No        | Collection interval (ISO 8601 format).                                                        |
| Log Level        | collector.log_level | `COLLECTOR_LOG_LEVEL`       | error                                         | No        | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.        |
| Platform         | collector.platform  | `COLLECTOR_PLATFORM`        | SIEM                                          | No        | Type of security platform this collector works for. One of: `EDR, XDR, SIEM, SOAR, NDR, ISPM` |

### Collector extra parameters environment variables

Below are the parameters you'll need to set for the collector:

| Parameter    | config.yml           | Docker environment variable | Default                     | Mandatory | Description                                                                              |
|--------------|----------------------|-----------------------------|-----------------------------|-----------|-----------------------------------------------------------------------------------------|
| Base URL     | elastic.base_url     | `ELASTIC_BASE_URL`          | https://localhost:9200      | Yes       | Base URL of the Elasticsearch API.                                                       |
| API Key      | elastic.api_key      | `ELASTIC_API_KEY`           |                             | No*       | Elasticsearch API key (preferred). Used instead of username/password when set.          |
| Username     | elastic.username     | `ELASTIC_USERNAME`          |                             | No*       | Username for HTTP basic authentication (used when no API key is set).                    |
| Password     | elastic.password     | `ELASTIC_PASSWORD`          |                             | No*       | Password for HTTP basic authentication.                                                  |
| Alerts Index | elastic.alerts_index | `ELASTIC_ALERTS_INDEX`      | .alerts-security.alerts-*   | No        | Index or index pattern to search for detection alerts.                                   |
| Kibana URL   | elastic.kibana_url   | `ELASTIC_KIBANA_URL`        |                             | No        | Kibana base URL used to build trace links (defaults to base_url on port 5601).           |
| Verify SSL   | elastic.verify_ssl   | `ELASTIC_VERIFY_SSL`        | true                        | No        | Whether to verify the Elasticsearch TLS certificate.                                     |
| Time Window  | elastic.time_window  | `ELASTIC_TIME_WINDOW`       | PT1H                        | No        | Default search time window when no date signatures are provided (ISO 8601 format).       |
| Offset       | elastic.offset       | `ELASTIC_OFFSET`            | PT30S                       | No        | Delay between retry attempts to account for alert ingestion latency (ISO 8601 format).   |
| Max Retry    | elastic.max_retry    | `ELASTIC_MAX_RETRY`         | 3                           | No        | Maximum number of retry attempts after the initial API call fails or returns no results. |

> \* Authentication is required: provide either `ELASTIC_API_KEY` or both `ELASTIC_USERNAME` and `ELASTIC_PASSWORD`.

### Example Configuration Files

#### YAML Configuration (`src/config.yml`)
```yaml
openaev:
  url: "https://your-openaev-instance.com"
  token: "your-openaev-token"
# tenant_id: "your-openaev-tenant-id"
collector:
  id: "elastic--your-unique-uuid"
  name: "Elastic Security Production"
  period: "PT10M"
  log_level: "info"

elastic:
  base_url: "https://your-elastic.company.com:9200"
  api_key: "your-base64-encoded-api-key"
  alerts_index: ".alerts-security.alerts-*"
  kibana_url: "https://your-kibana.company.com:5601"
  verify_ssl: true
  offset: "PT45S"
  max_retry: 5
```

#### Environment Variables
```bash
export OPENAEV_URL="https://your-openaev-instance.com"
export OPENAEV_TOKEN="your-openaev-token"
export OPENAEV_TENANT_ID="your-openaev-tenant-id"
export COLLECTOR_ID="elastic--your-unique-uuid"
export ELASTIC_BASE_URL="https://your-elastic.company.com:9200"
export ELASTIC_API_KEY="your-base64-encoded-api-key"
export ELASTIC_ALERTS_INDEX=".alerts-security.alerts-*"
```

## API endpoints used

- **Authentication**: API key (`Authorization: ApiKey ...`) or HTTP basic
- **Endpoint**: `POST /<alerts_index>/_search` (Elasticsearch search API)
- **ECS fields used for matching**: `@timestamp`, `source.ip`, `destination.ip`, `url.path`, and the alert rule name (`kibana.alert.rule.name`)
- **Reference**: [Elasticsearch search API](https://www.elastic.co/guide/en/elasticsearch/reference/current/search-search.html)

> **Note**: The required permissions and endpoints listed above are based on the current code and documentation. Elastic may change API requirements at any time. Always check the [official Elastic documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/search-search.html) for the latest requirements before deploying.
