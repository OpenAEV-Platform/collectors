# OpenAEV Splunk Enterprise Security Collector

A Splunk Enterprise Security (ES) integration for OpenAEV that validates security expectations by querying Splunk ES for detection alerts and matching them against expected outcomes.

**Note**: Requires access to a Splunk Enterprise Security instance.

## Overview

This collector validates OpenAEV expectations by querying your Splunk ES environment for matching security alerts via the Splunk REST API. When OpenAEV runs security exercises, this collector automatically checks if the expected security threats were actually detected in your SIEM, providing visibility into your detection capabilities.

The collector uses Splunk's notable events and security alerts to validate detection expectations, with support for IP-based matching, implant URL/process name tracking, and parent process detection.

## Features

- **Detection Validation**: Queries Splunk ES notable events to verify security detections
- **IP-based Matching**: Supports both source and destination IPv4/IPv6 address matching
- **Implant Detection**: Matches implant callback URL paths and process names (`{implant_urls}`, `{implant_names}`) including `parent_process_name`
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
- Splunk user account with appropriate search permissions

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

| Parameter         | config.yml        | Docker environment variable | Mandatory | Description                                           |
|-------------------|-------------------|-----------------------------|-----------|-------------------------------------------------------|
| OpenAEV URL       | openaev.url       | `OPENAEV_URL`               | Yes       | The URL of the OpenAEV platform.                      |
| OpenAEV Token     | openaev.token     | `OPENAEV_TOKEN`             | Yes       | The default admin token set in the OpenAEV platform.  |
| OpenAEV Tenant ID | openaev.tenant_id | `OPENAEV_TENANT_ID`         | No        | Identifier of the tenant within the OpenAEV platform. |

> ⚠️ Warning ⚠️
>
> The `tenant_id` parameter is a new configuration option. A period of backward compatibility is ensured: if this key is not defined,
> existing configurations will not be affected, and the default value will be `None`. However, if a value is provided, it will be
> validated by Pydantic and must conform to a valid UUID format, otherwise, a validation error will be returned.

### Base collector environment variables

Below are the parameters you'll need to set for running the collector properly:

| Parameter        | config.yml          | Docker environment variable | Default                                         | Mandatory | Description                                                                                   |
|------------------|---------------------|-----------------------------|-------------------------------------------------|-----------|-----------------------------------------------------------------------------------------------|
| Collector ID     | collector.id        | `COLLECTOR_ID`              | splunk-es--0b13e3f7-5c9e-46f5-acc4-33032e9b4921 | Yes       | A unique `UUIDv4` identifier for this collector instance.                                     |
| Collector Name   | collector.name      | `COLLECTOR_NAME`            | Splunk ES                                       | No        | Name of the collector.                                                                        |
| Collector Period | collector.period    | `COLLECTOR_PERIOD`          | PT1M                                            | No        | Collection interval (ISO 8601 format).                                                        |
| Log Level        | collector.log_level | `COLLECTOR_LOG_LEVEL`       | error                                           | No        | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.        |
| Platform         | collector.platform  | `COLLECTOR_PLATFORM`        | SIEM                                            | No        | Type of security platform this collector works for. One of: `EDR, XDR, SIEM, SOAR, NDR, ISPM` |

### Collector extra parameters environment variables

Below are the parameters you'll need to set for the collector:

| Parameter    | config.yml             | Docker environment variable | Default                 | Mandatory | Description                                                                             |
|--------------|------------------------|-----------------------------|-------------------------|-----------|-----------------------------------------------------------------------------------------|
| Base URL     | splunk_es.base_url     | `SPLUNKES_BASE_URL`         | https://localhost:8089  | Yes       | Splunk ES Management URL (typically port 8089 for REST API)                             |
| Username     | splunk_es.username     | `SPLUNKES_USERNAME`         |                         | Yes       | Splunk username with search permissions                                                 |
| Password     | splunk_es.password     | `SPLUNKES_PASSWORD`         |                         | Yes       | Splunk user password                                                                    |
| Alerts Index | splunk_es.alerts_index | `SPLUNKES_ALERTS_INDEX`     | main                    | No        | Splunk index to search for security alerts                                              |
| Time Window  | splunk_es.time_window  | `SPLUNKES_TIME_WINDOW`      | PT1H                    | No        | Default search time window when no date signatures are provided (ISO 8601 format)       |
| Offset       | splunk_es.offset       | `SPLUNKES_OFFSET`           | PT30S                   | No        | Delay between retry attempts to account for alert ingestion latency (ISO 8601 format)   |
| Max Retry    | splunk_es.max_retry    | `SPLUNKES_MAX_RETRY`        | 3                       | No        | Maximum number of retry attempts after the initial API call fails or returns no results |
| Query        | splunk_es.query_template | `SPLUNKES_QUERY_TEMPLATE`   | *(see below)*           | No        | Custom SPL query template with placeholders (leave empty for default)                   |

### Query Customization

The `SPLUNKES_QUERY_TEMPLATE` field allows you to customize the SPL query used to fetch security alerts from Splunk ES. The query supports **placeholders** that are resolved at runtime:

| Placeholder | Description | Example resolved value |
|---|---|---|
| `{alerts_index}` | The configured Splunk index (`SPLUNKES_ALERTS_INDEX`) | `main` |
| `{source_ips}` | Source IP values quoted for Splunk IN operator | `"10.0.0.1","10.0.0.2"` |
| `{target_ips}` | Target IP values quoted for Splunk IN operator | `"192.168.1.1"` |
| `{implant_urls}` | Implant callback URL paths quoted for Splunk IN operator | `"/oaev-implant-a1b2c3d4-agent-e5f6a7b8/callback"` |
| `{implant_names}` | Implant process names quoted for Splunk IN operator | `"oaev-implant-a1b2c3d4-agent-e5f6a7b8"` |
| `{start_date}` | Start date from signatures, or relative time fallback | `2026-06-12T08:00:00Z` or `-3600s` |
| `{end_date}` | End date from signatures, or `now` fallback | `2026-06-12T09:00:00Z` or `now` |
| `{process_conditions}` | Legacy: auto-generated URL path / process filter | `(url_path=*uuid* ...)` |
| `{ip_conditions}` | Legacy: auto-generated IP filter (source + destination) | `(src_ip=10.0.0.1 OR src=10.0.0.1 ...)` |
| `{time_window}` | Legacy: computed earliest time in seconds | `3600` |

**Default query template:**
```spl
index={alerts_index} (src_ip IN ({source_ips}) OR src IN ({source_ips}) OR source_ip IN ({source_ips}) OR client_ip IN ({source_ips})) (dst_ip IN ({target_ips}) OR dest IN ({target_ips}) OR dest_ip IN ({target_ips}) OR destination_ip IN ({target_ips}) OR server_ip IN ({target_ips})) (url_path IN ({implant_urls}) OR url IN ({implant_urls}) OR path IN ({implant_urls}) OR query IN ({implant_urls}) OR process_name IN ({implant_names}) OR parent_process_name IN ({implant_names})) earliest={start_date} latest={end_date} | table _time, src_ip, src, source_ip, client_ip, dst_ip, dest, dest_ip, destination_ip, server_ip, signature, rule_name, event_type, severity, url_path, url, path, query, process_name, parent_process_name, _raw | sort -_time
```

> ⚠️ **Important**: The query **must** include `| table _time` for proper alert parsing. Required fields for detection matching: `_time`, `src_ip`, `dst_ip`, `signature`, `rule_name`, `severity`.

**Example — resolved query with real values:**

Given an exercise with source IP `10.0.0.5`, target IP `192.168.1.100`, and an implant named `oaev-implant-a1b2c3d4-agent-e5f6a7b8`, the default template resolves to:

```spl
index=notable (src_ip IN ("10.0.0.5") OR src IN ("10.0.0.5") OR source_ip IN ("10.0.0.5") OR client_ip IN ("10.0.0.5")) (dst_ip IN ("192.168.1.100") OR dest IN ("192.168.1.100") OR dest_ip IN ("192.168.1.100") OR destination_ip IN ("192.168.1.100") OR server_ip IN ("192.168.1.100")) (url_path IN ("/oaev-implant-a1b2c3d4-agent-e5f6a7b8/callback") OR url IN ("/oaev-implant-a1b2c3d4-agent-e5f6a7b8/callback") OR path IN ("/oaev-implant-a1b2c3d4-agent-e5f6a7b8/callback") OR query IN ("/oaev-implant-a1b2c3d4-agent-e5f6a7b8/callback") OR process_name IN ("oaev-implant-a1b2c3d4-agent-e5f6a7b8") OR parent_process_name IN ("oaev-implant-a1b2c3d4-agent-e5f6a7b8")) earliest=2026-06-12T08:00:00Z latest=2026-06-12T09:00:00Z | table _time, src_ip, src, source_ip, client_ip, dst_ip, dest, dest_ip, destination_ip, server_ip, signature, rule_name, event_type, severity, url_path, url, path, query, process_name, parent_process_name, _raw | sort -_time
```

**Example — adding a sourcetype filter:**
```spl
index={alerts_index} sourcetype=notable (src_ip IN ({source_ips}) OR src IN ({source_ips})) (dst_ip IN ({target_ips}) OR dest IN ({target_ips})) (url_path IN ({implant_urls}) OR process_name IN ({implant_names}) OR parent_process_name IN ({implant_names})) earliest={start_date} latest={end_date} | table _time, src_ip, src, source_ip, client_ip, dst_ip, dest, dest_ip, destination_ip, server_ip, signature, rule_name, event_type, severity, url_path, url, path, query, process_name, parent_process_name, _raw | sort -_time
```

### Example Configuration Files

#### YAML Configuration (`src/config.yml`)
```yaml
openaev:
  url: "https://your-openaev-instance.com"
  token: "your-openaev-token"
# tenant_id: "your-openaev-tenant-id"
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
export OPENAEV_TENANT_ID="your-openaev-tenant-id"
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
