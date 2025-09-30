# OpenBAS Splunk Enterprise Security Collector

A Splunk Enterprise Security (ES) integration for OpenBAS that validates security expectations by querying Splunk ES for detection alerts and matching them against expected outcomes.

**Note**: Requires access to a Splunk Enterprise Security instance.

## Overview

This collector validates OpenBAS expectations by querying your Splunk ES environment for matching security alerts via the Splunk REST API. When OpenBAS runs security exercises, this collector automatically checks if the expected security threats were actually detected in your SIEM, providing visibility into your detection capabilities.

The collector uses Splunk's notable events and security alerts to validate detection expectations, with support for IP-based matching and parent process tracking through URL path analysis.

## Features

- **Detection Validation**: Queries Splunk ES notable events to verify security detections
- **IP-based Matching**: Supports both source and destination IPv4/IPv6 address matching
- **Parent Process Tracking**: Extracts and matches parent process names from URL paths
- **Retry Mechanism**: Built-in retry logic with configurable delays to handle alert ingestion latency
- **Trace Generation**: Creates detailed traces with links back to Splunk ES search results
- **Flexible Configuration**: Support for YAML, environment variables, and multiple deployment scenarios

## Requirements

- OpenBAS Platform
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

### OpenBAS environment variables

Below are the parameters you'll need to set for OpenBAS:

| Parameter     | config.yml    | Docker environment variable | Mandatory | Description                                          |
|---------------|---------------|-----------------------------|-----------|------------------------------------------------------|
| OpenBAS URL   | openbas.url   | `OPENBAS_URL`               | Yes       | The URL of the OpenBAS platform.                    |
| OpenBAS Token | openbas.token | `OPENBAS_TOKEN`             | Yes       | The default admin token set in the OpenBAS platform.|

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
openbas:
  url: "https://your-openbas-instance.com"
  token: "your-openbas-token"

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
export OPENBAS_URL="https://your-openbas-instance.com"
export OPENBAS_TOKEN="your-openbas-token"
export COLLECTOR_ID="splunk-es--your-unique-uuid"
export SPLUNKES_BASE_URL="https://your-splunk-es.company.com:8089"
export SPLUNKES_USERNAME="splunk-user"
export SPLUNKES_PASSWORD="your-splunk-password"
export SPLUNKES_ALERTS_INDEX="main"
```

## Deployment

### Manual Deployment with Poetry

1. **Clone and Install Dependencies**:
   ```bash
   git clone <repository-url>
   cd splunk-es
   poetry install -E current --with prod
   ```

2. **Configure the Collector**:
   - Copy `src/config.yml.sample` to `src/config.yml`
   - Update configuration values or set environment variables

3. **Run the Collector**:
   ```bash
   # Using Poetry
   poetry run python -m src

   # Or direct execution after installation
   SplunkESCollector
   ```

### Docker Deployment

```bash
# Build the container
docker build -t openbas-splunk-es-collector .

# Run with environment variables
docker run -d \
  -e OPENBAS_URL="https://your-openbas-instance.com" \
  -e OPENBAS_TOKEN="your-token" \
  -e COLLECTOR_ID="splunk-es--your-uuid" \
  -e SPLUNKES_BASE_URL="https://your-splunk-es.company.com:8089" \
  -e SPLUNKES_USERNAME="splunk-user" \
  -e SPLUNKES_PASSWORD="your-password" \
  openbas-splunk-es-collector

# Or run with configuration file mounted
docker run -d \
  -v /path/to/config.yml:/app/src/config.yml:ro \
  openbas-splunk-es-collector
```

## Behavior

### Supported Signature Types

The collector supports the following OpenBAS signature types:

- **`source_ipv4_address`**: Source IPv4 addresses to search for in Splunk ES alerts
- **`source_ipv6_address`**: Source IPv6 addresses to search for in Splunk ES alerts
- **`target_ipv4_address`**: Destination IPv4 addresses to search for in Splunk ES alerts
- **`target_ipv6_address`**: Destination IPv6 addresses to search for in Splunk ES alerts
- **`parent_process_name`**: Process names extracted from URL paths for matching
- **`start_date`**: Start time for the search query (ISO 8601 format)
- **`end_date`**: End time for the search query (ISO 8601 format)

### Processing Flow

1. **Expectation Retrieval**: Fetches pending expectations from OpenBAS
2. **Signature Extraction**: Extracts supported signature types from expectations
3. **SPL Query Generation**: Constructs Search Processing Language queries for Splunk ES
4. **Alert Search**: Executes searches against Splunk ES notable events index
5. **Data Conversion**: Converts Splunk ES alerts to OpenBAS-compatible format
6. **Expectation Validation**: Matches found data against expectation criteria using DetectionHelper
7. **Result Reporting**: Updates expectation status in OpenBAS
8. **Trace Creation**: Creates detailed traces linking back to Splunk ES search results

### Detection Logic

#### Detection Expectations
- Queries Splunk ES notable events using SPL (Search Processing Language)
- Supports IP-based matching with OR logic (any matching IP validates)
- Handles parent process matching through URL path extraction
- Combined logic: Parent process match AND (source IP match OR target IP match)

**Note**: This collector only supports Detection expectations. Prevention expectations are marked as invalid since Splunk ES is a detection-focused SIEM platform.

### Query Construction

The collector constructs sophisticated SPL queries like:

```spl
search index=main ((src_ip=192.168.1.100 OR dst_ip=10.0.0.50) AND (url_path="/api/injects/877b423b-ae91-4fc5-86c3-fa8ea3c938ba/1402422f-2eaa-4fbd-80b2-b30df1b83b19/executable-payload")) earliest=-3600s | table _time, src_ip, dst_ip, url_path, signature, rule_name | sort -_time
```

### Retry Mechanism

The collector implements intelligent retry logic to handle Splunk ES's alert ingestion delays:

1. **Initial Delay**: Waits for configured offset before first API call
2. **Progressive Retries**: Retries up to `max_retry` times with delays between attempts
3. **Dynamic Time Windows**: Extends search time windows on each retry to catch newly ingested alerts
4. **Graceful Degradation**: Returns available data even if some queries fail

## API Requirements

### Splunk ES API Permissions

Your Splunk user account requires the following permissions:

- **Search Access**: Ability to execute searches via REST API
- **Index Permissions**: Read access to the configured events index (typically `main`)
- **REST API Access**: General access to Splunk's REST endpoints

### API Endpoints Used

- `POST /services/search/jobs`: Execute SPL search queries
- **Search Mode**: Uses oneshot execution mode for immediate results
- **Output Format**: JSON format with configurable result limits

### Rate Limiting

The collector respects Splunk ES's performance considerations by:
- Implementing delays between API calls
- Using efficient SPL queries with appropriate time windows
- Providing configurable retry intervals
- Supporting SSL verification settings for enterprise deployments

## Troubleshooting

### Common Issues

#### No Alerts Found
- **Symptom**: Collector reports no matching alerts despite expecting them
- **Causes**:
  - Alert ingestion delay in Splunk ES
  - Incorrect IP addresses or process names in expectations
  - Time window too narrow
  - Wrong alerts index configured
- **Solutions**:
  - Increase `splunk_es.offset` configuration
  - Verify IP addresses and process names match Splunk ES data
  - Extend `splunk_es.time_window` for broader searches
  - Check `splunk_es.alerts_index` configuration

#### API Authentication Errors
- **Symptom**: HTTP 401 errors in logs
- **Causes**:
  - Invalid username/password combination
  - Insufficient search permissions
  - Account locked or disabled
- **Solutions**:
  - Verify credentials in Splunk ES web interface
  - Check user permissions for search and index access
  - Review account status in Splunk user management

#### Connection Timeouts
- **Symptom**: HTTP timeout errors or connection failures
- **Causes**:
  - Network connectivity issues
  - Splunk ES unavailability
  - Incorrect base URL or port
  - SSL certificate issues
- **Solutions**:
  - Verify network connectivity to Splunk ES
  - Check `splunk_es.base_url` configuration (typically port 8089)
  - Review firewall and proxy settings
  - Verify SSL certificate validity

#### SPL Query Errors
- **Symptom**: Search execution failures or syntax errors
- **Causes**:
  - Invalid SPL syntax generated by collector
  - Index permission issues
  - Field name mismatches
- **Solutions**:
  - Enable debug logging to view generated SPL queries
  - Test SPL queries manually in Splunk ES web interface
  - Verify field names exist in your Splunk ES data

### Logging

The collector provides comprehensive logging at multiple levels:

- **Error**: Critical failures and exceptions
- **Warn**: Recoverable issues and misconfigurations
- **Info**: Processing progress and results summary
- **Debug**: Detailed API interactions, SPL queries, and data processing

#### Log Configuration
```yaml
collector:
  log_level: "debug"  # For maximum verbosity during troubleshooting
```

#### Key Log Patterns
- `[SplunkESClientAPI]`: API communication, SPL queries, and responses
- `[SplunkESExpectationService]`: Expectation processing logic
- `[CollectorExpectationManager]`: High-level processing flow
- `[SplunkESTraceService]`: Trace creation and submission
- `[SplunkESConverter]`: Data format conversion

### Performance Tuning

#### For High-Volume Environments
- Reduce `collector.period` for more frequent processing
- Increase `splunk_es.max_retry` for better reliability
- Adjust `splunk_es.offset` based on your environment's alert ingestion patterns
- Use more specific search criteria to reduce query load

#### For Low-Latency Requirements
- Decrease `splunk_es.offset` to reduce processing delays
- Use shorter time windows in expectations for faster queries
- Monitor Splunk ES search performance and adjust retry intervals accordingly
- Consider index-time field extraction for better query performance

## Architecture

The collector uses a modular, service-provider architecture:

- **Collector Core**: Main daemon handling scheduling and coordination
- **Expectation Service**: Splunk ES-specific business logic and query generation
- **Client API**: Splunk ES REST API communication layer with SPL query construction
- **Converter**: Data transformation between Splunk ES and OpenBAS formats
- **Trace Service**: Trace creation with Splunk ES search links
- **Configuration System**: Hierarchical configuration management with Pydantic validation
- **Parent Process Parser**: Utility for extracting UUIDs from URL paths

This architecture allows for easy extension and customization while maintaining clean separation of concerns between generic collector functionality and Splunk ES-specific implementations.

## License

This project is licensed under the terms specified in the main OpenBAS project.
