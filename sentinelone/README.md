# OpenAEV SentinelOne Collector

A SentinelOne EDR integration for OpenAEV that validates security expectations by querying SentinelOne's Deep Visibility and Threats APIs.

**Note**: Requires access to a SentinelOne Management Console with appropriate API permissions.

## Overview

This collector validates OpenAEV expectations by querying your SentinelOne environment for matching security events via the SentinelOne API. When OpenAEV runs security exercises, this collector automatically checks if the expected security threats were actually detected and/or prevented in your EDR, providing visibility into your detection and prevention capabilities.

The collector uses SentinelOne's Deep Visibility events for detection validation and combines them with threat data for prevention validation.

## Features

- **Detection Validation**: Queries SentinelOne Deep Visibility events to verify process execution detections
- **Prevention Validation**: Combines Deep Visibility events with threat data to verify prevention actions
- **Retry Mechanism**: Built-in retry logic with configurable delays to handle event ingestion latency
- **Trace Generation**: Creates detailed traces with links back to SentinelOne console
- **Flexible Configuration**: Support for YAML, environment variables, and multiple deployment scenarios

## Requirements

- OpenAEV Platform
- SentinelOne Management Console with API access
- Python 3.12+ (for manual deployment)
- SentinelOne API token with appropriate permissions

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
| Collector ID     | collector.id        | `COLLECTOR_ID`              | sentinelone--0b13e3f7-5c9e-46f5-acc4-33032e9b4921 | Yes       | A unique `UUIDv4` identifier for this collector instance.                                     |
| Collector Name   | collector.name      | `COLLECTOR_NAME`            | SentinelOne             | No        | Name of the collector.                                                                        |
| Collector Period | collector.period    | `COLLECTOR_PERIOD`          | PT1M                    | No        | Collection interval (ISO 8601 format).                                                       |
| Log Level        | collector.log_level | `COLLECTOR_LOG_LEVEL`       | error                   | No        | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.      |
| Type             | collector.type      | `COLLECTOR_TYPE`            | openaev_sentinelone     | No        | Type of the collector                                                                         |
| Platform         | collector.platform  | `COLLECTOR_PLATFORM`        | EDR                     | No        | Type of security platform this collector works for. One of: `EDR, XDR, SIEM, SOAR, NDR, ISPM` |

### Collector extra parameters environment variables

Below are the parameters you'll need to set for the collector:

| Parameter         | config.yml                    | Docker environment variable | Default                     | Mandatory | Description                                                                                        |
|-------------------|-------------------------------|-----------------------------|-----------------------------|-----------|----------------------------------------------------------------------------------------------------|
| Base URL          | sentinelone.base_url          | `SENTINELONE_BASE_URL`      | https://api.sentinelone.com | No        | SentinelOne Management Console URL                                                                 |
| API Key           | sentinelone.api_key           | `SENTINELONE_API_KEY`       |                             | Yes       | SentinelOne API token with Deep Visibility and Threats permissions                                |
| Time Window       | sentinelone.time_window       | `SENTINELONE_TIME_WINDOW`   | PT1H                        | No        | Default search time window when no date signatures are provided (ISO 8601 format)                |
| Offset            | sentinelone.offset            | `SENTINELONE_OFFSET`        | PT1M                        | No        | Delay before API calls to account for event ingestion latency (ISO 8601 format)                  |
| Max Retry         | sentinelone.max_retry         | `SENTINELONE_MAX_RETRY`     | 5                           | No        | Maximum number of retry attempts after the initial API call fails or returns no results          |

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
  offset: "PT2M"
  max_retry: 3
```

#### Environment Variables
```bash
export OPENAEV_URL="https://your-openaev-instance.com"
export OPENAEV_TOKEN="your-openaev-token"
export COLLECTOR_ID="sentinelone--your-unique-uuid"
export SENTINELONE_BASE_URL="https://your-sentinelone-console.sentinelone.net"
export SENTINELONE_API_KEY="your-sentinelone-api-token"
```

## Deployment

### Manual Deployment with Poetry

1. **Clone and Install Dependencies**:
   ```bash
   git clone <repository-url>
   cd sentinelone
   poetry install -E current --with dev
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

## Behavior

### Supported Signature Types

The collector supports the following OpenAEV signature types:

- **`parent_process_name`**: Process names to search for in SentinelOne Deep Visibility
- **`start_date`**: Start time for the search query (ISO 8601 format)
- **`end_date`**: End time for the search query (ISO 8601 format)

### Processing Flow

1. **Expectation Retrieval**: Fetches pending expectations from OpenAEV
2. **Signature Extraction**: Extracts supported signature types from expectations
3. **Deep Visibility Query**: Searches SentinelOne for matching process execution events
4. **Threat Correlation**: For prevention expectations, correlates events with threat data
5. **Expectation Validation**: Matches found data against expectation criteria
6. **Result Reporting**: Updates expectation status in OpenAEV
7. **Trace Creation**: Creates detailed traces linking back to SentinelOne console

### Detection vs Prevention Logic

#### Detection Expectations
- Queries SentinelOne Deep Visibility for process execution events
- Matches against `parent_process_name` signatures
- Success indicates the process was detected by SentinelOne

#### Prevention Expectations
- Queries Deep Visibility events AND correlates with threat data
- Requires both process detection and associated threat information
- Success indicates the process was both detected and prevented

### Retry Mechanism

The collector implements intelligent retry logic to handle SentinelOne's event ingestion delays:

1. **Initial Delay**: Waits for configured offset before first API call
2. **Progressive Retries**: Retries up to `max_retry` times with delays between attempts
3. **Dynamic Time Windows**: Updates end times on each retry to catch newly ingested events
4. **Graceful Degradation**: Returns available data even if some queries fail

## API Requirements

### SentinelOne API Permissions

Your SentinelOne API token requires the following permissions:

- **Deep Visibility**: Read access to query process execution events
- **Threats**: Read access to correlate prevention data
- **Console Access**: General API access to the Management Console

### API Endpoints Used

- `POST /web/api/v2.1/dv/init-query`: Initialize Deep Visibility searches
- `GET /web/api/v2.1/dv/events`: Retrieve Deep Visibility events
- `GET /web/api/v2.1/threats`: Query threat information by content hash

### Rate Limiting

The collector respects SentinelOne's API rate limits by:
- Implementing delays between API calls
- Using batch processing where possible
- Providing configurable retry intervals

## Troubleshooting

### Common Issues

#### No Events Found
- **Symptom**: Collector reports no matching events despite expecting them
- **Causes**:
  - Event ingestion delay in SentinelOne
  - Incorrect process names in expectations
  - Time window too narrow
- **Solutions**:
  - Increase `sentinelone.offset` configuration
  - Verify process names match SentinelOne data
  - Extend `sentinelone.time_window` for broader searches

#### API Authentication Errors
- **Symptom**: HTTP 401/403 errors in logs
- **Causes**:
  - Invalid or expired API token
  - Insufficient API permissions
- **Solutions**:
  - Verify API token in SentinelOne console
  - Check token permissions for Deep Visibility and Threats

#### Connection Timeouts
- **Symptom**: HTTP timeout errors or connection failures
- **Causes**:
  - Network connectivity issues
  - SentinelOne console unavailability
  - Incorrect base URL
- **Solutions**:
  - Verify network connectivity to SentinelOne
  - Check `sentinelone.base_url` configuration
  - Review firewall and proxy settings

### Logging

The collector provides comprehensive logging at multiple levels:

- **Error**: Critical failures and exceptions
- **Warn**: Recoverable issues and misconfigurations
- **Info**: Processing progress and results summary
- **Debug**: Detailed API interactions and data processing

#### Log Configuration
```yaml
collector:
  log_level: "debug"  # For maximum verbosity during troubleshooting
```

#### Key Log Patterns
- `[SentinelOneClientAPI]`: API communication and responses
- `[SentinelOneExpectationService]`: Expectation processing logic
- `[CollectorExpectationManager]`: High-level processing flow
- `[SentinelOneTraceService]`: Trace creation and submission

### Performance Tuning

#### For High-Volume Environments
- Reduce `collector.period` for more frequent processing
- Increase `sentinelone.max_retry` for better reliability
- Adjust `sentinelone.offset` based on your environment's ingestion patterns

#### For Low-Latency Requirements
- Decrease `sentinelone.offset` to reduce processing delays
- Use shorter time windows in expectations for faster queries
- Monitor API rate limits and adjust retry intervals accordingly

## Architecture

The collector uses a modular, service-provider architecture:

- **Collector Core**: Main daemon handling scheduling and coordination
- **Expectation Service**: SentinelOne-specific business logic
- **Client API**: SentinelOne API communication layer
- **Trace Service**: Trace creation and submission
- **Configuration System**: Hierarchical configuration management

This architecture allows for easy extension and customization while maintaining clean separation of concerns.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding standards, and contribution guidelines.

## License

This project is licensed under the terms specified in the main OpenAEV project.
