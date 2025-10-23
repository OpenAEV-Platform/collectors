# OpenAEV SentinelOne Collector

A SentinelOne EDR integration for OpenAEV that validates security expectations by querying SentinelOne's Deep Visibility and Threats APIs.

**Note**: Requires access to a SentinelOne Management Console with appropriate API permissions.

## Overview

This collector validates OpenAEV expectations by querying your SentinelOne environment for threat data via the SentinelOne API. When OpenAEV runs security exercises, this collector automatically checks if the expected security threats were detected in your EDR by matching threat information and associated events, providing visibility into your detection capabilities.

The collector uses SentinelOne's Threats API to fetch threat data and correlates it with threat events to validate expectations.

## Features

- **Threat-Based Validation**: Queries SentinelOne Threats API to validate security expectations against detected threats
- **Batch Processing**: Processes expectations in configurable batches for improved performance
- **Event Correlation**: Correlates threat data with threat events to extract process execution details
- **Trace Generation**: Creates detailed traces with links back to SentinelOne console
- **Flexible Configuration**: Support for YAML, environment variables, and multiple deployment scenarios

## Requirements

- OpenAEV Platform
- SentinelOne Management Console with API access
- Python 3.12+ (for manual deployment)
- SentinelOne API token with Threats and Threat Events permissions

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

- **`parent_process_name`**: Process names to match against threat event data
- **`target_hostname_address`**: Target hostnames to filter threat queries
- **`end_date`**: End time for the threat search query (ISO 8601 format)

### Processing Flow

1. **Expectation Retrieval**: Fetches pending expectations from OpenAEV
2. **Batch Creation**: Groups expectations into configurable batches for processing
3. **Time Window Determination**: Extracts time windows from expectations or uses default configuration
4. **Threat Fetching**: Queries SentinelOne Threats API for the determined time window
5. **Event Correlation**: Fetches threat events for each identified threat
6. **Expectation Matching**: Matches threat data and events against expectation criteria using detection helper
7. **Result Reporting**: Updates expectation status in OpenAEV
8. **Trace Creation**: Creates detailed traces linking back to SentinelOne console

### Threat Matching Logic

The collector validates expectations by:

1. **Threat Data Conversion**: Converts SentinelOne threat objects to OpenAEV-compatible format
2. **Process Name Extraction**: Extracts parent process names from threat events, focusing on `oaev-implant-*` prefixed processes
3. **Signature Matching**: Uses OpenAEV detection helper to match extracted data against expectation signatures
4. **Static vs Dynamic Threats**: Handles both static threat indicators and dynamic threats with associated events

### Batch Processing

The collector implements efficient batch processing to handle large volumes of expectations:

1. **Configurable Batch Size**: Processes expectations in batches based on `expectation_batch_size` configuration
2. **Time Window Optimization**: Extracts and consolidates time windows across batch expectations
3. **Bulk Threat Fetching**: Fetches threats for the entire time window rather than individual queries
4. **Parallel Event Processing**: Efficiently correlates threat events across the batch

## API Requirements

### SentinelOne API Permissions

Your SentinelOne API token requires the following permissions:

- **Threats**: Read access to query threat information
- **Threat Events**: Read access to retrieve threat event details
- **Console Access**: General API access to the Management Console

### API Endpoints Used

- `GET /web/api/v2.1/threats`: Query threat information using time-based filters
- `GET /web/api/v2.1/threat-events`: Retrieve detailed threat event information

### Rate Limiting

The collector respects SentinelOne's API rate limits by:
- Processing expectations in configurable batches
- Consolidating time windows to minimize API calls

## Troubleshooting

### Common Issues

#### No Threats Found
- **Symptom**: Collector reports no matching threats despite expecting them
- **Causes**:
  - Threat ingestion delay in SentinelOne
  - Incorrect process names or hostnames in expectations
  - Time window too narrow for threat detection
- **Solutions**:
  - Verify process names match threat event data
  - Extend `sentinelone.time_window` for broader searches

#### API Authentication Errors
- **Symptom**: HTTP 401/403 errors in logs
- **Causes**:
  - Invalid or expired API token
  - Insufficient API permissions
- **Solutions**:
  - Verify API token in SentinelOne console

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
- `[SentinelOneExpectationService]`: Batch expectation processing logic
- `[SentinelOneThreatFetcher]`: Threat data fetching operations
- `[SentinelOneThreatEventsFetcher]`: Threat events fetching operations
- `[CollectorExpectationManager]`: High-level processing flow
- `[SentinelOneTraceService]`: Trace creation and submission

### Performance Tuning

#### For High-Volume Environments
- Reduce `collector.period` for more frequent processing
- Increase `sentinelone.expectation_batch_size` for better throughput
- Monitor API rate limits and ingestion patterns in your environment

#### For Low-Latency Requirements
- Use shorter time windows in expectations for faster queries
- Reduce `collector.period` for more frequent collection cycles
- Monitor API rate limits and ingestion patterns accordingly

## Architecture

The collector uses a modular, service-provider architecture:

- **Collector Core**: Main daemon handling scheduling and coordination
- **Expectation Service**: Batch processing and threat correlation logic
- **Threat Fetcher**: Dedicated service for fetching threat data
- **Threat Events Fetcher**: Service for retrieving threat event details
- **Client API**: SentinelOne API communication layer
- **Trace Service**: Trace creation and submission
- **Configuration System**: Hierarchical configuration management

This architecture allows for easy extension and customization while maintaining clean separation of concerns.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding standards, and contribution guidelines.

## License

This project is licensed under the terms specified in the main OpenAEV project.
