# OpenAEV Template Collector

A template for OpenAEV collector built from late-2025/early-2026 collectors (e.g. SentinelOne). Provides a modular approach to collector development based on a service-provider architecture with `Protocol` based interfaces for advanced customisation.

## Overview

This collector is not meant to be used directly in OpenAEV but as a first support for collector development. Please update this README.md with the relevant elements to describe your collector.

The codebase to adapt to your specific needs can be found under `src/services/`, by replacing reference to the abstract TemplateData with your specific objects, updating the DataFetcher and the various services according to this custom object and your specific needs (keywords such as data and template can be used to help parsing the generic code that should be customized).

Once `src/services/` updated, the imports must be updated in `src/collector/collector.py`. Finally, new configuration parameters for your collector should be integrated under the `src/models/configs/` folder, replacing the `template_configs.py` file with yours.

Do not hesitate to check the `CONTRIBUTING.md` for more details regarding the collector design and help regarding development setup.

## Features

- **Batch Processing**: Processes expectations in configurable batches for improved performance
- **Trace Generation**: Creates detailed traces with links back if available
- **Flexible Configuration**: Support for YAML, environment variables, and multiple deployment scenarios

## Requirements

- OpenAEV Platform
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
| Collector ID     | collector.id        | `COLLECTOR_ID`              | template--0b13e3f7-5c9e-46f5-acc4-33032e9b4921 | Yes       | A unique `UUIDv4` identifier for this collector instance.                                     |
| Collector Name   | collector.name      | `COLLECTOR_NAME`            | Template             | No        | Name of the collector.                                                                        |
| Collector Period | collector.period    | `COLLECTOR_PERIOD`          | PT2M                    | No        | Collection interval (ISO 8601 format).                                                       |
| Log Level        | collector.log_level | `COLLECTOR_LOG_LEVEL`       | error                   | No        | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.      |
| Platform         | collector.platform  | `COLLECTOR_PLATFORM`        | EDR                     | No        | Type of security platform this collector works for. One of: `EDR, XDR, SIEM, SOAR, NDR, ISPM` |
| Icon Filepath    | collector.icon_filepath | `COLLECTOR_ICON_FILEPATH` | src/img/template-logo.png | No        | Path to the icon file of the collector.                                           |

### Collector extra parameters environment variables

Below are the parameters you'll need to set for the collector:

| Parameter                | config.yml                           | Docker environment variable            | Default                     | Mandatory | Description                                                                                        |
|--------------------------|--------------------------------------|----------------------------------------|-----------------------------|-----------|----------------------------------------------------------------------------------------------------|
| Base URL                 | template.key                 | `TEMPLATE_KEY`                 |value| No        | Template example key value                                                                 |
| Time Window              | template.time_window              | `TEMPLATE_TIME_WINDOW`              | PT1H                        | No        | Default search time window when no date signatures are provided (ISO 8601 format)                |
| Expectation Batch Size   | template.expectation_batch_size   | `TEMPLATE_EXPECTATION_BATCH_SIZE`   | 50                          | No        | Number of expectations to process in each batch for batch-based processing                         |

### Example Configuration Files

#### YAML Configuration (`src/config.yml`)
```yaml
openaev:
  url: "https://your-openaev-instance.com"
  token: "your-openaev-token"

collector:
  id: "template--your-unique-uuid"
  name: "Template Production"
  period: "PT10M"
  log_level: "info"

template:
  key: "your-value"
  time_window: "PT1H"
  expectation_batch_size: 50
```

#### Environment Variables
```bash
export OPENAEV_URL="https://your-openaev-instance.com"
export OPENAEV_TOKEN="your-openaev-token"
export COLLECTOR_ID="template--your-unique-uuid"
export TEMPLATE_KEY="value"
```

## Deployment

### Manual Deployment with Poetry

1. **Clone and Install Dependencies**:
   ```bash
   git clone <repository-url>
   cd template
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
   TemplateCollector
   ```

### Docker Deployment

```bash
# Build the container
docker build -t openaev-template-collector .

# Run with environment variables
docker run -d \
  -e OPENAEV_URL="https://your-openaev-instance.com" \
  -e OPENAEV_TOKEN="your-token" \
  -e COLLECTOR_ID="template--your-uuid" \
  -e TEMPLATE_KEY="your-value" \
  openaev-template-collector

# Or run with configuration file mounted
docker run -d \
  -v /path/to/config.yml:/app/src/config.yml:ro \
  openaev-template-collector
```

## Behavior

### Supported Signature Types

The collector supports the following OpenAEV signature types:
- **change_me**: detail of the supported signature

### Processing Flow

1. **Expectation Retrieval**: Fetches pending expectations from OpenAEV
2. **Batch Creation**: Groups expectations into configurable batches for processing
3. **Time Window Determination**: Extracts time windows from expectations or uses default configuration
4. **Data Fetching**: Fetch data for the determined time window
6. **Expectation Matching**: Matches data against expectation criteria using detection helper
7. **Result Reporting**: Updates expectation status in OpenAEV
8. **Trace Creation**: Creates detailed traces

### Batch Processing

The collector implements efficient batch processing to handle large volumes of expectations:

1. **Configurable Batch Size**: Processes expectations in batches based on `expectation_batch_size` configuration
2. **Time Window Optimization**: Extracts and consolidates time windows across batch expectations
3. **Bulk Data Fetching**: Fetches data for the entire time window rather than individual queries

## Troubleshooting

### Common Issues

#### Type of common issue
- **Symptom**: main symptom for this common issue
- **Causes**:
  - common cause for this issue (1)
  - common cause for this issue (2)
- **Solutions**:
  - solution(s)

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
- `[TemplateExpectationService]`: Batch expectation processing logic
- `[TemplateDataFetcher]`: Data fetching operations
- `[CollectorExpectationManager]`: High-level processing flow
- `[TemplateTraceService]`: Trace creation and submission

### Performance Tuning

#### For High-Volume Environments
- Reduce `collector.period` for more frequent processing
- Increase `template.expectation_batch_size` for better throughput

#### For Low-Latency Requirements
- Use shorter time windows in expectations for faster queries
- Reduce `collector.period` for more frequent collection cycles

## Architecture

The collector uses a modular, service-provider architecture:

- **Collector Core**: Main daemon handling scheduling and coordination
- **Expectation Service**: Batch processing and data correlation logic
- **Data Fetcher**: Dedicated service for fetching data
- **Trace Service**: Trace creation and submission
- **Configuration System**: Hierarchical configuration management

This architecture allows for easy extension and customization while maintaining clean separation of concerns.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding standards, and contribution guidelines.

## License

This project is licensed under the terms specified in the main OpenAEV project.
