# OpenAEV Microsoft Defender for Office 365 Collector

A collector for OpenAEV that collects and matches Microsoft Defender for Office 365 (email-focused) alerts, based on a split between a generic base collector (under `src/collector`) and a custom source (under `src/source`). The premade elements provided by the generic base collector should be enough for basic collector development. Yet, thanks to various models, protocols and alternative implementations, the generic elements can be customized, expanded and/or overwritten for more complex collectors.

## Overview

This collector collects Microsoft Defender for Office 365 alerts (email-focused, MVP1) and matches them against OpenAEV expectations.

For a basic collector, the work required should be limited to :
1. rewriting files under `src/source` to fit your needs
2. replacing `src/template_collector.py` with your own, feeding your source into a generic collector
3. updating the import made in `src/__main__.py` (according to your file's name from point number 2)

Under `src/source` the minimal expectations are the following:
- a data fetcher object following the `DataFetcherProtocol` (e.g. `src/source/template_data_fetcher.py`)
- a source data object following the `SourceDataProtocol` (e.g. `src/source/template_source_data.py`)
- a list of supported signature types (e.g. `src/source/template_signatures.py`)
A source (from `src/collector/models/source.py`) will be built from those three elements in the `src/templateçcollector.py` (from point number 2 in the list earlier). Protocols can be found under `src/collector/protocols/` for more details.

As of now, outside of `src/collector` (generic) and `src/source` (custom) there is still a mixed codebase of generic and custom elements under `src/models/settings`. In order to forward custom parameters to your source elements, the `src/models/source_configs.py` is available. Note that elements added to `source_configs.py` must be reflected in `config_loader.py` too.

Your custom configuration will be propagated through the source handler to the `__init__.py` of you data fetcher object as a `source_config` parameter. From there, it can be used at your convenience.

Do not hesitate to check the `CONTRIBUTING.md` for more details regarding the collector design and help regarding development setup.

## Features

- **Clean Split**: Clear distinction between the generic collector and the custom source
- **Highly Customizable**: Alternative engines, source handler injection, base models and protocols for source
- **Opt-in Batch Processing**: Processes expectations in configurable batches for improved performance
- **Trace Generation**: Creates detailed traces with links back if available
- **Resilient Uploader**: Provides a resilient uploader for results and traces upload into OpenAEV
- **Flexible Configuration**: Support for YAML, environment variables, and multiple deployment scenarios

## Requirements

- OpenAEV Platform
- Python 3.11+

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
| OpenAEV URL       | `openaev.url`       | `OPENAEV_URL`                   | Yes       | The URL of the OpenAEV platform.                    |
| OpenAEV Token     | `openaev.token`     | `OPENAEV_TOKEN`                 | Yes       | The default admin token set in the OpenAEV platform.|
| OpenAEV Tenant ID | `openaev.tenant_id` | `OPENAEV_TENANT_ID`             | No        | Tenant identifier for multi-tenant deployments. When set, it must be a valid UUID.|

### Base collector environment variables

Below are the parameters you'll need to set for running the collector properly:

| Parameter        | config.yml          | Docker environment variable | Default                 | Mandatory | Description                                                                                   |
|------------------|---------------------|-----------------------------|-------------------------|-----------|-----------------------------------------------------------------------------------------------|
| Collector ID     | `collector.id`            | `COLLECTOR_ID`              | microsoft-defender-o365--0b13e3f7-5c9e-46f5-acc4-33032e9b4921 | Yes       | A unique `UUIDv4` identifier for this collector instance.                                     |
| Collector Name   | `collector.name`          | `COLLECTOR_NAME`            | Microsoft Defender for Office 365 | No        | Name of the collector.                                                                        |
| Collector Period | `collector.period`        | `COLLECTOR_PERIOD`          | PT2M                    | No        | Collection interval (ISO 8601 format).                                                       |
| Log Level        | `collector.log_level`     | `COLLECTOR_LOG_LEVEL`       | error                   | No        | Determines the verbosity of the logs. Options are `debug`, `info`, `warning`, `error` or `critical`.    |
| Platform         | `collector.platform`      | `COLLECTOR_PLATFORM`        | EDR                     | No        | Type of security platform this collector works for. One of: `EDR, XDR, SIEM, SOAR, NDR, ISPM` |
| Icon Filepath    | `collector.icon_filepath` | `COLLECTOR_ICON_FILEPATH`   | src/img/microsoft-defender-o365-logo.png | No        | Path to the icon file of the collector.                                           |

### Collector extra parameters environment variables

Below are the parameters you'll need to set for the collector:

| Parameter                          | config.yml                                     | Docker environment variable                             | Default                             | Mandatory | Description                                                                                     |
|-------------------------------------|-------------------------------------------------|-----------------------------------------------------------|--------------------------------------|-----------|---------------------------------------------------------------------------------------------------|
| Tenant ID                           | `source.tenant_id`                              | `SOURCE_TENANT_ID`                        | -                                     | Yes       | Azure AD (Entra ID) tenant identifier used to authenticate against Microsoft Graph.                |
| Client ID                           | `source.client_id`                              | `SOURCE_CLIENT_ID`                        | -                                     | Yes       | Azure AD application (client) identifier used to authenticate against Microsoft Graph.             |
| Use Certificate Auth                | `source.use_certificate_auth`                   | `SOURCE_USE_CERTIFICATE_AUTH`             | false                                 | No        | Whether to authenticate using a client certificate instead of a client secret.                     |
| Client Secret                       | `source.client_secret`                          | `SOURCE_CLIENT_SECRET`                    | -                                     | Yes, unless certificate auth is used | Azure AD application client secret.                                       |
| Client Certificate Path             | `source.client_cert_path`                       | `SOURCE_CLIENT_CERT_PATH`                 | -                                     | Yes, if certificate auth is used | Filesystem path to the client certificate.                                     |
| Client Certificate Thumbprint       | `source.client_cert_thumbprint`                 | `SOURCE_CLIENT_CERT_THUMBPRINT`           | -                                     | Yes, if certificate auth is used | Thumbprint of the client certificate.                                          |
| Base URL                            | `source.base_url`                               | `SOURCE_BASE_URL`                         | https://graph.microsoft.com/v1.0     | No        | Base URL for the Microsoft Graph API.                                                              |
| Filter Service Source               | `source.filter_service_source`                  | `SOURCE_FILTER_SERVICE_SOURCE`            | microsoftDefenderForOffice365        | No        | Value used to filter Microsoft Graph security alerts down to those produced by Microsoft Defender for Office 365. |
| Rate Limit (requests per minute)    | `source.rate_limit_requests_per_minute`         | `SOURCE_RATE_LIMIT_REQUESTS_PER_MINUTE`   | 150                                   | No        | Maximum number of Microsoft Graph API requests issued per minute (must be >= 1).                   |
| Max Fetch Retries                   | `source.max_fetch_retries`                      | `SOURCE_MAX_FETCH_RETRIES`                | 5                                     | No        | Maximum number of retries when fetching data from Microsoft Graph fails transiently.                |

*Nota bene*: exactly one authentication mode must be fully configured: either `use_certificate_auth=false` with `client_secret` set, or `use_certificate_auth=true` with both `client_cert_path` and `client_cert_thumbprint` set.

### Example Configuration Files

#### YAML Configuration (`src/config.yml`)
```yaml
openaev:
  url: "https://your-openaev-instance.com"
  token: "your-openaev-token"

collector:
  id: "microsoft-defender-o365--your-unique-uuid"
  name: "Microsoft Defender for Office 365 Production"
  period: "PT10M"
  log_level: "info"

source:
  tenant_id: "your-tenant-id"
  client_id: "your-client-id"
  client_secret: "your-client-secret"
  base_url: "https://graph.microsoft.com/v1.0"
  filter_service_source: "microsoftDefenderForOffice365"
  rate_limit_requests_per_minute: 150
  max_fetch_retries: 5
```

#### Environment Variables
```bash
export OPENAEV_URL="https://your-openaev-instance.com"
export OPENAEV_TOKEN="your-openaev-token"
export COLLECTOR_ID="microsoft-defender-o365--your-unique-uuid"
export SOURCE_TENANT_ID="your-tenant-id"
export SOURCE_CLIENT_ID="your-client-id"
export SOURCE_CLIENT_SECRET="your-client-secret"
```

## Deployment

### Manual Deployment with Poetry

1. **Clone and Install Dependencies**:
   ```bash
   git clone <repository-url>
   cd microsoft-defender-o365
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
   MicrosoftDefenderO365Collector
   ```

### Docker Deployment

```bash
# Build the container
docker build -t openaev-microsoft-defender-o365-collector .

# Run with environment variables
docker run -d \
  -e OPENAEV_URL="https://your-openaev-instance.com" \
  -e OPENAEV_TOKEN="your-token" \
  -e COLLECTOR_ID="microsoft-defender-o365--your-uuid" \
  -e SOURCE_TENANT_ID="your-tenant-id" \
  -e SOURCE_CLIENT_ID="your-client-id" \
  -e SOURCE_CLIENT_SECRET="your-client-secret" \
  openaev-microsoft-defender-o365-collector

# Or run with configuration file mounted
docker run -d \
  -v /path/to/config.yml:/app/src/config.yml:ro \
  openaev-microsoft-defender-o365-collector
```

## Behavior

### Supported Signature Types

The collector supports the following OpenAEV signature types:
- **change_me**: detail of the supported signature

### Link between collector, engine and source handler

1. **Start from the daemon**: The `BaseCollector` is the foundation, inheriting from `CollectorDaemon`
2. **Provide an engine to the collector**: A `CollectorEngine` is attached to the `BaseCollector` (by default the `BasicCollectorEngine`)
3. **Provide a source handler to the engine**: Through the `BaseCollector` a `SourceHandler` is provided to the `CollectorEngine`
4. **Setup and start the engine**: The `BaseCollector` will setup and start the `CollectorEngine`
5. **Use the source handler through the engine**: While processing, the `CollectorEngine` will rely on the `SourceHandler` to operate elements from the `Source`

### Processing Flow

1. **Fetch and filter the expectations**: Fetches pending expectations from OpenAEV and filter them according to handled expectation types
2. **If enabled, split expectations in batches**: Groups expectations into configurable batches for processing
3. **Fetch data**: Fetch data using the source handler to call the data fetcher
4. **Match data and signature types**: Match fetched data with supported signature types
5. **Match data and expectations**: Match fetched data with expectation using the OAEV detection helper
6. **Create and upload results**: Update expectation status in OpenAEV
7. **Create and upload traces**: Creates detailed traces OpenAEV-side

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
- `[MicrosoftDefenderO365ExpectationService]`: Batch expectation processing logic
- `[MicrosoftDefenderO365DataFetcher]`: Data fetching operations
- `[CollectorExpectationManager]`: High-level processing flow
- `[MicrosoftDefenderO365TraceService]`: Trace creation and submission

### Performance Tuning

#### For High-Volume Environments
- Reduce `collector.period` for more frequent processing
- Increase `source.rate_limit_requests_per_minute` for higher Microsoft Graph API throughput

#### For Low-Latency Requirements
- Use shorter time windows in expectations for faster queries
- Reduce `collector.period` for more frequent collection cycles

## Architecture

The collector is based on a split between a generic base collector, seen as a data processing unit, and a custom source of data. The main architectural elements are the following:
- **BaseCollector**: Main daemon handling scheduling and engine management
- **CollectorEngine**: Generic expectation processing engine dispatching and matching the various relevant data
- **Source**: Container made of a data fetcher, a source data format and the associated signatures
- **SourceHandler**: Wrapper provided to the collector engine to interact with the custom service
- **Configuration System**: Hierarchical configuration management

This architecture allows for easy extension and customization while maintaining clean separation of concerns.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding standards, and contribution guidelines.

## License

This project is licensed under the terms specified in the main OpenAEV project.
