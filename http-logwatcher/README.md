# HTTP Logwatcher Collector

A collector monitoring the access and error logfiles of a nginx-like HTTP server for respectively specific successful or failed connections.

## Overview

This collector validates OpenAEV expectations by searching the `access.log` and `error.log` of a nginx-like HTTP server for a specific connection (according to its IP). A match in `access.log` is considered as *detected* while a match in `error.log` is considered as *prevented*.

## Limitations

Due to relying only on the source IP to match expectations, and thus the lack of an explicit discriminatory factor between successive requests from a single source, prevention expectation can be false-positive. To illustrate this, please refer to the table below describing the status of the expectations for two consecutive tests, with `test A` supposed to be detected-only and `test B` supposed to be detected and prevented.

| Step |  test A, detection expectation | test A, prevention expectation | test B, detection expectation | test B, prevention expectation |
|------|--------------------------------|--------------------------------|-------------------------------|--------------------------------|
| (starting point) | N/A | N/A | N/A | N/A |
| running test A in OAEV | X | N/A | N/A | N/A |
| running test B in OAEV | X | N/A | X | X |
| checking test A previous results in OAEV | X | X | X | X |

## Requirements

- OpenAEV platform
- Python 3.12+ for manual deployment
- Docker or an equivalent (e.g. Podman) for container deployment

## Configuration

### Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or in `config.yml` (for manual deployment).

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
| Collector ID     | collector.id        | `COLLECTOR_ID`              | http_logwatcher--0b13e3f7-5c9e-46f5-acc4-33032e9b4921 | Yes       | A unique `UUIDv4` identifier for this collector instance.                                     |
| Collector Name   | collector.name      | `COLLECTOR_NAME`            | HTTPLogwatcher          | No        | Name of the collector.                                                                        |
| Collector Period | collector.period    | `COLLECTOR_PERIOD`          | PT2M                    | No        | Collection interval (ISO 8601 format).                                                       |
| Log Level        | collector.log_level | `COLLECTOR_LOG_LEVEL`       | error                   | No        | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.      |
| Platform         | collector.platform  | `COLLECTOR_PLATFORM`        | EDR                     | No        | Type of security platform this collector works for. One of: `EDR, XDR, SIEM, SOAR, NDR, ISPM` |
| Icon Filepath    | collector.icon_filepath | `COLLECTOR_ICON_FILEPATH` | src/img/http-logwatcher-logo.png | No        | Path to the icon file of the collector.                                           |

### Collector extra parameters environment variables

Below are the parameters you'll need to set for the collector:

| Parameter                | config.yml                           | Docker environment variable            | Default                     | Mandatory | Description                                                                                        |
|--------------------------|--------------------------------------|----------------------------------------|-----------------------------|-----------|----------------------------------------------------------------------------------------------------|
| Logs folder path         | http_logwatcher.logs_folder_path         | `HTTP_LOGWATCHER_LOGS_FOLDER_PATH`     | /var/log/nginx/ | Yes     | Log folder full path                                                                 |
| Time Window              | http_logwatcher.time_window              | `HTTP_LOGWATCHER_TIME_WINDOW`              | PT1H                        | No        | Default search time window when no date signatures are provided (ISO 8601 format)                |

### Example Configuration Files

#### YAML Configuration (`src/config.yml`)
```yaml
openaev:
  url: "https://your-openaev-instance.com"
  token: "your-openaev-token"

collector:
  id: "http_logwatcher--your-unique-uuid"
  name: "HTTP Logwatcher Production"
  period: "PT10M"
  log_level: "info"

http_logwatcher:
  logs_folder_path: "/var/log/nginx/"
  time_window: "PT1H"
```

#### Environment Variables
```bash
export OPENAEV_URL="https://your-openaev-instance.com"
export OPENAEV_TOKEN="your-openaev-token"
export COLLECTOR_ID="http_logwatcher--your-unique-uuid"
export HTTP_LOGWATCHER_LOGS_FOLDER_PATH="/var/log/nginx/"
```

## Deployment

### Manual Deployment with Poetry

1. **Clone and Install Dependencies**:
   ```bash
   git clone <repository-url>
   cd http-logwatcher
   poetry install --extra local
   ```

2. **Configure the Collector**:
   - Copy `src/config.yml.sample` to `src/config.yml`
   - Update configuration values or set environment variables

3. **Run the Collector**:
   ```bash
   # Using Poetry
   poetry run python -m src

   # Or direct execution after installation
   HTTPLogwatcherCollector
   ```

### Docker Deployment

```bash
# Build the container
docker build -t openaev-http_logwatcher-collector .

# Run with environment variables
docker run -d \
  -e OPENAEV_URL="https://your-openaev-instance.com" \
  -e OPENAEV_TOKEN="your-token" \
  -e COLLECTOR_ID="http_logwatcher--your-uuid" \
  -e HTTP_LOGWATCHER_LOGS_FOLDER_PATH="/var/log/nginx/" \
  openaev-http_logwatcher-collector

# Or run with configuration file mounted
docker run -d \
  -v /path/to/config.yml:/app/src/config.yml:ro \
  openaev-http_logwatcher-collector
```

**Nota bene**: using the container deployment, you may have to also bind the local logs folder to the container in order to give access to the files to the collector.


## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding standards, and contribution guidelines.

## License

This project is licensed under the terms specified in the main OpenAEV project.
