# OpenAEV CrowdStrike Endpoint Security Collector

The CrowdStrike Endpoint Security collector.

## Prerequisites

**Note**: Requires subscription to the CrowdStrike Falcon platform. The subscription
details dictate what data is actually available to the collector.

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or
in `config.yml` (for manual deployment).

### OpenAEV environment variables

Below are the parameters you'll need to set for OpenAEV:

| Parameter     | config.yml    | Docker environment variable | Mandatory | Description                                          |
|---------------|---------------|-----------------------------|-----------|------------------------------------------------------|
| OpenAEV URL   | openaev.url   | `OPENAEV_URL`               | Yes       | The URL of the OpenAEV platform.                     |
| OpenAEV Token | openaev.token | `OPENAEV_TOKEN`             | Yes       | The default admin token set in the OpenAEV platform. |

### Base collector environment variables

Below are the parameters you'll need to set for running the collector properly:

| Parameter        | config.yml          | Docker environment variable | Default                       | Mandatory | Description                                                                                             |
|------------------|---------------------|-----------------------------|-------------------------------|-----------|---------------------------------------------------------------------------------------------------------|
| Collector ID     | collector.id        | `COLLECTOR_ID`              |                               | Yes       | A unique `UUIDv4` identifier for this collector instance.                                               |
| Collector Name   | collector.name      | `COLLECTOR_NAME`            | CrowdStrike Endpoint Security | No        | Name of the collector.                                                                                  |
| Collector Period | collector.period    | `COLLECTOR_PERIOD`          | PT1M                          | No        | The time interval at which your collector will run (ISO 8601 period expression, e.g. 'PT1M': 1 minute). |
| Log Level        | collector.log_level | `COLLECTOR_LOG_LEVEL`       | warn                          | No        | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.                  |
| Platform         | collector.platform  | `COLLECTOR_PLATFORM`        | EDR                           | No        | Type of security platform this collector works for. One of: `EDR, XDR, SIEM, SOAR, NDR, ISPM`           |

### Collector extra parameters environment variables

Below are the parameters you'll need to set for the collector:

**Note**: the Crowdstrike credentials must have been granted the following privilege for this to work: `Alerts: Read and Write`
(as per https://falcon.us-2.crowdstrike.com/documentation/page/d02475a5/converting-from-detects-api-to-alerts-api#s4c83596)

| Parameter     | config.yml                | Docker environment variable | Default                               | Mandatory | Description                                                     |
|---------------|---------------------------|-----------------------------|---------------------------------------|-----------|-----------------------------------------------------------------|
| API Base URL  | crowdstrike.api_base_url  | `CROWDSTRIKE_API_BASE_URL`  | `https://api.us-2.crowdstrike.com`    | No        | The base URL for the CrowdStrike APIs.                          |
| UI Base URL   | crowdstrike.ui_base_url   | `CROWDSTRIKE_UI_BASE_URL`   | `https://falcon.us-2.crowdstrike.com` | No        | The base URL for the CrowdStrike UI you use to see your alerts. |
| Client ID     | crowdstrike.client_id     | `CROWDSTRIKE_CLIENT_ID`     |                                       | Yes       | The CrowdStrike API client ID.                                  |
| Client Secret | crowdstrike.client_secret | `CROWDSTRIKE_CLIENT_SECRET` |                                       | Yes       | The CrowdStrike API client secret.                              |

## Deployment

### Docker Deployment

Build a Docker Image using the provided `Dockerfile`.

Example:

```shell
# Replace the IMAGE NAME with the appropriate value
docker build . -t [IMAGE NAME]
```

Make sure to replace the environment variables in `docker-compose.yml` with the appropriate configurations for your
environment. Then, start the docker container with the provided docker-compose.yml

```shell
docker compose up -d
# -d for detached
```

### Manual deployment

Get a local copy
```commandline
git checkout https://github.com/OpenAEV-Platform/collectors
cd ./collectors/crowdstrike
```
Install the environment:
**Production**:
```shell
# production environment
poetry install --extras prod
```

**Development** (note that you should also clone the [pyoaev](OpenAEV-Platform/client-python) repository [according to
these instructions](../README.md#simultaneous-development-on-pyoaev-and-a-collector))
```shell
# development environment
poetry install --extras dev
```

## Usage
```commandline
poetry run python -m crowdstrike.openaev_crowdstrike
```

## Behavior

The collector retrieves recent alerts (last 45 minutes) from Crowdstrike and matches them with attacks executed
by OpenAEV agents to validate prevention and detection expectations.

## Development

### Run the tests
In a terminal:
```commandline
cd collectors/crowdstrike
poetry run python -m unittest
```
