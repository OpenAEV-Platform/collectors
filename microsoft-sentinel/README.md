# OpenAEV Microsoft Sentinel Collector

Table of Contents

- [OpenAEV Microsoft Sentinel Collector](#openaev-microsoft-sentinel-collector)
    - [Prerequisites](#prerequisites)
    - [Configuration variables](#configuration-variables)
        - [OpenAEV environment variables](#openaev-environment-variables)
        - [Base collector environment variables](#base-collector-environment-variables)
        - [Collector extra parameters environment variables](#collector-extra-parameters-environment-variables)
    - [Deployment](#deployment)
        - [Docker Deployment](#docker-deployment)
        - [Manual Deployment](#manual-deployment)
    - [Behavior](#behavior)

## Prerequisites

To use this collector, you need to create an application in your Azure portal with the following permissions:
**Log Analytics API > Data.Read**

This Sentinel collector works only if your Sentinel is powered by your Defender. To make it work, you also need to
activate the Defender collector.
Indeed, this relies on Defender matchings to validate Sentinel alerts.

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

| Parameter        | config.yml          | Docker environment variable   | Default                    | Mandatory | Description                                                                                   |
|------------------|---------------------|-------------------------------|----------------------------|-----------|-----------------------------------------------------------------------------------------------|
| Collector ID     | collector.id        | `COLLECTOR_ID`                |                            | Yes       | A unique `UUIDv4` identifier for this collector instance.                                     |
| Collector Name   | collector.name      | `COLLECTOR_NAME`              | Microsoft Sentinel         | No        | Name of the collector.                                                                        |
| Collector Period | collector.period    | `COLLECTOR_PERIOD`            | 60                         | No        | The time interval at which your collector will run (int, seconds).                            |
| Log Level        | collector.log_level | `COLLECTOR_LOG_LEVEL`         | warn                       | No        | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.        |
| Platform         | collector.platform  | `COLLECTOR_PLATFORM`          | SIEM                       | No        | Type of security platform this collector works for. One of: `EDR, XDR, SIEM, SOAR, NDR, ISPM` |

### Collector extra parameters environment variables

Below are the parameters you'll need to set for the collector:

| Parameter                 | config.yml                                   | Docker environment variable          | Default | Mandatory | Description                                                                  |
|---------------------------|----------------------------------------------|--------------------------------------|---------|-----------|------------------------------------------------------------------------------|
| Application Tenant ID     | collector.microsoft_sentinel_tenant_id       | `MICROSOFT_SENTINEL_TENANT_ID`       |         | Yes       |                                                                              |
| Application Client ID     | collector.microsoft_sentinel_client_id       | `MICROSOFT_SENTINEL_CLIENT_ID`       |         | Yes       |                                                                              |
| Application Client Secret | collector.microsoft_sentinel_client_secret   | `MICROSOFT_SENTINEL_CLIENT_SECRET`   |         | Yes       |                                                                              |
| Subscription ID           | collector.microsoft_sentinel_subscription_id | `MICROSOFT_SENTINEL_SUBSCRIPTION_ID` |         | Yes       |                                                                              |
| Workspace ID              | collector.microsoft_sentinel_workspace_id    | `MICROSOFT_SENTINEL_WORKSPACE_ID`    |         | Yes       |                                                                              |
| Resource group            | collector.microsoft_sentinel_resource_group  | `MICROSOFT_SENTINEL_RESOURCE_GROUP`  |         | Yes       |                                                                              |
| UUID linked collectors    | collector.microsoft_sentinel_edr_collectors  | `MICROSOFT_SENTINEL_EDR_COLLECTORS`  |         | Yes       | The list of collector UUIDs is sourced from the EDR collectors' deployments. |

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

### Manual Deployment

Create a file `config.yml` based on the provided `config.yml.sample`.

Replace the configuration variables with the appropriate configurations for
you environment.

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

Then, start the collector:

```shell
poetry run python -m microsoft_sentinel.openaev_microsoft_sentinel
```

## Behavior

By searching in your tool's logs and based on connected EDRs for recent alerts (last 45 minutes), the collector tries to
match the attack launched with the
logs reported in your SIEM and validate prevention or expectation type expectations.
