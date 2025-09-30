# OpenBAS Microsoft Defender Collector

Table of Contents

- [OpenBAS Microsoft Defender Collector](#openbas-microsoft-defender-collector)
    - [Prerequisites](#prerequisites)
    - [Configuration variables](#configuration-variables)
        - [OpenBAS environment variables](#openbas-environment-variables)
        - [Base collector environment variables](#base-collector-environment-variables)
        - [Collector extra parameters environment variables](#collector-extra-parameters-environment-variables)
    - [Deployment](#deployment)
        - [Docker Deployment](#docker-deployment)
        - [Manual Deployment](#manual-deployment)
    - [Behavior](#behavior)

## Prerequisites

To use this collector, you need to create an application in your Azure portal with the following permissions:
**Microsoft Graph > ThreatHunting.Read.All**

The permission type should be **Application** or **Delegated Work Account**.

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or
in `config.yml` (for manual deployment).

### OpenBAS environment variables

Below are the parameters you'll need to set for OpenBAS:

| Parameter     | config.yml    | Docker environment variable | Mandatory | Description                                          |
|---------------|---------------|-----------------------------|-----------|------------------------------------------------------|
| OpenBAS URL   | openbas.url   | `OPENBAS_URL`               | Yes       | The URL of the OpenBAS platform.                     |
| OpenBAS Token | openbas.token | `OPENBAS_TOKEN`             | Yes       | The default admin token set in the OpenBAS platform. |

### Base collector environment variables

Below are the parameters you'll need to set for running the collector properly:

| Parameter        | config.yml          | Docker environment variable | Default                    | Mandatory | Description                                                                                   |
|------------------|---------------------|-----------------------------|----------------------------|-----------|-----------------------------------------------------------------------------------------------|
| Collector ID     | collector.id        | `COLLECTOR_ID`              |                            | Yes       | A unique `UUIDv4` identifier for this collector instance.                                     |
| Collector Name   | collector.name      | `COLLECTOR_NAME`            | Microsoft Defender         | No        | Name of the collector.                                                                        |
| Collector Period | collector.period    | `COLLECTOR_PERIOD`          | 60                         | No        | The time interval at which your collector will run (int, seconds).                            |
| Log Level        | collector.log_level | `COLLECTOR_LOG_LEVEL`       | warn                       | No        | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.        |
| Platform         | collector.platform  | `COLLECTOR_PLATFORM`        | EDR                        | No        | Type of security platform this collector works for. One of: `EDR, XDR, SIEM, SOAR, NDR, ISPM` |

### Collector extra parameters environment variables

Below are the parameters you'll need to set for the collector:

| Parameter                 | config.yml                                 | Docker environment variable        | Default | Mandatory | Description |
|---------------------------|--------------------------------------------|------------------------------------|---------|-----------|-------------|
| Application Tenant ID     | collector.microsoft_defender_tenant_id     | `MICROSOFT_DEFENDER_TENANT_ID`     |         | Yes       |             |
| Application Client ID     | collector.microsoft_defender_client_id     | `MICROSOFT_DEFENDER_CLIENT_ID`     |         | Yes       |             |
| Application Client Secret | collector.microsoft_defender_client_secret | `MICROSOFT_DEFENDER_CLIENT_SECRET` |         | Yes       |             |

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
> [!NOTE]
> For Windows hosts: as of writing, the [msgraph-python-sdk has the following note](https://github.com/microsoftgraph/msgraph-sdk-python/blob/65d88850202e9ea75477583e76e75dfbf6d75859/README.md#1-installation):
> > * The Microsoft Graph SDK for Python is a fairly large package. It may take a few minutes for the initial installation to complete.
> > * Enable long paths in your environment if you receive a Could not install packages due to an OSError. For details, see [Enable Long Paths in Windows 10, Version 1607, and Later](https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation?tabs=powershell#enable-long-paths-in-windows-10-version-1607-and-later).
> 
> Follow these instructions if not already enabled on your system.

**Production**:
```shell
# production environment
poetry install --extras prod
```

**Development** (note that you should also clone the [pyobas](OpenBAS-Platform/client-python) repository [according to
these instructions](../README.md#simultaneous-development-on-pyobas-and-a-collector))
```shell
# development environment
poetry install --extras dev
```

Then, start the collector:

```shell
poetry run python -m microsoft_defender.openbas_microsoft_defender
```

## Behavior

The collector retrieves recent alerts (last 45 minutes) from Microsoft Defender and matches them with attacks executed
by OpenBAS agents to validate prevention and detection expectations.

The collector identifies matches using the parent process name. OpenBAS attacks are
recognized by the parent process name format: `openbas-implant-INJECT_ID.exe`.
