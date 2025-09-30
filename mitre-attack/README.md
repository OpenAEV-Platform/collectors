# OpenBAS Mitre Attack Collector

Table of Contents

- [OpenBAS Mittre Attack Collector](#openbas-mitre-attack-collector)
    - [Configuration variables](#configuration-variables)
        - [OpenBAS environment variables](#openbas-environment-variables)
        - [Base collector environment variables](#base-collector-environment-variables)
    - [Deployment](#deployment)
        - [Docker Deployment](#docker-deployment)
        - [Manual Deployment](#manual-deployment)
    - [Behavior](#behavior)

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

| Parameter        | config.yml           | Docker environment variable | Default              | Mandatory | Description                                                                            |
|------------------|----------------------|-----------------------------|----------------------|-----------|----------------------------------------------------------------------------------------|
| Collector ID     | collector.id         | `COLLECTOR_ID`              |                      | Yes       | A unique `UUIDv4` identifier for this collector instance.                              |
| Collector Name   | collector.name       | `COLLECTOR_NAME`            | MITRE ATT&CK         | No        | Name of the collector.                                                                 |
| Collector Period | collector.period     | `COLLECTOR_PERIOD`          | 604800               | No        | The time interval at which your collector will run (int, seconds).                     |
| Log Level        | collector.log_level  | `COLLECTOR_LOG_LEVEL`       | warn                 | no        | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`. |

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

**Development** (note that you should also clone the [pyobas](OpenBAS-Platform/client-python) repository [according to
these instructions](../README.md#simultaneous-development-on-pyobas-and-a-collector))
```shell
# development environment
poetry install --extras dev
```

Then, start the collector:

```shell
poetry run python -m mitre_attack.openbas_mitre_attack
```

## Behavior

This collector retrieves the mitre attack matrix to extract attack patterns and kill chain phases and import them into
your OpenBAS instance.
