# OpenBAS Datasets Collector

This collector allows to import the OpenBAS payloads repository in order to pre-populate your OpenBAS instance with out-of-the-box payloads.

## Configuration

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or
in `config.yml` (for manual deployment).

### OpenBAS environment variables

Below are the parameters you'll need to set for OpenBAS:

| Parameter                  | config.yml                 | Docker environment variable  | Default                                                                        | Mandatory | Description                                          |
|----------------------------|----------------------------|------------------------------|--------------------------------------------------------------------------------|-----------|------------------------------------------------------|
| OpenBAS URL                | openbas.url                | `OPENBAS_URL`                |                                                                                | Yes       | The URL of the OpenBAS platform.                     |
| OpenBAS Token              | openbas.token              | `OPENBAS_TOKEN`              |                                                                                | Yes       | The default admin token set in the OpenBAS platform. |
| OpenBAS URL Prefix         | openbas.url_prefix         | `OPENBAS_URL_PREFIX`         | `https://raw.githubusercontent.com/OpenBAS-Platform/payloads/refs/heads/main/` | No        | URL prefix to look for the content                   |
| OpenBAS Import Only Native | openbas.import_only_native | `OPENBAS_IMPORT_ONLY_NATIVE` | false                                                                          | No        | Only import native datasets                          |

### Base collector environment variables

Below are the parameters you'll need to set for running the collector properly:

| Parameter        | config.yml           | Docker environment variable | Default          | Mandatory | Description                                                                            |
|------------------|----------------------|-----------------------------|------------------|-----------|----------------------------------------------------------------------------------------|
| Collector ID     | collector.id         | `COLLECTOR_ID`              |                  | Yes       | A unique `UUIDv4` identifier for this collector instance.                              |
| Collector Name   | collector.name       | `COLLECTOR_NAME`            | OpenBAS Datasets | No        | Name of the collector.                                                                 |
| Collector Period | collector.period     | `COLLECTOR_PERIOD`          | 604800           | No        | The time interval at which your collector will run (int, seconds).                     |
| Log Level        | collector.log_level  | `COLLECTOR_LOG_LEVEL`       | warn             | no        | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`. |

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

**Development** (note that you should also clone the [pyoaev](OpenBAS-Platform/client-python) repository [according to
these instructions](../README.md#simultaneous-development-on-pyoaev-and-a-collector))
```shell
# development environment
poetry install --extras dev
```

Then, start the collector:

```shell
poetry run python -m openbas.openbas_openbas
```

## Behavior

The collector retrieves payloads from the Filigran OpenBAS payload repository. 
