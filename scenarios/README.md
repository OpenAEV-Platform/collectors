# OpenAEV Scenarios Collector

A collector that follows the releases of the [OpenAEV scenarios repository](https://github.com/OpenAEV-Platform/scenarios):
at each period, it reads the pointer of the channel it follows, downloads the release that
pointer names, and checks it against its manifest before anything reaches the platform.

> **Status:** by default the collector runs dry: it checks releases and says what it would
> send, changing nothing on the platform. With `SCENARIOS_DRY_RUN=false` it sends them to the
> platform's catalogue, which needs a platform that receives catalogue releases.

## What a run does

1. Read `<channel>.json` on the repository's `channels` branch: the release the channel names,
   and the SHA-256 of its manifest. No pointer yet: nothing to do.
2. A pointer already handled: nothing to do.
3. List the release's files, download its `manifest.json`, and check that it is the one the
   pointer names (its SHA-256), of the repository and channel followed, and approved (it names
   its `release_approver`).
4. Check that every file the manifest lists, scenario archives and payload version files, is
   a file of the release with the listed size, that the release holds nothing else, then
   download each and check its size and SHA-256.
5. Hand the release on, whole. A release with any finding is not handed on at all: the run
   logs why and the next run tries again.
6. Out of dry run, send it to the platform's catalogue in one call, `POST /api/catalog/sync`
   (`/api/tenants/<tenant>/catalog/sync` with a tenant): the manifest in the `manifest` part,
   and every file it lists in an `archives` part of its own, under its name. The platform checks
   them again before it uses anything, and answers what it added, what it already had and what it
   refused, with why: the run logs it. A call that fails is sent again by the next run; a release
   the platform already holds changes nothing.

Every JSON document is read strictly (UTF-8, no key twice, no `NaN`, no integer beyond
±(2^53 − 1), at most 64 levels deep), every answer is read within a bound, redirects are followed
over HTTPS only, and the GitHub token is sent to the GitHub API's host alone. The OpenAEV token
goes to the platform's URL alone: the sync follows no redirect, reads its answer within 1 MiB and
10 minutes, and takes it only for the release it sent. A platform reached over `http://` gets
the token and the release in clear: the collector warns at start; use `https://` outside a
private network.

## Requirements

- OpenAEV Platform
- Python 3.14+

## Configuration variables

The collector reads its settings from environment variables, then from `config.yml` or `.env`
if present (see `scenarios/config.yml.sample` and `.env.sample`).

### OpenAEV environment variables

| Parameter         | config.yml          | Docker environment variable | Mandatory | Description                                          |
|-------------------|---------------------|-----------------------------|-----------|------------------------------------------------------|
| OpenAEV URL       | `openaev.url`       | `OPENAEV_URL`               | Yes       | The URL of the OpenAEV platform.                     |
| OpenAEV Token     | `openaev.token`     | `OPENAEV_TOKEN`             | Yes       | The default admin token set in the OpenAEV platform. |
| OpenAEV Tenant ID | `openaev.tenant_id` | `OPENAEV_TENANT_ID`         | No        | Tenant identifier for multi-tenant deployments.      |

### Base collector environment variables

| Parameter        | config.yml                | Docker environment variable | Default                            | Mandatory | Description                                          |
|------------------|---------------------------|-----------------------------|------------------------------------|-----------|------------------------------------------------------|
| Collector ID     | `collector.id`            | `COLLECTOR_ID`              |                                    | Yes       | A unique `UUIDv4` identifier for this collector.     |
| Collector Name   | `collector.name`          | `COLLECTOR_NAME`            | `OpenAEV Scenarios`                | No        | Name of the collector.                               |
| Collector Period | `collector.period`        | `COLLECTOR_PERIOD`          | `PT1H`                             | No        | Time between two runs (ISO 8601).                    |
| Log Level        | `collector.log_level`     | `COLLECTOR_LOG_LEVEL`       | `error`                            | No        | One of `debug`, `info`, `warn`, `error`; `info` shows what each run checked. |
| Icon Filepath    | `collector.icon_filepath` | `COLLECTOR_ICON_FILEPATH`   | `scenarios/img/icon-scenarios.png` | No        | Path to the icon of the collector.                   |

### Source environment variables

| Parameter      | config.yml                 | Docker environment variable | Default                      | Mandatory | Description                                                        |
|----------------|----------------------------|-----------------------------|------------------------------|-----------|--------------------------------------------------------------------|
| Repository     | `scenarios.repository`     | `SCENARIOS_REPOSITORY`      | `OpenAEV-Platform/scenarios` | No        | The repository whose releases are followed, as `owner/name`.       |
| Channel        | `scenarios.channel`        | `SCENARIOS_CHANNEL`         | `edge`                       | No        | `edge` (every release) or `stable` (the recommended ones).         |
| GitHub API URL | `scenarios.github_api_url` | `SCENARIOS_GITHUB_API_URL`  | `https://api.github.com`     | No        | The GitHub REST API the releases are read from, over HTTPS.        |
| GitHub Token   | `scenarios.github_token`   | `SCENARIOS_GITHUB_TOKEN`    |                              | No        | A token that can read the repository, needed while it is private. |
| Dry Run        | `scenarios.dry_run`        | `SCENARIOS_DRY_RUN`         | `true`                       | No        | `true` checks each release and sends nothing; `false` sends it to the platform's catalogue. |

## Deployment

### Docker

```bash
docker build . -t openaev/collector-scenarios:latest
docker compose up -d
```

### Manual

```bash
poetry install
cp scenarios/config.yml.sample scenarios/config.yml   # then set its values
poetry run python -m scenarios
```

## Development

```bash
poetry install --with dev,test
poetry run pytest
```
