# OpenAEV GitHub Collector

The GitHub collector imports the code estate of your [GitHub](https://github.com/) organizations and users into OpenAEV
as **source-code assets**: every repository as a code repository, every GitHub Actions workflow as a CI/CD pipeline and
every GitHub Packages package as a software package. On each run it reads the GitHub REST API with a read-only token and
creates or updates one OpenAEV asset per object, so your source code and release pipeline are part of the asset
inventory, of asset groups and of the scope of your exposure management. This collector imports inventory only: it
never writes to GitHub and does not validate detection or prevention expectations.

## Table of Contents

- [OpenAEV GitHub Collector](#openaev-github-collector)
  - [Table of Contents](#table-of-contents)
  - [Requirements](#requirements)
  - [Configuration variables](#configuration-variables)
    - [OpenAEV environment variables](#openaev-environment-variables)
    - [Base collector environment variables](#base-collector-environment-variables)
    - [GitHub access](#github-access)
    - [What to collect](#what-to-collect)
  - [Creating the token](#creating-the-token)
  - [Deployment](#deployment)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment with Poetry](#manual-deployment-with-poetry)
  - [Behavior](#behavior)
  - [Asset mapping](#asset-mapping)
  - [Rate limits](#rate-limits)
  - [Required permissions and API endpoints](#required-permissions-and-api-endpoints)
  - [Debugging](#debugging)

## Requirements

- An OpenAEV Platform whose asset taxonomy holds the **Source code** category (`SOURCE_CODE`, with the subcategories
  `CODE_REPOSITORY`, `CI_CD_PIPELINE` and `SOFTWARE_PACKAGE`). An older platform refuses these values.
- A GitHub token with read access to the owners you collect (see [Creating the token](#creating-the-token)).
- github.com, or GitHub Enterprise Server reachable from the collector.

## Configuration variables

Configuration is read from `config.yml` (manual deployment) or from environment variables (Docker), the latter
winning.

### OpenAEV environment variables

| Parameter     | config.yml  | Docker environment variable | Mandatory | Description                                          |
|---------------|-------------|-----------------------------|-----------|------------------------------------------------------|
| OpenAEV URL   | `url`       | `OPENAEV_URL`               | Yes       | The URL of the OpenAEV platform.                     |
| OpenAEV Token | `token`     | `OPENAEV_TOKEN`             | Yes       | The API token of an OpenAEV user.                    |
| Tenant id     | `tenant_id` | `OPENAEV_TENANT_ID`         | No        | Only for multi-tenancy (Enterprise Edition).         |

### Base collector environment variables

| Parameter        | config.yml  | Docker environment variable | Default | Mandatory | Description                                                  |
|------------------|-------------|-----------------------------|---------|-----------|--------------------------------------------------------------|
| Collector ID     | `id`        | `COLLECTOR_ID`              | /       | Yes       | A unique `UUIDv4` identifier for this collector instance.    |
| Collector Name   | `name`      | `COLLECTOR_NAME`            | GitHub  | No        | Name of the collector.                                       |
| Collector Period | `period`    | `COLLECTOR_PERIOD`          | PT6H    | No        | Time between two runs (ISO 8601 duration).                   |
| Log Level        | `log_level` | `COLLECTOR_LOG_LEVEL`       | error   | No        | `debug`, `info`, `warn` or `error`.                          |

### GitHub access

| Parameter    | config.yml                 | Docker environment variable  | Default                  | Mandatory | Description                                                          |
|--------------|----------------------------|------------------------------|--------------------------|-----------|----------------------------------------------------------------------|
| Token        | `collector.github_token`   | `COLLECTOR_GITHUB_TOKEN`     | /                        | Yes       | Read-only GitHub token.                                              |
| API URL      | `collector.github_api_url` | `COLLECTOR_GITHUB_API_URL`   | `https://api.github.com` | No        | GitHub Enterprise Server: `https://<host>/api/v3`.                   |

### What to collect

| Parameter        | config.yml                          | Docker environment variable            | Default                               | Description                                                                                  |
|------------------|-------------------------------------|----------------------------------------|---------------------------------------|----------------------------------------------------------------------------------------------|
| Organizations    | `collector.github_organizations`    | `COLLECTOR_GITHUB_ORGANIZATIONS`       | /                                     | Comma-separated organization logins. At least one organization or user is required.         |
| Users            | `collector.github_users`            | `COLLECTOR_GITHUB_USERS`               | /                                     | Comma-separated user logins (their own repositories).                                        |
| Include archived | `collector.github_include_archived` | `COLLECTOR_GITHUB_INCLUDE_ARCHIVED`    | true                                  | Collect archived repositories, flagged `github-state:archived`.                              |
| Include forks    | `collector.github_include_forks`    | `COLLECTOR_GITHUB_INCLUDE_FORKS`       | false                                 | Collect forked repositories.                                                                 |
| Workflows        | `collector.github_collect_workflows`| `COLLECTOR_GITHUB_COLLECT_WORKFLOWS`   | true                                  | Register each GitHub Actions workflow as a CI/CD pipeline asset linked to its repository.    |
| Packages         | `collector.github_collect_packages` | `COLLECTOR_GITHUB_COLLECT_PACKAGES`    | true                                  | Register GitHub Packages as software package assets when the token can read them.            |
| Package types    | `collector.github_package_types`    | `COLLECTOR_GITHUB_PACKAGE_TYPES`       | `npm,maven,rubygems,nuget,container`  | Package types read (`npm`, `maven`, `rubygems`, `docker`, `nuget`, `container`).             |
| End-date removed | `collector.github_end_date_removed` | `COLLECTOR_GITHUB_END_DATE_REMOVED`    | true                                  | End-date (never delete) the assets of objects GitHub no longer returns.                      |

## Creating the token

Use a **fine-grained personal access token** (or a GitHub App installation token) owned by a service account, scoped
to the organizations collected, with **read-only** repository permissions:

- **Metadata: read** (repositories, topics, visibility; always granted),
- **Actions: read** (workflows),
- **Packages: read** for GitHub Packages (a classic token needs `read:packages`).

A classic token works too with `repo` (private repositories) or no scope (public only), plus `read:packages`. No write
permission is needed: the collector only issues `GET` requests.

## Deployment

### Docker Deployment

Build the Docker image (or use the published `openaev/collector-github` image):

```shell
docker build . -t openaev/collector-github:latest
```

Copy `.env.sample` to `.env`, fill it in, then start it:

```shell
docker compose up -d
```

### Manual Deployment with Poetry

```shell
cd collectors/github
poetry install
cp github_collector/config.yml.sample github_collector/config.yml   # then edit it
poetry run python -m github_collector
```

## Behavior

On each run the collector:

1. Lists the repositories of every configured organization (`type=all`) and user (`type=owner`).
2. Drops forks (unless `github_include_forks`) and archived repositories (when `github_include_archived` is false).
3. Lists the GitHub Actions workflows of every kept repository (a repository with Actions disabled or not readable
   keeps its own asset).
4. Lists the GitHub Packages of each owner for the configured types (skipped silently when the token cannot read
   packages).
5. Upserts one OpenAEV asset per object, keyed on its stable GitHub id (a renamed or transferred repository keeps its
   asset), and creates the tags `source:github`, `github-owner:<owner>`, `visibility:<visibility>`,
   `language:<language>`, `topic:<topic>`, `github-repo:<owner/name>` and `package-type:<type>`.
6. When `github_end_date_removed` is on, reads the source-code assets it registered earlier and end-dates those GitHub
   no longer returns: their metadata gets `github_state: deleted` and `github_end_date`, and they are tagged
   `github-state:deleted`. Assets are **never deleted**. An owner whose listing failed in this run is left untouched,
   so an API outage never end-dates a whole organization.

## Asset mapping

| OpenAEV field              | Repository                              | Workflow                                    | Package                                  |
|----------------------------|-----------------------------------------|---------------------------------------------|------------------------------------------|
| `asset_category`           | `SOURCE_CODE`                           | `SOURCE_CODE`                               | `SOURCE_CODE`                            |
| `asset_subcategory`        | `CODE_REPOSITORY`                       | `CI_CD_PIPELINE`                            | `SOFTWARE_PACKAGE`                       |
| `asset_external_reference` | `github:repository:<node id>`           | `github:workflow:<node id>`                 | `github:package:<id>`                    |
| `asset_name`               | `<owner>/<name>`                        | `<owner>/<name>: <workflow name>`           | `<owner>/<package> (<type>)`             |
| `asset_url`                | Repository page                         | Workflow file page                          | Package page                             |
| `asset_internet_facing`    | true when public                        | /                                           | true when public                         |
| `asset_metadata`           | visibility, default branch, archived, fork, last push, language, topics | path, state, repository and its external reference | type, visibility, versions, repository |

Archived repositories carry `github_archived: true`, `github_state: archived` and the tag `github-state:archived`.

## Rate limits

The collector stays within the GitHub rate limits:

- every page is fetched with `If-None-Match` and its last `ETag`; an unchanged page answers `304 Not Modified`, which
  does not count against the primary rate limit (the cache lives for the life of the process);
- an exhausted primary limit waits until `X-RateLimit-Reset` (at most 15 minutes, else the run of that owner fails and
  is retried at the next period);
- a secondary limit (`Retry-After`) or a server error is retried with an exponential backoff.

## Required permissions and API endpoints

| Endpoint                                   | Use                          | Permission           |
|--------------------------------------------|------------------------------|----------------------|
| `GET /orgs/{org}/repos`                    | Organization repositories    | Metadata: read       |
| `GET /users/{user}/repos`                  | User repositories            | Metadata: read       |
| `GET /repos/{owner}/{repo}/actions/workflows` | Workflows                 | Actions: read        |
| `GET /orgs/{org}/packages`, `GET /users/{user}/packages` | Packages       | Packages: read       |

## Debugging

Set `COLLECTOR_LOG_LEVEL=debug` to log every upsert.

- `github_token is required` or `at least one owner`: fill the token and `github_organizations` or `github_users`.
- No workflows: the token lacks **Actions: read**, or Actions is disabled on the repository.
- No packages: the token lacks **Packages: read** (`read:packages`), or the owner publishes none of the listed types.
- Upserts refused with an unknown category: the OpenAEV platform predates the **Source code** category.
