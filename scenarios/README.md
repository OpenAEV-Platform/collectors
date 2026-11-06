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
2. A pointer already handled, or naming a release older than the newest one handed on since
   the collector started: nothing to do (an older one is logged as an error: the channel went
   back). Releases are compared by their numbers, `MAJOR.YYMMDD.N`, each as an integer; the first
   releases, up to `2026.10.29.2`, are named `YYYY.MM.DD.N` and come before every other.
3. List the release's files, download its `manifest.json`, and check that it is the one the
   pointer names (its SHA-256), of the repository and channel followed, and that it names a
   `release_approver`: the person who started the release workflow. The collector checks that
   name's form only; nothing proves who it is (see [What is guaranteed](#what-is-guaranteed)).
4. Check that every file the manifest lists, scenario archives and payload version files, is
   a file of the release with the listed size, that the release holds nothing else, then
   download each and check its size and SHA-256. The manifest and the files weigh 512 MiB
   at most in all.
5. Hand the release on, whole. A release with any finding is not handed on at all: the run
   logs why and the next run tries again.
6. Out of dry run, send it to the platform's catalogue in one call, `POST /api/catalog/sync`
   (`/api/tenants/<tenant>/catalog/sync` with a tenant): the manifest in the `manifest` part,
   and every file it lists in an `archives` part of its own, under its name. The platform checks
   them again before it uses anything, and answers what it added, what it already had and what it
   refused, with why: the run logs it. The sync is synchronous: the platform processes the release
   in the call and answers `200` when it is done, and the collector takes no other status for
   success. It waits for that answer up to 30 minutes (`SYNC_READ_TIMEOUT`), so that a release
   still being processed is not sent again; a reverse proxy between the two must allow as much.
   A call that fails is sent again by the next run; a release the platform already holds changes
   nothing.

Every JSON document is read strictly (UTF-8, no key twice, no `NaN`, no integer beyond
±(2^53 − 1), at most 64 levels deep), every answer is read within a bound, redirects are followed
over HTTPS only, and the GitHub token is sent to the GitHub API's host alone. The OpenAEV token
goes to the platform's URL alone: the sync follows no redirect, reads its answer within 1 MiB and
10 minutes, and takes it only for the release it sent. A platform reached over `http://` gets
the token and the release in clear: the collector warns at start; use `https://` outside a
private network.

## When the format changes

The pointer and the manifest each carry a `schema_version`; the collector reads format 1 and
refuses any other, for either file. Within a format, a later release may add fields, never rename
or remove one: the collector ignores the fields it does not know, so an installed collector keeps
syncing.

A field the collector would have to understand to stay safe is not added that way. If ignoring a
field would let the collector accept what it should refuse (a revocation, an expiry, a minimum
collector version, a signed provenance), that field is a break: it comes with a new
`schema_version`, published in a pointer of its own beside the one of format 1, which keeps
moving while collectors upgrade.

## Requirements

- OpenAEV Platform
- Python 3.14+
- Memory: a release is held in memory until it is handed on whole, and sent from there without
  being copied. Plan the release's size plus a margin of about 256 MiB for the interpreter and
  what it reads (the manifest as a document, the file being downloaded): up to 768 MiB for a
  release at its 512 MiB limit. The image sets no memory limit; if you set one, keep to this.
- GitHub rate limit: without a token GitHub allows 60 calls an hour, and a run costs three calls
  plus one for each file of the release, so a release of more than 57 files cannot be read. A run
  that meets the limit stops and says so; set `SCENARIOS_GITHUB_TOKEN` (below).

## Configuration variables

The collector reads its settings from environment variables, then from `config.yml` or `.env`
if present (see `scenarios/config.yml.sample` and `.env.sample`).

### OpenAEV environment variables

| Parameter         | config.yml          | Docker environment variable | Mandatory | Description                                          |
|-------------------|---------------------|-----------------------------|-----------|------------------------------------------------------|
| OpenAEV URL       | `openaev.url`       | `OPENAEV_URL`               | Yes       | The URL of the OpenAEV platform.                     |
| OpenAEV Token     | `openaev.token`     | `OPENAEV_TOKEN`             | Yes       | The token of a dedicated service account, not an admin token and not shared with another collector: it can inject payloads into the catalogue. To send releases, that account needs the **Sync content catalogue** right (`SYNC_CATALOG`), which no role holds by default: an administrator grants it to that account alone. |
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
| GitHub Token   | `scenarios.github_token`   | `SCENARIOS_GITHUB_TOKEN`    |                              | No        | A fine-grained personal access token (see below), needed while the repository is private, and to read a release of more than 57 files. |
| Dry Run        | `scenarios.dry_run`        | `SCENARIOS_DRY_RUN`         | `true`                       | No        | `true` checks each release and sends nothing; `false` sends it to the platform's catalogue. |

### The GitHub token

Give the collector the least a token can have: a **fine-grained personal access token**, with
`OpenAEV-Platform` as resource owner, **this repository only** (`OpenAEV-Platform/scenarios`),
and the permission **Contents: read** (with the `Metadata: read` that comes with it), nothing
else. Never a classic token with the `repo` scope: it can write, and whoever reads the
collector's environment could publish a release and move the pointer.

## What is guaranteed

The collector's reading of GitHub and its call to the platform are hardened, so that the weak
link is not the transport. It guarantees, against a server or a network that is not what it
should be:

- the GitHub token goes to the GitHub API's host alone, never to the storage an asset is
  redirected to, and no `.netrc` replaces it; the OpenAEV token goes to the platform's URL alone;
- every hop is HTTPS, redirects included (a platform over `http://` is warned about);
- every read is bounded in size and in time, however slowly the server answers, and compression
  is not asked for;
- a release is handed on whole or not at all, along a chain of SHA-256: the pointer names the
  manifest, the manifest lists each file, and each file is checked against it;
- a release older than the newest handed on is not handed on again.

It does **not** guarantee that a release is authentic. The collector trusts whoever can move the
`channels` pointer of the scenarios repository: anyone who can write there can publish a
self-consistent release, and the collector accepts it. The `release_approver` of the manifest
is declarative: it names the person who started the release workflow, nothing signs it, and
the collector checks its form only. Protecting the `channels` branch, and verifying a signed
provenance of the manifest, are decisions about that repository and a follow-up of this
collector, not something it does today. Its memory of the newest release ends with the process:
refusing an older release for good is the platform's part.

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
