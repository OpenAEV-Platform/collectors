# OpenAEV Elastic Security Collector

The Elastic Security collector validates OpenAEV detection expectations against
[Elastic Security](https://www.elastic.co/security), Elastic's SIEM and security analytics solution built on the
Elastic Stack. After OpenAEV agents execute attacks, the collector queries the Elastic Security alerts index in
Elasticsearch and correlates the resulting detection alerts with the related injects to confirm whether the activity
was detected.

## Table of Contents

- [OpenAEV Elastic Security Collector](#openaev-elastic-security-collector)
  - [Table of Contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Requirements](#requirements)
  - [Configuration variables](#configuration-variables)
    - [OpenAEV environment variables](#openaev-environment-variables)
    - [Base collector environment variables](#base-collector-environment-variables)
    - [Elastic collector environment variables](#elastic-collector-environment-variables)
    - [PKI (client certificate) authentication](#pki-client-certificate-authentication)
  - [Deployment](#deployment)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment](#manual-deployment)
  - [Usage](#usage)
  - [Behavior](#behavior)
  - [Required permissions and API endpoints](#required-permissions-and-api-endpoints)
  - [Debugging](#debugging)
  - [Additional information](#additional-information)

## Introduction

OpenAEV (Breach and Attack Simulation) raises "expectations" each time it executes an inject (a simulated attack) on an
endpoint: a DETECTION expectation (the security product should raise an alert) and/or a PREVENTION expectation (the
security product should block the action). This collector connects to Elastic Security, registers a `SecurityPlatform`
of type `SIEM`, and periodically reconciles those expectations with the detection alerts produced by Elastic Security,
marking each expectation as detected/not detected and attaching a trace that links back to the Elastic Security alerts
view in Kibana. Elastic Security is a detection source, so this collector validates DETECTION expectations only;
PREVENTION expectations are not supported.

## Requirements

- OpenAEV Platform >= 1.19.0
- An Elasticsearch cluster storing Elastic Security detection alerts (default index pattern `.alerts-security.alerts-*`)
- An Elasticsearch API key (preferred), a username/password pair, or an X.509 client certificate mapped through a
  [PKI realm](#pki-client-certificate-authentication), with read access to that alerts index
- Optionally, a Kibana instance to build alert links in the expectation traces
- For a manual (non-Docker) deployment: Python >= 3.11 and [Poetry](https://python-poetry.org/) >= 2.1

## Configuration variables

The collector is configured either through environment variables (recommended, read from `docker-compose.yml` / the
`.env` file for a Docker deployment) or through a `config.yml` file (for a manual deployment). Copy the provided
`src/.env.sample` / `src/config.yml.sample` and fill in the values flagged with `ChangeMe`.

### OpenAEV environment variables

| Parameter         | config.yml          | Docker environment variable | Mandatory | Description                                                                              |
|-------------------|---------------------|-----------------------------|-----------|------------------------------------------------------------------------------------------|
| OpenAEV URL       | `openaev.url`       | `OPENAEV_URL`               | Yes       | The URL of the OpenAEV platform. Must be reachable from where the collector runs.        |
| OpenAEV Token     | `openaev.token`     | `OPENAEV_TOKEN`             | Yes       | The administrator token of the OpenAEV platform.                                         |
| OpenAEV Tenant ID | `openaev.tenant_id` | `OPENAEV_TENANT_ID`         | No        | Tenant identifier for multi-tenant deployments. When set, it must be a valid UUID.       |

### Base collector environment variables

| Parameter        | config.yml            | Docker environment variable | Default          | Mandatory | Description                                                                                            |
|------------------|-----------------------|-----------------------------|------------------|-----------|--------------------------------------------------------------------------------------------------------|
| Collector ID     | `collector.id`        | `COLLECTOR_ID`              | /                | Yes       | A unique `UUIDv4` identifier for this collector instance.                                               |
| Collector Name   | `collector.name`      | `COLLECTOR_NAME`            | Elastic Security | No        | The name of the collector as shown in OpenAEV.                                                          |
| Collector Period | `collector.period`    | `COLLECTOR_PERIOD`          | PT1M             | No        | Interval between two runs, as an ISO 8601 duration (e.g. `PT1M` = 1 minute).                            |
| Log Level        | `collector.log_level` | `COLLECTOR_LOG_LEVEL`       | error            | No        | Verbosity of the logs. One of `debug`, `info`, `warn`, `error`.                                         |
| Platform         | `collector.platform`  | `COLLECTOR_PLATFORM`        | SIEM             | No        | The `SecurityPlatform` type registered in OpenAEV. One of `EDR`, `XDR`, `SIEM`, `SOAR`, `NDR`, `ISPM`.  |

### Elastic collector environment variables

| Parameter    | config.yml             | Docker environment variable | Default                     | Mandatory   | Description                                                                                                                                                |
|--------------|------------------------|-----------------------------|-----------------------------|-------------|----------------------------------------------------------------------------------------------------------------------------------------------------------|
| Base URL     | `elastic.base_url`     | `ELASTIC_BASE_URL`          | `https://localhost:9200`    | Yes         | Base URL of the Elasticsearch API (e.g. `https://elastic.company.com:9200`).                                                                              |
| API Key      | `elastic.api_key`      | `ELASTIC_API_KEY`           | /                           | Conditional | Elasticsearch API key (preferred). When set, it is used instead of username/password.                                                                     |
| Username     | `elastic.username`     | `ELASTIC_USERNAME`          | /                           | Conditional | Username for HTTP basic authentication (used when no API key is set).                                                                                     |
| Password     | `elastic.password`     | `ELASTIC_PASSWORD`          | /                           | Conditional | Password for HTTP basic authentication.                                                                                                                   |
| Client Cert  | `elastic.client_cert`  | `ELASTIC_CLIENT_CERT`       | /                           | Conditional | Path to the PEM client certificate for PKI realm authentication (used when neither an API key nor username/password is set). May bundle the private key. |
| Client Key   | `elastic.client_key`   | `ELASTIC_CLIENT_KEY`        | /                           | No          | Path to the unencrypted PEM private key of the client certificate, when it is not bundled in `ELASTIC_CLIENT_CERT`.                                      |
| CA Cert      | `elastic.ca_cert`      | `ELASTIC_CA_CERT`           | /                           | No          | Path to a PEM CA bundle used to verify the Elasticsearch TLS certificate (e.g. an internal PKI). Ignored when `ELASTIC_VERIFY_SSL=false`.                 |
| Alerts Index | `elastic.alerts_index` | `ELASTIC_ALERTS_INDEX`      | `.alerts-security.alerts-*` | No          | Index or index pattern to search for detection alerts.                                                                                                    |
| Kibana URL   | `elastic.kibana_url`   | `ELASTIC_KIBANA_URL`        | /                           | No          | Kibana base URL used to build trace links. When unset, `base_url` is reused with its port rewritten to 5601; set it when Kibana is elsewhere.            |
| Verify SSL   | `elastic.verify_ssl`   | `ELASTIC_VERIFY_SSL`        | true                        | No          | Whether to verify the Elasticsearch TLS certificate.                                                                                                      |
| Time Window  | `elastic.time_window`  | `ELASTIC_TIME_WINDOW`       | PT1H                        | No          | Default search window when no date signatures are provided, as an ISO 8601 duration.                                                                      |
| Offset       | `elastic.offset`       | `ELASTIC_OFFSET`            | PT30S                       | No          | Delay between retry attempts to absorb alert ingestion latency, as an ISO 8601 duration.                                                                  |
| Max Retry    | `elastic.max_retry`    | `ELASTIC_MAX_RETRY`         | 3                           | No          | Maximum number of retry attempts after the initial query returns no results.                                                                              |

> Note: authentication is required. Provide `ELASTIC_API_KEY` (preferred), both `ELASTIC_USERNAME` and
> `ELASTIC_PASSWORD`, or `ELASTIC_CLIENT_CERT`. The collector fails to start if none is configured. When several are
> set, the API key wins, then username/password, then the client certificate. A configured client certificate is always
> presented during the TLS handshake, so it can also be used for mutual TLS together with an API key or basic auth.

### PKI (client certificate) authentication

The collector can authenticate with an X.509 client certificate through the Elasticsearch
[PKI realm](https://www.elastic.co/docs/deploy-manage/users-roles/cluster-or-deployment-auth/pki), so that no API key or
password has to be stored in its configuration.

> PKI realm authentication is only available on self-managed Elasticsearch and ECK deployments. It is **not** supported
> on Elastic Cloud Hosted or ECE: keep using an API key or basic authentication there.

1. **Enable client authentication on the HTTP layer and add a PKI realm** (`elasticsearch.yml` on every node):

   ```yaml
   xpack.security.http.ssl.enabled: true
   # "optional" keeps password/API-key clients working; use "required" to enforce certificates
   xpack.security.http.ssl.client_authentication: optional
   xpack.security.authc.realms.pki.pki1:
     order: 1
     # CA(s) that issued the collector certificate; defaults to the HTTP SSL trust configuration
     certificate_authorities: ["/path/to/client-ca.crt"]
     # Extracts the username from the certificate subject (this is the default pattern)
     username_pattern: "CN=(.*?)(?:,|$)"
   ```

   Keep your existing realms (e.g. `native`) enabled if other clients still rely on them.

2. **Create a role granting read access to the alerts index**:

   ```
   PUT /_security/role/openaev_alerts_reader
   {
     "indices": [
       { "names": [".alerts-security.alerts-*"], "privileges": ["read"] }
     ]
   }
   ```

3. **Map the collector certificate to that role** (match on the certificate distinguished name):

   ```
   PUT /_security/role_mapping/openaev_collector_pki
   {
     "roles": ["openaev_alerts_reader"],
     "enabled": true,
     "rules": {
       "all": [
         { "field": { "realm.name": "pki1" } },
         { "field": { "dn": "CN=openaev-collector,OU=SOC,O=Example" } }
       ]
     }
   }
   ```

4. **Configure the collector** with the certificate files (mount them into the container for a Docker deployment):

   ```shell
   ELASTIC_BASE_URL=https://elastic.company.com:9200
   ELASTIC_CLIENT_CERT=/certs/openaev-collector.crt
   ELASTIC_CLIENT_KEY=/certs/openaev-collector.key
   ELASTIC_CA_CERT=/certs/ca.crt
   ```

   Leave `ELASTIC_API_KEY`, `ELASTIC_USERNAME` and `ELASTIC_PASSWORD` unset, otherwise they take precedence. The private
   key must be unencrypted (PEM), `ELASTIC_BASE_URL` must use `https://`, and TLS must terminate on Elasticsearch itself:
   a proxy terminating TLS in front of the cluster would drop the client certificate.

You can check the mapping with `curl --cert <crt> --key <key> --cacert <ca> https://<host>:9200/_security/_authenticate`,
which should return the certificate username, the `pki1` realm and the `openaev_alerts_reader` role.

## Deployment

### Docker Deployment

Build the Docker image (or use the published `openaev/collector-elastic` image):

```shell
docker build . -t openaev/collector-elastic:latest
```

Create a `.env` file from `src/.env.sample` and fill in your values, then start the collector with the provided
`docker-compose.yml` (which reads those variables):

```shell
docker compose up -d
```

### Manual Deployment with Poetry

1. **Clone and Install Dependencies**:
   ```bash
   git clone <repository-url>
   cd <your-collector>
   poetry install
   ```

2. **Configure the Collector**:
- Copy `src/config.yml.sample` to `src/config.yml`
- Update configuration values or set environment variables

3. **Run the Collector**:
   ```bash
   # Using Poetry
   poetry run python -m src
   
   # Or 
   poetry run ElasticCollector

   # Or direct execution after installing the project and activating the virtual environment:
   ElasticCollector
   ```

For local development against a checkout of [client-python](https://github.com/OpenAEV-Platform/client-python),
The client-python repository must be cloned at the same level as the collectors repository, so that `../../client-python`
resolves correctly from the collector directory.

```
parent-directory/ 
├── collectors/
│   └── <your-collector>/
└── client-python/
```

Then install the local `client-python` version inside the <your-collector> environment:
```bash
poetry run pip install -e ../../client-python --force-reinstall
```
The `-e` option installs the package in editable mode, allowing local changes in `client-python` to be used immediately
without reinstalling the package.

## Usage

Once started, the collector registers itself (and its `SecurityPlatform`) in OpenAEV and then runs automatically every
`COLLECTOR_PERIOD`. No manual interaction is required: as soon as injects produce expectations bound to this collector,
they are reconciled on the next run.

## Behavior

```mermaid
flowchart LR
    subgraph OpenAEV
        E[Detection expectations]
        R[Updated expectations + traces]
    end
    subgraph Elastic Security
        A[Alerts index _search]
    end
    C(Elastic Security collector)
    E -->|poll unfilled expectations| C
    C -->|query alerts in the time window| A
    A -->|detection alerts| C
    C -->|match on IPs + parent process| R
```

On each run, the collector:

1. Fetches the unfilled DETECTION expectations assigned to this collector from OpenAEV. PREVENTION expectations are
   marked invalid because Elastic Security only supports detection.
2. Builds an Elasticsearch query from the expectation signatures (source/destination IP `terms`, plus a `url.path`
   `match_phrase` derived from the inject/agent UUIDs embedded in the parent process name) and runs
   `POST /<alerts_index>/_search` over a sliding time window (default 1 hour, `ELASTIC_TIME_WINDOW`).
3. Retries up to `ELASTIC_MAX_RETRY` times, waiting `ELASTIC_OFFSET` between attempts and progressively widening the
   window, to absorb alert ingestion latency.
4. Matches alerts against the expectation signatures: the `parent_process_name` signature must match and, when IP
   signatures are present, at least one source or destination IP must match.
5. Marks each matched DETECTION expectation as `Detected` and creates an expectation trace, including the alert name and
   a link to the Kibana Security alerts view (`ELASTIC_KIBANA_URL`, or `base_url` with its port rewritten to 5601).

Expectations that remain unmatched after all retries are left for OpenAEV to mark as failed (`Not Detected`) once they
expire.

## Required permissions and API endpoints

- Required permission: an Elasticsearch API key, user, or PKI-mapped certificate with `read` privileges on the configured alerts index
  (default `.alerts-security.alerts-*`) and permission to run `_search` requests against it.
- API endpoints used:
  - `POST /<alerts_index>/_search` (Elasticsearch search API, authenticated with the `Authorization: ApiKey` header,
    HTTP basic authentication, or a TLS client certificate through the PKI realm)
- ECS fields used for matching: `@timestamp`, `source.ip`, `destination.ip`, `url.path`.
- Reference: [Elasticsearch search API](https://www.elastic.co/guide/en/elasticsearch/reference/current/search-search.html)
  and [Create API key](https://www.elastic.co/guide/en/elasticsearch/reference/current/security-api-create-api-key.html)

## Debugging

Set `COLLECTOR_LOG_LEVEL=debug` to get verbose logs, including expectation polling, the queries issued to
Elasticsearch, and the matching decisions. Common causes of "nothing detected" are a wrong alerts index
(`ELASTIC_ALERTS_INDEX`) or a time window (`ELASTIC_TIME_WINDOW`) that is shorter than your alert ingestion latency. For
clusters with self-signed certificates, set `ELASTIC_VERIFY_SSL=false` (or trust the CA) if requests fail on TLS
verification.

## Additional information

- This collector validates detection only; it does not support prevention expectations.
- The collector only reads recent alerts (a sliding time window); it is designed to validate expectations shortly after
  an inject runs, not to back-fill historical data.
- Trace links to Kibana require either `ELASTIC_KIBANA_URL` or an explicit port in `ELASTIC_BASE_URL` (rewritten to
  5601); without either, the Elasticsearch base URL is used as-is.
- The required permissions and endpoints reflect the current implementation. Elastic may change its API over time, so
  always confirm against the official documentation before deploying.
