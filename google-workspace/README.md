# OpenAEV Google Workspace Collector

Table of Contents

- [OpenAEV Google Workspace Collector](#openaev-google-workspace-collector)
    - [Configuration variables](#configuration-variables)
        - [OpenAEV environment variables](#openaev-environment-variables)
        - [Base collector environment variables](#base-collector-environment-variables)
        - [Collector extra parameters environment variables](#collector-extra-parameters-environment-variables)
    - [Google Workspace Setup](#google-workspace-setup)
        - [Prerequisites](#prerequisites)
        - [Create Service Account](#create-service-account)
        - [Enable Domain-Wide Delegation](#enable-domain-wide-delegation)
        - [Grant API Scopes](#grant-api-scopes)
    - [Deployment](#deployment)
        - [Docker Deployment](#docker-deployment)
        - [Manual Deployment](#manual-deployment)
    - [Behavior](#behavior)
    - [Synchronization Modes](#synchronization-modes)

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or
in `config.yml` (for manual deployment).

### OpenAEV environment variables

Below are the parameters you'll need to set for OpenAEV:

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
|---------------|------------|-----------------------------|-----------|------------------------------------------------------|
| OpenAEV URL   | url        | `OPENAEV_URL`               | Yes       | The URL of the OpenAEV platform.                     |
| OpenAEV Token | token      | `OPENAEV_TOKEN`             | Yes       | The default admin token set in the OpenAEV platform. |

### Base collector environment variables

Below are the parameters you'll need to set for running the collector properly:

| Parameter        | config.yml          | Docker environment variable | Default          | Mandatory | Description                                                                                             |
|------------------|---------------------|----------------------------|------------------|-----------|---------------------------------------------------------------------------------------------------------|
| Collector ID     | collector.id        | `COLLECTOR_ID`             |                  | Yes       | A unique `UUIDv4` identifier for this collector instance.                                               |
| Collector Name   | collector.name      | `COLLECTOR_NAME`           | Google Workspace | No        | Name of the collector.                                                                                  |
| Collector Period | collector.period    | `COLLECTOR_PERIOD`         | PT1H             | No        | The time interval at which your collector will run (ISO 8601 period expression, e.g. 'PT1M': 1 minute). |
| Log Level        | collector.log_level | `COLLECTOR_LOG_LEVEL`      | warn             | No        | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.                  |

### Collector extra parameters environment variables

Below are the parameters you'll need to set for the collector:

| Parameter                   | config.yml                                       | Docker environment variable              | Default      | Mandatory | Description                                                              |
|-----------------------------|--------------------------------------------------|------------------------------------------|--------------|-----------|--------------------------------------------------------------------------|
| Service Account JSON        | collector.google_workspace_service_account_json | `GOOGLE_WORKSPACE_SERVICE_ACCOUNT_JSON` |              | Yes       | JSON string containing service account credentials                       |
| Delegated Admin Email       | collector.google_workspace_delegated_admin_email| `GOOGLE_WORKSPACE_DELEGATED_ADMIN_EMAIL`|              | Yes       | Email of the admin user for domain-wide delegation                       |
| Customer ID                 | collector.google_workspace_customer_id          | `GOOGLE_WORKSPACE_CUSTOMER_ID`          | my_customer  | No        | Google Workspace customer ID or 'my_customer' for your own domain        |
| Include Suspended Users     | collector.include_suspended                     | `INCLUDE_SUSPENDED`                     | false        | No        | Whether to include suspended users in synchronization                    |
| Sync All Users              | collector.sync_all_users                        | `SYNC_ALL_USERS`                        | false        | No        | If true, sync all users; if false, only sync users who are group members |

## Google Workspace Setup

### Prerequisites

- A Google Workspace (formerly G Suite) domain
- Admin access to the Google Workspace Admin Console
- API access enabled for your domain

### Create Service Account

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the Admin SDK API:
   - Navigate to "APIs & Services" > "Library"
   - Search for "Admin SDK API"
   - Click on it and press "Enable"
4. Create a Service Account:
   - Navigate to "IAM & Admin" > "Service Accounts"
   - Click "Create Service Account"
   - Give it a name (e.g., "openaev-collector")
   - Click "Create and Continue"
   - Skip the optional steps and click "Done"
5. Create a key for the Service Account:
   - Click on the created service account
   - Go to the "Keys" tab
   - Click "Add Key" > "Create new key"
   - Choose JSON format
   - Save the downloaded JSON file securely

### Enable Domain-Wide Delegation

1. In the Service Account details page, click "Show Advanced Settings"
2. Under "Domain-wide delegation", click "Enable G Suite Domain-wide Delegation"
3. Note the "Client ID" (you'll need this for the next step)

### Grant API Scopes

1. Go to your [Google Workspace Admin Console](https://admin.google.com/)
2. Navigate to "Security" > "API Controls" > "Domain-wide Delegation"
3. Click "Add new"
4. Enter the Client ID from the previous step
5. Add the following OAuth scopes:
   ```
   https://www.googleapis.com/auth/admin.directory.user.readonly
   https://www.googleapis.com/auth/admin.directory.group.readonly
   https://www.googleapis.com/auth/admin.directory.group.member.readonly
   ```
6. Click "Authorize"

## Deployment

### Docker Deployment

Build a Docker Image using the provided `Dockerfile`.

Example:

```shell
# Replace the IMAGE NAME with the appropriate value
docker build . -t [IMAGE NAME]
```

Make sure to replace the environment variables in `docker-compose.yml` with the appropriate configurations for your
environment. 

For the service account JSON, you need to provide it as a single-line JSON string. You can convert your JSON file to a single line using:

```shell
# Linux/Mac
cat service-account.json | jq -c . | sed 's/"/\\"/g'

# Windows PowerShell
Get-Content service-account.json | ConvertFrom-Json | ConvertTo-Json -Compress
```

Then, start the docker container with the provided docker-compose.yml

```shell
docker compose up -d
# -d for detached
```

### Manual Deployment

Create a file `config.yml` based on the provided `config.yml.sample`.

Replace the configuration variables with the appropriate configurations for
your environment.

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
poetry run python -m google_workspace.openaev_google_workspace
```

## Behavior

This collector retrieves your users and groups from your Google Workspace instance and imports them into your OpenAEV
instance. The collector supports two synchronization modes:

### Default Mode (Groups and Members)
When `sync_all_users` is set to `false` (default), the collector will:
1. Fetch all groups from Google Workspace
2. Create corresponding teams in OpenAEV
3. For each group, fetch its members
4. Create users (players) in OpenAEV and associate them with their teams

### All Users Mode
When `sync_all_users` is set to `true`, the collector will:
1. Fetch all users from Google Workspace
2. Create users (players) in OpenAEV without team associations
3. This mode is useful when you want to import all users regardless of group membership

## Synchronization Modes

The collector adds various tags to users for better organization and filtering:

### Source Tags
- `source:google-workspace` - All imported users receive this tag

### Status Tags
- `status:active` - Active users
- `status:suspended` - Suspended users (only imported if `include_suspended` is true)

### Organizational Unit Tags
- `org-unit:[unit-name]` - Based on the user's organizational unit in Google Workspace

### Role Tags
- `role:admin` - Users with admin privileges
- `role:delegated-admin` - Users with delegated admin privileges

These tags help in filtering and organizing users within OpenAEV for different exercise scenarios.
