# OpenAEV Microsoft Intune Collector

## Description

This collector enables OpenAEV to import managed devices from Microsoft Intune as endpoints. It uses the Microsoft Graph API to retrieve device information and synchronizes it with OpenAEV.

## Features

- Collects all managed devices from Microsoft Intune
- Automatically identifies device operating systems (Windows, iOS, Android, macOS, Linux)
- Captures device compliance status and metadata
- Supports filtering devices using OData query syntax
- Maps device properties to OpenAEV endpoint structure
- Includes device tags for compliance state, encryption status, and management details

## Requirements

- Microsoft Intune subscription
- Azure Active Directory application with appropriate permissions
- Python 3.11 or higher

## Configuration

### Azure AD Setup

1. **Create an Azure AD Application:**
   - Go to Azure Portal → Azure Active Directory → App registrations
   - Click "New registration"
   - Name your application (e.g., "OpenAEV Intune Collector")
   - Select supported account types (single tenant recommended)
   - Click "Register"

2. **Create Client Secret:**
   - In your app registration, go to "Certificates & secrets"
   - Click "New client secret"
   - Add a description and set expiration
   - Copy the secret value immediately (it won't be shown again)

3. **Grant Microsoft Graph API Permissions:**
   - In your app registration, go to "API permissions"
   - Click "Add a permission" → "Microsoft Graph" → "Application permissions"
   - Add the following permissions:
     - `DeviceManagementManagedDevices.Read.All` - Read all managed devices
     - `Group.Read.All` - Read all groups (required if using device group filtering)
     - `Device.Read.All` - Read all devices (optional, for Azure AD device info)
   - Click "Grant admin consent" for your organization

4. **Collect Required Information:**
   - Tenant ID: Azure Active Directory → Properties → Directory ID
   - Client ID: Your app registration → Overview → Application (client) ID
   - Client Secret: The secret you created earlier

### OpenAEV Configuration

Create or update `config.yml`:

```yaml
openaev:
  url: 'http://your-openaev-url:3001'
  token: 'your-openaev-token'

collector:
  id: 'unique-collector-id'
  name: 'Microsoft Intune'
  period: 'PT1H'  # Collection period in ISO 8601
  log_level: 'info'
  microsoft_intune_tenant_id: 'your-tenant-id'
  microsoft_intune_client_id: 'your-client-id'
  microsoft_intune_client_secret: 'your-client-secret'
  microsoft_intune_device_filter: ''  # Optional OData filter
  microsoft_intune_device_groups: ''  # Comma-separated device groups
```

### Device Filtering

You can filter devices in two ways:

#### 1. OData Filter (device properties)
Use the `microsoft_intune_device_filter` parameter with OData syntax:
- Windows devices only: `operatingSystem eq 'Windows'`
- Compliant devices: `complianceState eq 'compliant'`
- Encrypted devices: `isEncrypted eq true`
- Specific manufacturer: `manufacturer eq 'Microsoft Corporation'`
- Combined filters: `operatingSystem eq 'Windows' and complianceState eq 'compliant'`

#### 2. Device Groups (Azure AD groups)
Use the `microsoft_intune_device_groups` parameter to filter by group membership:
- Single group: `IT Department Devices`
- Multiple groups: `IT Devices,Sales Laptops,Executive Phones`
- By group ID: `a1b2c3d4-e5f6-7890-abcd-ef1234567890`
- Mix names and IDs: `IT Devices,a1b2c3d4-e5f6-7890-abcd-ef1234567890`

Leave both filters empty to collect all devices.

## Installation

### Using Docker

1. Build the Docker image:
```bash
docker build -t openaev-microsoft-intune-collector .
```

2. Run with docker-compose:
```bash
docker-compose up -d
```

### Manual Installation

1. Install dependencies:
```bash
pip install poetry
poetry install
```

2. Configure the collector by creating `config.yml` from `config.yml.sample`

3. Run the collector:
```bash
poetry run python microsoft_intune/openaev_microsoft_intune.py
```

## Environment Variables

All configuration can be provided via environment variables:

- `OPENAEV_URL`: OpenAEV platform URL
- `OPENAEV_TOKEN`: OpenAEV API token
- `COLLECTOR_ID`: Unique collector identifier
- `COLLECTOR_NAME`: Display name for the collector
- `COLLECTOR_PERIOD`: Collection interval as ISO 8601 period expression, e.g. PT1M: 1 minute
- `COLLECTOR_LOG_LEVEL`: Logging level (debug, info, warn, error)
- `COLLECTOR_MICROSOFT_INTUNE_TENANT_ID`: Azure AD tenant ID
- `COLLECTOR_MICROSOFT_INTUNE_CLIENT_ID`: Azure application client ID
- `COLLECTOR_MICROSOFT_INTUNE_CLIENT_SECRET`: Azure application client secret
- `COLLECTOR_MICROSOFT_INTUNE_DEVICE_FILTER`: OData filter for device selection (optional)
- `COLLECTOR_MICROSOFT_INTUNE_DEVICE_GROUPS`: Comma-separated list of device group names or IDs (optional)


## API Permissions and Endpoints Used

- **API Permissions Required:**
  - `DeviceManagementManagedDevices.Read.All` (Application)
  - `Group.Read.All` (Application, required for device group filtering)
  - `Device.Read.All` (optional, for Azure AD device info)
  - `User.Read.All` (optional, for device-user association)
- **API Endpoints Used:**
  - `GET /deviceManagement/managedDevices`
  - `GET /groups`
- **Reference:** [Microsoft Graph API Permissions](https://learn.microsoft.com/en-us/graph/permissions-reference)

> **Warning** _(as of April 14, 2026)_: The required permissions and endpoints listed above are based on the current code and documentation. Microsoft may change API requirements or endpoints at any time. **Always check the [official documentation](https://learn.microsoft.com/en-us/graph/permissions-reference) for the latest requirements before deploying.**
