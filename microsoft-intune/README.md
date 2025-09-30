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
  period: 3600  # Collection period in seconds
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
- `COLLECTOR_PERIOD`: Collection interval in seconds
- `COLLECTOR_LOG_LEVEL`: Logging level (debug, info, warn, error)
- `MICROSOFT_INTUNE_TENANT_ID`: Azure AD tenant ID
- `MICROSOFT_INTUNE_CLIENT_ID`: Azure application client ID
- `MICROSOFT_INTUNE_CLIENT_SECRET`: Azure application client secret
- `MICROSOFT_INTUNE_DEVICE_FILTER`: OData filter for device selection (optional)
- `MICROSOFT_INTUNE_DEVICE_GROUPS`: Comma-separated list of device group names or IDs (optional)

## Data Collected

For each managed device, the collector captures:

- **Device Name**: Used as asset name and hostname
- **Device ID**: Intune device identifier (external reference)
- **Platform**: Operating system (Windows/iOS/Android/macOS/Linux/Generic)
- **Architecture**: Device architecture (x86_64/arm64)
- **MAC Addresses**: WiFi and Ethernet MAC addresses when available
- **Compliance State**: Device compliance status (all devices imported regardless of state)
- **Model & Manufacturer**: Hardware information
- **Management Details**: Enrollment date, last sync, management agent
- **Security Status**: Encryption, supervision status
- **User Information**: Associated user principal name

### Tags

The collector automatically creates and assigns tags for better device categorization:

- **compliance**: Device compliance state (compliant/noncompliant)
- **enrollment**: Enrollment type (e.g., corporate, byod)
- **category**: Device category from Intune
- **manufacturer**: Device manufacturer (e.g., Microsoft, Apple, Dell)
- **model**: Device model (sanitized for tag compatibility)
- **os**: Operating system type (windows, ios, android, macos, linux)
- **security:encrypted**: Applied to encrypted devices
- **management:supervised**: Applied to supervised devices
- **agent**: Management agent type



## API Permissions Required

The minimum required Microsoft Graph API permissions are:

| Permission | Type | Description |
|------------|------|-------------|
| DeviceManagementManagedDevices.Read.All | Application | Read all managed devices in Intune |

Required for device group filtering:

| Permission | Type | Description |
|------------|------|-------------|
| Group.Read.All | Application | Read all groups (required if using device group filtering) |

Optional permissions for enhanced functionality:

| Permission | Type | Description |
|------------|------|-------------|
| Device.Read.All | Application | Read Azure AD device information |
| User.Read.All | Application | Read user information for device association |

## Troubleshooting

### Authentication Issues

If you encounter authentication errors:
1. Verify tenant ID, client ID, and client secret are correct
2. Ensure admin consent has been granted for API permissions
3. Check if the client secret has expired
4. Verify the application has the required permissions

### No Devices Found

If no devices are being discovered:
1. Verify devices are enrolled in Intune
2. Check the device filter syntax if using one
3. Ensure the application has `DeviceManagementManagedDevices.Read.All` permission
4. Check Intune portal to confirm devices are visible there

### API Rate Limiting

Microsoft Graph API has rate limits. If you encounter throttling:
1. Increase the collector period to reduce API calls
2. Use device filters to reduce the number of devices retrieved
3. Monitor the logs for 429 (Too Many Requests) errors

### Non-Compliant Devices

By default, the collector includes all devices. To exclude non-compliant devices:
1. Use a filter: `complianceState eq 'compliant'`
2. Or the collector will log warnings for non-compliant devices

## Device Platform Mapping

| Intune OS | OpenAEV Platform |
|-----------|------------------|
| Windows | Windows |
| iOS/iPadOS | iOS |
| Android | Android |
| macOS | MacOS |
| Linux | Linux |
| Other | Generic |

## Support

For issues or questions, please open an issue in the OpenAEV GitHub repository.
