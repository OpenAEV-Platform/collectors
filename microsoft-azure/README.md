# OpenAEV Microsoft Azure Collector

## Description

This collector enables OpenAEV to import Virtual Machines from Microsoft Azure subscriptions as endpoints.

## Features

- Collects Virtual Machines from specified Azure resource groups or entire subscription
- Automatically identifies VM operating system (Windows/Linux)
- Captures VM network configuration including private and public IPs
- Supports Azure tags for asset categorization
- Uses Azure Resource Manager API for VM discovery

## Requirements

- Microsoft Azure subscription
- Azure Active Directory application with appropriate permissions
- Python 3.11 or higher

## Configuration

### Azure Setup

1. **Create an Azure AD Application:**
   - Go to Azure Portal → Azure Active Directory → App registrations
   - Click "New registration"
   - Name your application (e.g., "OpenAEV Collector")
   - Select supported account types (single tenant recommended)
   - Click "Register"

2. **Create Client Secret:**
   - In your app registration, go to "Certificates & secrets"
   - Click "New client secret"
   - Add a description and set expiration
   - Copy the secret value immediately (it won't be shown again)

3. **Grant Permissions:**
   - Go to your Azure subscription
   - Navigate to "Access control (IAM)"
   - Add role assignment
   - Select "Reader" role (minimum required)
   - Assign to your application

4. **Collect Required Information:**
   - Tenant ID: Azure Active Directory → Properties → Directory ID
   - Client ID: Your app registration → Overview → Application (client) ID
   - Client Secret: The secret you created earlier
   - Subscription ID: Subscriptions → Your subscription → Overview → Subscription ID
   - Resource Groups: Names of resource groups to monitor (optional)

### OpenAEV Configuration

Create or update `config.yml`:

```yaml
openaev:
  url: 'http://your-openaev-url:3001'
  token: 'your-openaev-token'

collector:
  id: 'unique-collector-id'
  name: 'Microsoft Azure'
  period: 'PT1H'  # Collection period in ISO 8601
  log_level: 'info'
  microsoft_azure_tenant_id: 'your-tenant-id'
  microsoft_azure_client_id: 'your-client-id'
  microsoft_azure_client_secret: 'your-client-secret'
  microsoft_azure_subscription_id: 'your-subscription-id'
  microsoft_azure_resource_groups: 'rg1,rg2,rg3'  # Comma-separated, leave empty for all
```

## Installation

### Using Docker

1. Build the Docker image:
```bash
docker build -t openaev-microsoft-azure-collector .
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
poetry run python microsoft_azure/openaev_microsoft_azure.py
```

## Environment Variables

All configuration can be provided via environment variables:

- `OPENAEV_URL`: OpenAEV platform URL
- `OPENAEV_TOKEN`: OpenAEV API token
- `COLLECTOR_ID`: Unique collector identifier
- `COLLECTOR_NAME`: Display name for the collector
- `COLLECTOR_PERIOD`: Collection interval as ISO 8601 period expression, e.g. PT1M: 1 minute
- `COLLECTOR_LOG_LEVEL`: Logging level (debug, info, warn, error)
- `MICROSOFT_AZURE_TENANT_ID`: Azure AD tenant ID
- `MICROSOFT_AZURE_CLIENT_ID`: Azure application client ID
- `MICROSOFT_AZURE_CLIENT_SECRET`: Azure application client secret
- `MICROSOFT_AZURE_SUBSCRIPTION_ID`: Azure subscription ID
- `MICROSOFT_AZURE_RESOURCE_GROUPS`: Comma-separated list of resource groups

## Data Collected

For each Virtual Machine, the collector captures:

- **VM Name**: Used as asset name and hostname
- **Resource ID**: Azure resource identifier (external reference)
- **Platform**: Operating system type (Windows/Linux/Generic)
- **Architecture**: Based on VM size
- **IP Addresses**: Both private and public IPs (placeholder IP used if network details unavailable)
- **Location**: Azure region
- **Size**: VM size designation
- **Tags**: Azure tags for categorization

## API Versions

The collector uses different Azure API versions for different resource types:
- **Compute Resources** (VMs): API version `2023-03-01`
- **Network Resources** (NICs, Public IPs): API version `2023-06-01`

## Troubleshooting

### Authentication Issues

If you encounter authentication errors:
1. Verify tenant ID, client ID, and client secret are correct
2. Ensure the application has Reader permissions on the subscription
3. Check if the client secret has expired

### Permission Issues

If VMs are not being discovered:
1. Verify the application has at least Reader role on the subscription or resource groups
2. Check if resource group names are spelled correctly
3. Ensure the subscription ID is valid

### Network Issues

If unable to connect to Azure:
1. Check internet connectivity
2. Verify no proxy/firewall is blocking Azure endpoints
3. Ensure Azure services are accessible from your location

## Support

For issues or questions, please open an issue in the OpenAEV GitHub repository.
