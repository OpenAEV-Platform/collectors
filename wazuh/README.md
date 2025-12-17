# OpenAEV Wazuh Collector

A Wazuh SIEM integration for OpenAEV that validates security expectations by querying Wazuh indexer for security alerts and matching them against expected outcomes.

**Note**: Requires access to a Wazuh 4.x deployment with OpenSearch/Elasticsearch indexer.

## Overview

This collector validates OpenAEV expectations by querying your Wazuh environment for matching security alerts via the Wazuh indexer API. When OpenAEV runs security exercises, this collector automatically checks if the expected security threats were actually detected in your SIEM, providing visibility into your detection capabilities.

The collector uses Wazuh's alert storage in OpenSearch/Elasticsearch to validate detection expectations, with support for multiple signature types including process names, hashes, MITRE techniques, and custom rule matching.

## Features

- **Alert-Based Validation**: Queries Wazuh indexer for security alerts to verify detections
- **Flexible Signature Matching**: Supports multiple signature types:
  - Parent process names
  - Process names
  - Command lines
  - File paths
  - Hash values (MD5, SHA1, SHA256)
  - Wazuh rule IDs
  - MITRE ATT&CK techniques
- **Detection-Only Support**: Validates detection expectations based on alert rule levels
- **Trace Generation**: Creates detailed traces with links back to Wazuh dashboard
- **Configurable Collection**: Adjustable polling intervals and lookback windows
- **High-Volume Support**: Handles up to 10,000 alerts per collection cycle

**Note**: This collector only supports **DETECTION** expectations. Prevention expectations are not supported as Wazuh is a detection-focused SIEM platform.

## Requirements

- OpenAEV Platform
- Wazuh 4.x deployment with indexer access
- Python 3.11+ (for manual deployment)
- Wazuh indexer credentials with appropriate permissions

## Configuration

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or
in `config.yml` (for manual deployment).

The collector supports multiple configuration sources in order of precedence:
1. Environment variables
2. YAML configuration file (`config.yml`)
3. Default values

### OpenAEV environment variables

Below are the parameters you'll need to set for OpenAEV:

| Parameter     | config.yml    | Docker environment variable | Mandatory | Description                                          |
|---------------|---------------|-----------------------------|-----------|------------------------------------------------------|
| OpenAEV URL   | openaev.url   | `OPENAEV_URL`               | Yes       | The URL of the OpenAEV platform.                    |
| OpenAEV Token | openaev.token | `OPENAEV_TOKEN`             | Yes       | The default admin token set in the OpenAEV platform.|

### Base collector environment variables

Below are the parameters you'll need to set for running the collector properly:

| Parameter        | config.yml          | Docker environment variable | Default                 | Mandatory | Description                                                                                   |
|------------------|---------------------|-----------------------------|-------------------------|-----------|-----------------------------------------------------------------------------------------------|
| Collector ID     | collector.id        | `COLLECTOR_ID`              | wazuh--0b13e3f7-5c9e-46f5-acc4-33032e9b4921 | Yes       | A unique `UUIDv4` identifier for this collector instance.                                     |
| Collector Name   | collector.name      | `COLLECTOR_NAME`            | Wazuh SIEM Collector    | No        | Name of the collector.                                                                        |
| Collector Type   | collector.type      | `COLLECTOR_TYPE`            | wazuh                   | No        | Type identifier for the collector.                                                            |
| Collector Period | collector.period    | `COLLECTOR_PERIOD`          | 60                      | No        | Collection interval (int, seconds).                                                          |
| Log Level        | collector.log_level | `COLLECTOR_LOG_LEVEL`       | info                    | No        | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.      |
| Platform         | collector.platform  | `COLLECTOR_PLATFORM`        | SIEM                    | No        | Type of security platform this collector works for. One of: `EDR, XDR, SIEM, SOAR, NDR, ISPM` |

### Collector extra parameters environment variables

Below are the parameters you'll need to set for the collector:

| Parameter                | config.yml                | Docker environment variable | Default                     | Mandatory | Description                                                                                        |
|--------------------------|---------------------------|-----------------------------|-----------------------------|-----------|----------------------------------------------------------------------------------------------------|
| Indexer Host             | wazuh.indexer_host        | `INDEXER_HOST`              | localhost                   | Yes       | Wazuh indexer hostname or IP address                                                              |
| Indexer Port             | wazuh.indexer_port        | `INDEXER_PORT`              | 9200                        | No        | Wazuh indexer port (typically 9200 for OpenSearch)                                                |
| Indexer Username         | wazuh.indexer_username    | `INDEXER_USERNAME`          | admin                       | Yes       | Indexer username with read access to alert indices                                                |
| Indexer Password         | wazuh.indexer_password    | `INDEXER_PASSWORD`          |                             | Yes       | Indexer user password                                                                              |
| Use SSL                  | wazuh.indexer_use_ssl     | `INDEXER_USE_SSL`           | true                        | No        | Use SSL/TLS for indexer connection                                                                |
| Verify Certificates      | wazuh.indexer_verify_certs| `INDEXER_VERIFY_CERTS`      | false                       | No        | Verify SSL certificates (set to false for self-signed certificates)                               |
| CA Certificates Path     | wazuh.indexer_ca_certs    | `INDEXER_CA_CERTS`          |                             | No        | Path to CA certificates file for SSL verification                                                 |
| Index Pattern            | wazuh.indexer_index_pattern| `INDEXER_INDEX_PATTERN`    | wazuh-alerts-*              | No        | Index pattern for searching Wazuh alerts                                                          |
| Alert Limit              | wazuh.indexer_alert_limit | `INDEXER_ALERT_LIMIT`       | 10000                       | No        | Maximum number of alerts to retrieve per collection cycle                                         |
| Dashboard URL            | wazuh.dashboard_url       | `DASHBOARD_URL`             |                             | No        | Dashboard base URL for generating alert links (e.g., https://wazuh.example.com)                   |

### Example Configuration Files

#### YAML Configuration (`config.yml`)
```yaml
openaev:
  url: "https://your-openaev-instance.com"
  token: "your-openaev-token"

collector:
  id: "wazuh--your-unique-uuid"
  name: "Wazuh Production"
  type: "wazuh"
  period: 60
  log_level: "info"
  platform: "SIEM"

wazuh:
  indexer_host: "wazuh-indexer.company.com"
  indexer_port: 9200
  indexer_username: "wazuh-collector"
  indexer_password: "your-secure-password"
  indexer_use_ssl: true
  indexer_verify_certs: false
  indexer_index_pattern: "wazuh-alerts-*"
  indexer_alert_limit: 10000
  dashboard_url: "https://wazuh.company.com"
```

#### Environment Variables
```bash
export OPENAEV_URL="https://your-openaev-instance.com"
export OPENAEV_TOKEN="your-openaev-token"
export COLLECTOR_ID="wazuh--your-unique-uuid"
export INDEXER_HOST="wazuh-indexer.company.com"
export INDEXER_PORT=9200
export INDEXER_USERNAME="wazuh-collector"
export INDEXER_PASSWORD="your-secure-password"
export INDEXER_USE_SSL=true
export INDEXER_VERIFY_CERTS=false
export INDEXER_ALERT_LIMIT=10000
export DASHBOARD_URL="https://wazuh.company.com"
```

## Deployment

### Manual Deployment with Poetry

1. **Clone and Install Dependencies**:
   ```bash
   git clone <repository-url>
   cd wazuh-collector
   poetry install --extras prod
   ```

2. **Configure the Collector**:
   - Create a `config.yml` file with your configuration
   - Or set environment variables

3. **Run the Collector**:
   ```bash
   # Using Poetry
   poetry run python collector.py

   # Or direct execution after installation
   WazuhCollector
   ```

### Docker Deployment

```bash
# Build the container
docker build -t openaev-wazuh-collector .

# Run with environment variables
docker run -d \
  -e OPENAEV_URL="https://your-openaev-instance.com" \
  -e OPENAEV_TOKEN="your-token" \
  -e COLLECTOR_ID="wazuh--your-uuid" \
  -e INDEXER_HOST="wazuh-indexer.company.com" \
  -e INDEXER_USERNAME="wazuh-collector" \
  -e INDEXER_PASSWORD="your-password" \
  openaev-wazuh-collector

# Or run with configuration file mounted
docker run -d \
  -v /path/to/config.yml:/app/config.yml:ro \
  openaev-wazuh-collector
```

### Docker Compose

Create a `.env` file with your configuration:
```env
OPENAEV_URL=https://openaev.example.com
OPENAEV_TOKEN=your-token-here
COLLECTOR_ID=wazuh-collector-001
INDEXER_HOST=wazuh-indexer.example.com
INDEXER_PORT=9200
INDEXER_USERNAME=admin
INDEXER_PASSWORD=secure-password
INDEXER_USE_SSL=true
INDEXER_VERIFY_CERTS=false
INDEXER_ALERT_LIMIT=10000
DASHBOARD_URL=https://wazuh.example.com
```

Then run:
```bash
# Build and start the collector
docker-compose up -d

# View logs
docker-compose logs -f

# Stop the collector
docker-compose down
```

Example `docker-compose.yml`:
```yaml
version: '3.8'

services:
  wazuh-collector:
    image: openaev/collector-wazuh:latest
    environment:
      - OPENAEV_URL=${OPENAEV_URL}
      - OPENAEV_TOKEN=${OPENAEV_TOKEN}
      - COLLECTOR_ID=wazuh-collector-001
      - COLLECTOR_NAME=Wazuh SIEM Collector
      - INDEXER_HOST=${INDEXER_HOST}
      - INDEXER_PORT=9200
      - INDEXER_USERNAME=${INDEXER_USERNAME}
      - INDEXER_PASSWORD=${INDEXER_PASSWORD}
      - INDEXER_USE_SSL=true
      - INDEXER_VERIFY_CERTS=false
      - INDEXER_ALERT_LIMIT=10000
      - DASHBOARD_URL=${DASHBOARD_URL}
    restart: unless-stopped
```

## Behavior

### Supported Signature Types

The collector supports the following OpenAEV signature types:

- **`parent_process_name`**: Parent process names to match against alert data
- **`process_name`**: Process names to match against alert data
- **`command_line`**: Command line arguments to search for in alerts
- **`file_path`**: File system paths to match against alert data
- **`hash_md5`**: MD5 file hashes to search for in alerts
- **`hash_sha1`**: SHA1 file hashes to search for in alerts
- **`hash_sha256`**: SHA256 file hashes to search for in alerts
- **`rule_id`**: Wazuh rule IDs to match specific detection rules
- **`mitre_technique`**: MITRE ATT&CK technique IDs (e.g., T1059.001)
- **`start_date`**: Start time for the alert search query (ISO 8601 format)
- **`end_date`**: End time for the alert search query (ISO 8601 format)

### Processing Flow

1. **Expectation Retrieval**: Fetches pending expectations from OpenAEV
2. **Time Window Determination**: Extracts time windows from expectations or uses default lookback (60 minutes)
3. **Alert Fetching**: Queries Wazuh indexer for alerts within the time window
4. **Alert Processing**: Normalizes Wazuh alerts into OpenAEV-compatible format
5. **Signature Matching**: Matches alert data against expectation signatures using detection helper
6. **Outcome Determination**: Evaluates detection/prevention based on rule level and groups
7. **Result Reporting**: Updates expectation status in OpenAEV
8. **Trace Creation**: Creates detailed traces linking back to Wazuh dashboard
