# OpenAEV Amazon Web Services

## Description

This collector enables OpenAEV to import EC2 instances from AWS accounts as endpoints.

## Features

- Collects EC2 instances from specified AWS regions or all available regions
- Automatically identifies instance operating system (Windows/Linux)
- Captures instance network configuration including private and public IPs
- Supports AWS tags for asset categorization
- Supports multiple authentication methods (IAM user, instance role, assume role)
- Uses AWS EC2 API for instance discovery

## Requirements

- AWS Account with appropriate permissions
- Python 3.11 or higher

## Configuration

### AWS Setup

#### Option 1: Using IAM User Access Keys

1. **Create an IAM User:**
   - Go to AWS Console → IAM → Users
   - Click "Add users"
   - Enter a username (e.g., "openaev-collector")
   - Select "Programmatic access" for Access type
   - Click "Next: Permissions"

2. **Attach Permissions:**
   - Select "Attach existing policies directly"
   - Search for and select `AmazonEC2ReadOnlyAccess`
   - Or create a custom policy with minimal permissions (see below)
   - Click "Next: Tags" → "Next: Review" → "Create user"

3. **Save Access Keys:**
   - Copy the Access Key ID
   - Copy the Secret Access Key (won't be shown again)

#### Option 2: Using Instance Role (for EC2-hosted collector)

1. **Create an IAM Role:**
   - Go to AWS Console → IAM → Roles
   - Click "Create role"
   - Select "AWS service" → "EC2"
   - Attach `AmazonEC2ReadOnlyAccess` policy
   - Name the role (e.g., "OpenAEVCollectorRole")

2. **Attach Role to EC2 Instance:**
   - Launch or modify your EC2 instance
   - Attach the created IAM role

#### Option 3: Using AssumeRole for Cross-Account Access

1. **Create a Role in Target Account:**
   - Create an IAM role with EC2 read permissions
   - Configure trust relationship to allow assuming from source account

2. **Configure Collector:**
   - Provide base credentials (IAM user or instance role)
   - Specify the role ARN to assume

### Minimal IAM Policy

For security best practices, create a custom policy with only required permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeInstances",
                "ec2:DescribeRegions",
                "ec2:DescribeInstanceTypes",
                "ec2:DescribeInstanceStatus",
                "ec2:DescribeNetworkInterfaces",
                "ec2:DescribeTags"
            ],
            "Resource": "*"
        }
    ]
}
```

### OpenAEV Configuration

Create or update `config.yml`:

```yaml
openaev:
  url: 'http://your-openaev-url:3001'
  token: 'your-openaev-token'

collector:
  id: 'unique-collector-id'
  name: 'AWS Resources'
  period: 3600  # Collection period in seconds
  log_level: 'info'
  aws_access_key_id: 'your-access-key-id'  # Optional if using instance role
  aws_secret_access_key: 'your-secret-access-key'  # Optional if using instance role
  aws_session_token: ''  # Optional, for temporary credentials
  aws_assume_role_arn: ''  # Optional, ARN of role to assume
  aws_regions: 'us-east-1,eu-west-1'  # Comma-separated, leave empty for all regions
```

## Installation

### Using Docker

1. Build the Docker image:
```bash
docker build -t openaev-aws-resources-collector .
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
poetry run python aws_resources/openaev_aws_resources.py
```

## Environment Variables

All configuration can be provided via environment variables:

- `OPENAEV_URL`: OpenAEV platform URL
- `OPENAEV_TOKEN`: OpenAEV API token
- `COLLECTOR_ID`: Unique collector identifier
- `COLLECTOR_NAME`: Display name for the collector
- `COLLECTOR_PERIOD`: Collection interval as ISO 8601 period expression, e.g. PT1M: 1 minute
- `COLLECTOR_LOG_LEVEL`: Logging level (debug, info, warn, error)
- `AWS_ACCESS_KEY_ID`: AWS Access Key ID
- `AWS_SECRET_ACCESS_KEY`: AWS Secret Access Key
- `AWS_SESSION_TOKEN`: AWS Session Token (for temporary credentials)
- `AWS_ASSUME_ROLE_ARN`: ARN of IAM role to assume
- `AWS_REGIONS`: Comma-separated list of AWS regions

## Data Collected

For each EC2 instance, the collector captures:

- **Instance Name**: From Name tag or Instance ID as fallback
- **Instance ID**: AWS instance identifier (external reference)
- **Platform**: Operating system type (Windows/Linux)
- **Architecture**: Based on instance architecture (x86_64/arm64/arm)
- **IP Addresses**: Both private and public IPs from all network interfaces
- **Instance Type**: EC2 instance type (e.g., t2.micro, m5.large)
- **Region**: AWS region where instance is located
- **Availability Zone**: Specific AZ within the region
- **State**: Current instance state (running, stopped, etc.)
- **Tags**: AWS tags for categorization

## Supported Regions

The collector can work with:
- Specific regions listed in configuration
- All available regions (auto-discovery when no regions specified)
- Common regions fallback if discovery fails

## Authentication Priority

The collector tries authentication methods in this order:
1. Explicit credentials (access key + secret key)
2. Temporary credentials (with session token)
3. AssumeRole (if role ARN provided)
4. Instance role (if running on EC2)
5. Default credential chain

## Troubleshooting

### Authentication Issues

If you encounter authentication errors:
1. Verify AWS credentials are correct
2. Check IAM permissions include EC2 read access
3. For instance roles, ensure role is attached to the EC2 instance
4. For AssumeRole, verify trust relationship is configured

### Permission Issues

If instances are not being discovered:
1. Verify IAM user/role has `ec2:DescribeInstances` permission
2. Check if region-specific permissions are needed
3. Ensure credentials have access to the specified regions

### Network Issues

If unable to connect to AWS:
1. Check internet connectivity
2. Verify no proxy/firewall is blocking AWS endpoints
3. For VPC endpoints, ensure proper routing is configured

### No Instances Found

If collector runs but finds no instances:
1. Verify instances exist in the specified regions
2. Check instance state (terminated instances are skipped)
3. Ensure region names are spelled correctly
4. Try without region filter to scan all regions

## Performance Considerations

- **Region Selection**: Specifying regions improves performance
- **API Throttling**: AWS may throttle API calls for large deployments
- **Pagination**: Collector handles pagination for large instance lists
- **Collection Period**: Adjust based on instance change frequency

## Security Best Practices

1. **Use Minimal Permissions**: Only grant required EC2 read permissions
2. **Rotate Access Keys**: Regularly rotate IAM access keys
3. **Use Instance Roles**: When running on EC2, prefer instance roles
4. **Enable CloudTrail**: Monitor API calls made by the collector
5. **Restrict by Region**: Limit collector to required regions only
6. **Use AssumeRole**: For cross-account access, use temporary credentials

## Support

For issues or questions, please open an issue in the OpenAEV GitHub repository.
