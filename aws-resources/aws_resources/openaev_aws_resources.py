import os

import boto3
from aws_resources.configuration.config_loader import ConfigLoader
from botocore.exceptions import ClientError, NoCredentialsError
from pyoaev.configuration import Configuration
from pyoaev.daemons import CollectorDaemon


class OpenAEVAWSResources(CollectorDaemon):
    def __init__(
        self,
        configuration: Configuration,
    ):
        super().__init__(
            configuration=configuration,
            callback=self._process_message,
            collector_type="openaev_aws_resources",
        )

        # AWS settings
        self.access_key_id = self._configuration.get("aws_access_key_id")
        self.secret_access_key = self._configuration.get("aws_secret_access_key")
        self.session_token = self._configuration.get("aws_session_token")
        self.assume_role_arn = self._configuration.get("aws_assume_role_arn")
        self.regions = self._configuration.get("aws_regions")

        # Parse regions (comma-separated)
        # If no regions specified, we'll discover them
        if self.regions:
            self.regions_list = [
                region.strip() for region in self.regions.split(",") if region.strip()
            ]
        else:
            self.regions_list = None

        # Initialize AWS clients
        self.aws_clients = {}

        self.base_session = None
        self.session = None

    def _init_aws_session(self):
        """Initialize AWS session with credentials."""
        try:
            # Create base session with provided credentials or use instance role
            if self.access_key_id and self.secret_access_key:
                session_args = {
                    "aws_access_key_id": self.access_key_id,
                    "aws_secret_access_key": self.secret_access_key,
                }
                if self.session_token:
                    session_args["aws_session_token"] = self.session_token
                self.base_session = boto3.Session(**session_args)
            else:
                # Use instance role or default credentials
                self.base_session = boto3.Session()

            # If assume role is configured, assume the role
            if self.assume_role_arn:
                sts_client = self.base_session.client("sts")
                assumed_role = sts_client.assume_role(
                    RoleArn=self.assume_role_arn, RoleSessionName="OpenAEVAWSCollector"
                )
                credentials = assumed_role["Credentials"]
                self.session = boto3.Session(
                    aws_access_key_id=credentials["AccessKeyId"],
                    aws_secret_access_key=credentials["SecretAccessKey"],
                    aws_session_token=credentials["SessionToken"],
                )
            else:
                self.session = self.base_session

            self.logger.info("Successfully initialized AWS session")

            # Get list of regions if not specified
            if not self.regions_list:
                self._discover_regions()

        except NoCredentialsError:
            self.logger.error(
                "No AWS credentials found. Please configure access keys or use instance role."
            )
            raise
        except ClientError as e:
            self.logger.error(f"AWS client error: {str(e)}")
            raise
        except Exception as e:
            self.logger.error(f"Failed to initialize AWS session: {str(e)}")
            raise

    def _discover_regions(self):
        """Discover all available EC2 regions."""
        try:
            ec2_client = self.session.client("ec2", region_name="us-east-1")
            regions_response = ec2_client.describe_regions(AllRegions=False)
            self.regions_list = [
                region["RegionName"] for region in regions_response["Regions"]
            ]
            self.logger.info(f"Discovered {len(self.regions_list)} AWS regions")
        except ClientError as e:
            self.logger.error(f"Failed to discover regions: {str(e)}")
            # Fall back to common regions
            self.regions_list = [
                "us-east-1",
                "us-west-2",
                "eu-west-1",
                "eu-central-1",
                "ap-southeast-1",
                "ap-northeast-1",
            ]
            self.logger.warning(
                f"Using fallback regions: {', '.join(self.regions_list)}"
            )

    def _get_ec2_client(self, region):
        """Get or create EC2 client for a specific region."""
        if region not in self.aws_clients:
            self.aws_clients[region] = self.session.client("ec2", region_name=region)
        return self.aws_clients[region]

    def _get_instances_from_region(self, region):
        """Get all EC2 instances from a specific region."""
        try:
            ec2_client = self._get_ec2_client(region)

            # Get all instances (including stopped ones)
            paginator = ec2_client.get_paginator("describe_instances")
            page_iterator = paginator.paginate()

            instances = []
            for page in page_iterator:
                for reservation in page.get("Reservations", []):
                    instances.extend(reservation.get("Instances", []))

            return instances
        except ClientError as e:
            (
                self.logger.error(
                    f"Failed to get instances from region {region}: {str(e)}"
                )
            )
            return []

    def _determine_platform(self, instance):
        """Determine the platform based on instance properties."""
        platform = instance.get("Platform", "").lower()
        platform_details = instance.get("PlatformDetails", "").lower()

        if platform == "windows" or "windows" in platform_details:
            return "Windows"
        elif (
            "linux" in platform_details
            or "ubuntu" in platform_details
            or "amazon" in platform_details
        ):
            return "Linux"
        elif "red hat" in platform_details or "rhel" in platform_details:
            return "Linux"
        elif "suse" in platform_details:
            return "Linux"
        else:
            # Default to Linux for Unix-like systems
            return "Linux"

    def _get_instance_ips(self, instance):
        """Extract IP addresses from instance."""
        ips = []

        # Get private IP
        private_ip = instance.get("PrivateIpAddress")
        if private_ip:
            ips.append(private_ip)

        # Get public IP
        public_ip = instance.get("PublicIpAddress")
        if public_ip:
            ips.append(public_ip)

        # Get IPs from network interfaces
        for interface in instance.get("NetworkInterfaces", []):
            # Private IPs
            for private_ip_info in interface.get("PrivateIpAddresses", []):
                private_ip = private_ip_info.get("PrivateIpAddress")
                if private_ip and private_ip not in ips:
                    ips.append(private_ip)

                # Associated public IP
                association = private_ip_info.get("Association", {})
                public_ip = association.get("PublicIp")
                if public_ip and public_ip not in ips:
                    ips.append(public_ip)

        return ips

    def _determine_architecture(self, instance):
        """Determine architecture based on instance properties."""
        arch = instance.get("Architecture", "").lower()
        instance_type = instance.get("InstanceType", "")

        if "x86_64" in arch or "amd64" in arch:
            return "x86_64"
        elif "arm" in arch or "arm" in instance_type.lower():
            if "64" in arch:
                return "arm64"
            else:
                return "arm"
        elif "i386" in arch:
            return "x86"
        else:
            # Default to x86_64 for most modern instances
            return "x86_64"

    def _create_or_get_tag(self, tag_name, tag_color="#6b7280"):
        """Create or get a tag and return its ID."""
        try:
            tag_data = {"tag_name": tag_name, "tag_color": tag_color}
            result = self.api.tag.upsert(tag_data)
            return result.get("tag_id")
        except Exception as e:
            self.logger.warning(f"Failed to upsert tag {tag_name}: {e}")
            return None

    def __lazy_session_init(self):
        if not self.base_session:
            self._init_aws_session()

    def _process_message(self) -> None:
        """Process message to collect EC2 instances and upsert them as endpoints."""

        # lazily init session
        self.__lazy_session_init()

        try:
            self.logger.info("Starting AWS EC2 collection...")

            all_instances = []

            # Collect instances from all specified regions
            for region in self.regions_list:
                self.logger.info(f"Collecting EC2 instances from region: {region}")
                instances = self._get_instances_from_region(region)

                # Add region information to each instance
                for instance in instances:
                    instance["_region"] = region

                all_instances.extend(instances)
                self.logger.info(f"Found {len(instances)} instances in region {region}")

            self.logger.info(f"Total EC2 instances found: {len(all_instances)}")

            # Process each instance and upsert as endpoint
            for instance in all_instances:
                instance_id = instance.get("InstanceId", "unknown")
                instance_name = None

                # Try to get instance name from tags
                for tag in instance.get("Tags", []):
                    if tag.get("Key") == "Name":
                        instance_name = tag.get("Value")
                        break

                # Use instance ID as name if no Name tag
                if not instance_name:
                    instance_name = instance_id

                # Get instance details
                instance_type = instance.get("InstanceType", "unknown")
                state = instance.get("State", {}).get("Name", "unknown")
                region = instance.get("_region", "unknown")
                availability_zone = instance.get("Placement", {}).get(
                    "AvailabilityZone", ""
                )

                # Skip terminated instances
                if state == "terminated":
                    self.logger.debug(f"Skipping terminated instance {instance_name}")
                    continue

                # Determine platform and architecture
                platform = self._determine_platform(instance)
                architecture = self._determine_architecture(instance)

                # Get IP addresses
                ips = self._get_instance_ips(instance)

                # Skip instances without IPs (might be in weird state)
                if not ips:
                    self.logger.warning(
                        f"Skipping instance {instance_name} - no IP addresses found"
                    )
                    continue

                # Create endpoint object
                endpoint = {
                    "asset_name": instance_name,
                    "asset_external_reference": instance_id,  # Using AWS instance ID as external reference
                    "endpoint_hostname": instance_name,
                    "endpoint_platform": platform,
                    "endpoint_arch": architecture,
                    "endpoint_ips": ips,
                    "asset_description": f"AWS EC2 Instance - Type: {instance_type}, Region: {region}, AZ: {availability_zone}, State: {state}",
                }

                # Prepare tag IDs list for OpenAEV tags
                tag_ids = []
                tag_colors = {
                    "source": "#ef4444",  # Red
                    "region": "#3b82f6",  # Blue
                    "instance-type": "#8b5cf6",  # Purple
                    "availability-zone": "#10b981",  # Green
                    "state": "#f59e0b",  # Amber
                    "aws-tag": "#6b7280",  # Gray (for native AWS tags)
                }

                # Add collector source tag
                source_tag_name = "source:aws-resources"
                source_tag_id = self._create_or_get_tag(
                    source_tag_name, tag_colors["source"]
                )
                if source_tag_id:
                    tag_ids.append(source_tag_id)

                # Add region tag
                if region and region != "unknown":
                    tag_name = f"region:{region}"
                    tag_id = self._create_or_get_tag(tag_name, tag_colors["region"])
                    if tag_id:
                        tag_ids.append(tag_id)

                # Add instance type tag
                if instance_type and instance_type != "unknown":
                    tag_name = f"instance-type:{instance_type}"
                    tag_id = self._create_or_get_tag(
                        tag_name, tag_colors["instance-type"]
                    )
                    if tag_id:
                        tag_ids.append(tag_id)

                # Add availability zone tag
                if availability_zone:
                    tag_name = f"az:{availability_zone}"
                    tag_id = self._create_or_get_tag(
                        tag_name, tag_colors["availability-zone"]
                    )
                    if tag_id:
                        tag_ids.append(tag_id)

                # Add state tag
                if state and state != "unknown":
                    tag_name = f"state:{state}"
                    tag_id = self._create_or_get_tag(tag_name, tag_colors["state"])
                    if tag_id:
                        tag_ids.append(tag_id)

                # Add AWS native tags
                aws_tags = instance.get("Tags", [])
                if aws_tags:
                    for tag in aws_tags:
                        key = tag.get("Key", "")
                        value = tag.get("Value", "")
                        # Skip the Name tag as it's already used for asset_name
                        if key and value and key != "Name":
                            tag_name = f"aws-{key.lower()}:{value.lower()}"
                            tag_id = self._create_or_get_tag(
                                tag_name, tag_colors["aws-tag"]
                            )
                            if tag_id:
                                tag_ids.append(tag_id)

                # Add tag IDs to endpoint if we have any
                if tag_ids:
                    endpoint["asset_tags"] = tag_ids

                # Upsert endpoint
                try:
                    self.api.endpoint.upsert(endpoint)
                    self.logger.info(
                        f"Successfully upserted endpoint: {instance_name} ({instance_id})"
                    )
                except Exception as e:
                    self.logger.error(
                        f"Failed to upsert endpoint {instance_name}: {str(e)}"
                    )

            self.logger.info("AWS EC2 collection completed")

        except Exception as e:
            self.logger.error(f"Error during EC2 collection: {str(e)}")


if __name__ == "__main__":
    for key in [
        "AWS_ACCESS_KEY",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_ASSUME_ROLE_ARN",
        "AWS_REGIONS",
    ]:
        if not os.environ.get(f"COLLECTOR_{key}") and os.environ.get(key):
            os.environ[f"COLLECTOR_{key}"] = os.environ.get(key)

    OpenAEVAWSResources(configuration=ConfigLoader().to_daemon_config()).start()
