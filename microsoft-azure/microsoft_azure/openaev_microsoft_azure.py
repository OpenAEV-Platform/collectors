import requests
from microsoft_azure.configuration.config_loader import ConfigLoader
from pyoaev.configuration import Configuration
from pyoaev.daemons import CollectorDaemon


class OpenAEVMicrosoftAzure(CollectorDaemon):
    def __init__(
        self,
        configuration: Configuration,
    ):
        super().__init__(
            configuration=configuration,
            callback=self._process_message,
            collector_type="openaev_microsoft_azure",
        )

        self.session = requests.Session()

        # Azure settings
        self.tenant_id = self._configuration.get("microsoft_azure_tenant_id")
        self.client_id = self._configuration.get("microsoft_azure_client_id")
        self.client_secret = self._configuration.get("microsoft_azure_client_secret")
        self.subscription_id = self._configuration.get(
            "microsoft_azure_subscription_id"
        )
        self.resource_groups = self._configuration.get(
            "microsoft_azure_resource_groups"
        )

        # Parse resource groups (comma-separated)
        if self.resource_groups:
            self.resource_groups_list = [
                rg.strip() for rg in self.resource_groups.split(",") if rg.strip()
            ]

        # Azure Resource Manager endpoints
        self.authority = f"https://login.microsoftonline.com/{self.tenant_id}"
        self.resource = "https://management.azure.com"
        self.base_url = f"{self.resource}/subscriptions/{self.subscription_id}"

        self.access_token = None

    def _get_access_token(self):
        """Get Azure access token using client credentials."""
        try:
            import msal

            app = msal.ConfidentialClientApplication(
                self.client_id,
                authority=self.authority,
                client_credential=self.client_secret,
            )

            result = app.acquire_token_silent(
                [f"{self.resource}/.default"], account=None
            )
            if not result:
                result = app.acquire_token_for_client(
                    scopes=[f"{self.resource}/.default"]
                )

            if "access_token" in result:
                self.access_token = result["access_token"]
                self.logger.info("Successfully authenticated with Azure")
                return True
            else:
                self.logger.error(
                    f"Failed to get access token: {result.get('error_description', 'Unknown error')}"
                )
                return False
        except Exception as e:
            self.logger.error(f"Authentication error: {str(e)}")
            return False

    def _azure_api_call(self, endpoint):
        """Make an API call to Azure Resource Manager."""
        if not self.access_token:
            if not self._get_access_token():
                return None

        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json",
        }

        url = f"{self.base_url}{endpoint}"
        # Add API version based on resource type
        if "?" not in url:
            if "/Microsoft.Network/" in endpoint:
                # Network resources use different API version
                url += "?api-version=2023-06-01"
            else:
                # Compute resources
                url += "?api-version=2023-03-01"

        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 401:  # Token expired
                self.logger.info("Token expired, refreshing...")
                if self._get_access_token():
                    headers["Authorization"] = f"Bearer {self.access_token}"
                    response = requests.get(url, headers=headers)

            if response.status_code == 200:
                return response.json()
            else:
                self.logger.error(
                    f"API call failed: {response.status_code} - {response.text}"
                )
                return None
        except Exception as e:
            self.logger.error(f"API call error: {str(e)}")
            return None

    def _get_vms_from_resource_group(self, resource_group):
        """Get all VMs from a specific resource group."""
        endpoint = f"/resourceGroups/{resource_group}/providers/Microsoft.Compute/virtualMachines"
        result = self._azure_api_call(endpoint)

        if result and "value" in result:
            return result["value"]
        return []

    def _get_vm_network_profile(self, vm):
        """Extract network information from VM."""
        ips = []
        try:
            if "networkProfile" in vm.get("properties", {}):
                network_profile = vm["properties"]["networkProfile"]
                for interface in network_profile.get("networkInterfaces", []):
                    # Get the NIC details
                    nic_id = interface.get("id", "")
                    if nic_id:
                        try:
                            # Extract resource group and NIC name from the ID
                            parts = nic_id.split("/")
                            if len(parts) >= 9:
                                rg_name = parts[4]
                                nic_name = parts[-1]
                                nic_endpoint = f"/resourceGroups/{rg_name}/providers/Microsoft.Network/networkInterfaces/{nic_name}"
                                nic_data = self._azure_api_call(nic_endpoint)

                                if nic_data and "properties" in nic_data:
                                    for ip_config in nic_data["properties"].get(
                                        "ipConfigurations", []
                                    ):
                                        if "properties" in ip_config:
                                            private_ip = ip_config["properties"].get(
                                                "privateIPAddress"
                                            )
                                            if private_ip:
                                                ips.append(private_ip)

                                            # Check for public IP
                                            if (
                                                "publicIPAddress"
                                                in ip_config["properties"]
                                            ):
                                                public_ip_id = ip_config["properties"][
                                                    "publicIPAddress"
                                                ].get("id", "")
                                                if public_ip_id:
                                                    try:
                                                        pub_parts = public_ip_id.split(
                                                            "/"
                                                        )
                                                        if len(pub_parts) >= 9:
                                                            pub_rg = pub_parts[4]
                                                            pub_name = pub_parts[-1]
                                                            pub_endpoint = f"/resourceGroups/{pub_rg}/providers/Microsoft.Network/publicIPAddresses/{pub_name}"
                                                            pub_data = (
                                                                self._azure_api_call(
                                                                    pub_endpoint
                                                                )
                                                            )
                                                            if (
                                                                pub_data
                                                                and "properties"
                                                                in pub_data
                                                            ):
                                                                public_ip = pub_data[
                                                                    "properties"
                                                                ].get("ipAddress")
                                                                if public_ip:
                                                                    ips.append(
                                                                        public_ip
                                                                    )
                                                    except Exception as e:
                                                        self.logger.debug(
                                                            f"Could not get public IP for {nic_name}: {str(e)}"
                                                        )
                        except Exception as e:
                            self.logger.debug(
                                f"Could not process network interface {nic_id}: {str(e)}"
                            )
        except Exception as e:
            self.logger.warning(f"Error extracting network profile for VM: {str(e)}")

        return ips

    def _determine_platform(self, vm):
        """Determine the platform based on VM properties."""
        os_type = (
            vm.get("properties", {})
            .get("storageProfile", {})
            .get("osDisk", {})
            .get("osType", "")
        )

        if os_type.lower() == "windows":
            return "Windows"
        elif os_type.lower() == "linux":
            return "Linux"
        else:
            return "Generic"

    def _create_or_get_tag(self, tag_name, tag_color="#6b7280"):
        """Create or get a tag and return its ID."""
        try:
            tag_data = {"tag_name": tag_name, "tag_color": tag_color}
            result = self.api.tag.upsert(tag_data)
            return result.get("tag_id")
        except Exception as e:
            self.logger.warning(f"Failed to upsert tag {tag_name}: {e}")
            return None

    def _process_message(self) -> None:
        """Process message to collect VMs and upsert them as endpoints."""
        try:
            self.logger.info("Starting Azure VM collection...")

            # If no specific resource groups are provided, get all VMs in subscription
            if not self.resource_groups_list:
                self.logger.info(
                    "No specific resource groups provided, collecting all VMs in subscription"
                )
                endpoint = "/providers/Microsoft.Compute/virtualMachines"
                result = self._azure_api_call(endpoint)
                all_vms = result.get("value", []) if result else []
            else:
                # Collect VMs from specified resource groups
                all_vms = []
                for resource_group in self.resource_groups_list:
                    self.logger.info(
                        f"Collecting VMs from resource group: {resource_group}"
                    )
                    vms = self._get_vms_from_resource_group(resource_group)
                    all_vms.extend(vms)
                    self.logger.info(
                        f"Found {len(vms)} VMs in resource group {resource_group}"
                    )

            self.logger.info(f"Total VMs found: {len(all_vms)}")

            # Process each VM and upsert as endpoint
            for vm in all_vms:
                vm_name = vm.get("name", "unknown")
                vm_id = vm.get("id", "")
                vm_location = vm.get("location", "")

                # Get VM properties
                properties = vm.get("properties", {})
                vm_size = properties.get("hardwareProfile", {}).get("vmSize", "")
                provisioning_state = properties.get("provisioningState", "")

                # Skip VMs that are not successfully provisioned
                if provisioning_state.lower() != "succeeded":
                    self.logger.warning(
                        f"Skipping VM {vm_name} - provisioning state: {provisioning_state}"
                    )
                    continue

                # Determine platform
                platform = self._determine_platform(vm)

                # Get network information
                ips = self._get_vm_network_profile(vm)

                # If no IPs were retrieved
                if not ips:
                    continue

                # Create endpoint object
                endpoint = {
                    "asset_name": vm_name,
                    "asset_external_reference": vm_id,  # Using Azure resource ID as external reference
                    "endpoint_hostname": vm_name,
                    "endpoint_platform": platform,
                    "endpoint_arch": (
                        "x86_64"
                        if "64" in vm_size or platform != "Generic"
                        else "Unknown"
                    ),
                    "endpoint_ips": ips,
                    "asset_description": f"Azure VM - Size: {vm_size}, Location: {vm_location}",
                }

                # Prepare tag IDs list for OpenAEV tags
                tag_ids = []
                tag_colors = {
                    "source": "#ef4444",  # Red
                    "location": "#3b82f6",  # Blue
                    "size": "#8b5cf6",  # Purple
                    "state": "#f59e0b",  # Amber
                    "resource-group": "#10b981",  # Green
                    "azure-tag": "#6b7280",  # Gray (for native Azure tags)
                }

                # Add collector source tag
                source_tag_name = "source:microsoft-azure"
                source_tag_id = self._create_or_get_tag(
                    source_tag_name, tag_colors["source"]
                )
                if source_tag_id:
                    tag_ids.append(source_tag_id)

                # Add location tag
                if vm_location:
                    tag_name = f"location:{vm_location}"
                    tag_id = self._create_or_get_tag(tag_name, tag_colors["location"])
                    if tag_id:
                        tag_ids.append(tag_id)

                # Add VM size tag
                if vm_size:
                    tag_name = f"vm-size:{vm_size.lower()}"
                    tag_id = self._create_or_get_tag(tag_name, tag_colors["size"])
                    if tag_id:
                        tag_ids.append(tag_id)

                # Add provisioning state tag
                if provisioning_state:
                    tag_name = f"state:{provisioning_state.lower()}"
                    tag_id = self._create_or_get_tag(tag_name, tag_colors["state"])
                    if tag_id:
                        tag_ids.append(tag_id)

                # Extract resource group from vm_id
                if vm_id:
                    parts = vm_id.split("/")
                    if len(parts) > 4:
                        resource_group = parts[4]
                        tag_name = f"resource-group:{resource_group.lower()}"
                        tag_id = self._create_or_get_tag(
                            tag_name, tag_colors["resource-group"]
                        )
                        if tag_id:
                            tag_ids.append(tag_id)

                # Add Azure native tags
                azure_tags = vm.get("tags", {})
                if azure_tags:
                    for key, value in azure_tags.items():
                        if key and value:
                            tag_name = f"azure-{key.lower()}:{value.lower()}"
                            tag_id = self._create_or_get_tag(
                                tag_name, tag_colors["azure-tag"]
                            )
                            if tag_id:
                                tag_ids.append(tag_id)

                # Add tag IDs to endpoint if we have any
                if tag_ids:
                    endpoint["asset_tags"] = tag_ids

                # Upsert endpoint
                try:
                    self.api.endpoint.upsert(endpoint)
                    self.logger.info(f"Successfully upserted endpoint: {vm_name}")
                except Exception as e:
                    self.logger.error(f"Failed to upsert endpoint {vm_name}: {str(e)}")

            self.logger.info("Azure VM collection completed")

        except Exception as e:
            self.logger.error(f"Error during VM collection: {str(e)}")


if __name__ == "__main__":
    OpenAEVMicrosoftAzure(configuration=ConfigLoader().to_daemon_config()).start()
