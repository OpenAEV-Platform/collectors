import requests
from microsoft_intune.configuration.config_loader import ConfigLoader
from pyoaev.configuration import Configuration
from pyoaev.daemons import CollectorDaemon


class OpenAEVMicrosoftIntune(CollectorDaemon):
    def __init__(
        self,
        configuration: Configuration,
    ):
        super().__init__(
            configuration=configuration,
            callback=self._process_message,
            collector_type="openaev_microsoft_intune",
        )
        self.session = requests.Session()

        # Intune settings
        self.tenant_id = self._configuration.get("microsoft_intune_tenant_id")
        self.client_id = self._configuration.get("microsoft_intune_client_id")
        self.client_secret = self._configuration.get("microsoft_intune_client_secret")
        self.device_filter = self._configuration.get("microsoft_intune_device_filter")
        self.device_groups = self._configuration.get("microsoft_intune_device_groups")

        # Parse device groups (comma-separated)
        if self.device_groups:
            self.device_groups_list = [
                g.strip() for g in self.device_groups.split(",") if g.strip()
            ]

        # Microsoft Graph endpoints
        self.authority = f"https://login.microsoftonline.com/{self.tenant_id}"
        self.graph_url = "https://graph.microsoft.com/v1.0"

        self.access_token = None

    def _get_access_token(self):
        """Get Microsoft Graph access token using client credentials."""
        try:
            import msal

            app = msal.ConfidentialClientApplication(
                self.client_id,
                authority=self.authority,
                client_credential=self.client_secret,
            )

            result = app.acquire_token_silent(
                ["https://graph.microsoft.com/.default"], account=None
            )
            if not result:
                result = app.acquire_token_for_client(
                    scopes=["https://graph.microsoft.com/.default"]
                )

            if "access_token" in result:
                self.access_token = result["access_token"]
                self.logger.info("Successfully authenticated with Microsoft Graph")
                return True
            else:
                self.logger.error(
                    f"Failed to get access token: {result.get('error_description', 'Unknown error')}"
                )
                return False
        except Exception as e:
            self.logger.error(f"Authentication error: {str(e)}")
            return False

    def _graph_api_call(self, endpoint, params=None):
        """Make an API call to Microsoft Graph."""
        if not self.access_token:
            if not self._get_access_token():
                return None

        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json",
        }

        url = f"{self.graph_url}{endpoint}"

        try:
            response = requests.get(url, headers=headers, params=params)
            if response.status_code == 401:  # Token expired
                self.logger.info("Token expired, refreshing...")
                if self._get_access_token():
                    headers["Authorization"] = f"Bearer {self.access_token}"
                    response = requests.get(url, headers=headers, params=params)

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

    def _get_device_groups(self):
        """Get all device configuration groups from Intune."""
        all_groups = []

        # Get all device groups
        endpoint = "/groups"
        params = {
            "$filter": "resourceProvisioningOptions/Any(x:x eq 'Intune')",
            "$select": "id,displayName",
        }

        result = self._graph_api_call(endpoint, params)

        if result and "value" in result:
            all_groups.extend(result["value"])

            # Handle pagination
            while "@odata.nextLink" in result:
                next_url = result["@odata.nextLink"].replace(self.graph_url, "")
                result = self._graph_api_call(next_url)
                if result and "value" in result:
                    all_groups.extend(result["value"])

        return all_groups

    def _get_devices_from_group(self, group_id):
        """Get device IDs that are members of a specific group."""
        device_ids = []

        # Get group members
        endpoint = f"/groups/{group_id}/members"
        params = {
            "$select": "id,deviceId",
            "$filter": "deviceId ne null",  # Only get devices, not users
        }

        result = self._graph_api_call(endpoint, params)

        if result and "value" in result:
            for member in result["value"]:
                # Check if this is a device (has deviceId property)
                if member.get("@odata.type") == "#microsoft.graph.device":
                    device_id = member.get("deviceId") or member.get("id")
                    if device_id:
                        device_ids.append(device_id)

            # Handle pagination
            while "@odata.nextLink" in result:
                next_url = result["@odata.nextLink"].replace(self.graph_url, "")
                result = self._graph_api_call(next_url)
                if result and "value" in result:
                    for member in result["value"]:
                        if member.get("@odata.type") == "#microsoft.graph.device":
                            device_id = member.get("deviceId") or member.get("id")
                            if device_id:
                                device_ids.append(device_id)

        return device_ids

    def _get_managed_devices(self):
        """Get all managed devices from Intune."""
        all_devices = []
        allowed_device_ids = set()

        # If device groups are specified, get their members first
        if self.device_groups_list:
            self.logger.info(
                f"Filtering by device groups: {', '.join(self.device_groups_list)}"
            )

            # Get all groups to match names to IDs
            all_groups = self._get_device_groups()

            # Find matching groups
            for group_filter in self.device_groups_list:
                group_found = False
                for group in all_groups:
                    # Match by name or ID
                    if group_filter.lower() in [
                        group.get("displayName", "").lower(),
                        group.get("id", "").lower(),
                    ]:
                        group_found = True
                        self.logger.info(
                            f"Processing group: {group.get('displayName')} ({group.get('id')})"
                        )

                        # Get devices from this group
                        device_ids = self._get_devices_from_group(group.get("id"))
                        allowed_device_ids.update(device_ids)
                        self.logger.info(
                            f"Found {len(device_ids)} devices in group {group.get('displayName')}"
                        )

                if not group_found:
                    self.logger.warning(f"Device group '{group_filter}' not found")

            if not allowed_device_ids:
                self.logger.warning("No devices found in specified groups")
                return []

        # Build filter if provided
        params = {
            # Request available fields from managedDevice
            "$select": (
                "id,deviceName,operatingSystem,complianceState,enrolledDateTime,"
                "lastSyncDateTime,model,manufacturer,serialNumber,deviceEnrollmentType,"
                "deviceCategoryDisplayName,managementAgent,isEncrypted,isSupervised,"
                "userPrincipalName,userDisplayName,azureADDeviceId,"
                "wiFiMacAddress,ethernetMacAddress"
            )
        }
        if self.device_filter:
            params["$filter"] = self.device_filter

        # Initial request
        endpoint = "/deviceManagement/managedDevices"
        result = self._graph_api_call(endpoint, params)

        if result and "value" in result:
            for device in result["value"]:
                # If groups are specified, only include devices in those groups
                if self.device_groups_list:
                    if device.get("id") in allowed_device_ids:
                        all_devices.append(device)
                else:
                    all_devices.append(device)

            # Handle pagination
            while "@odata.nextLink" in result:
                next_url = result["@odata.nextLink"].replace(self.graph_url, "")
                result = self._graph_api_call(next_url)
                if result and "value" in result:
                    for device in result["value"]:
                        # If groups are specified, only include devices in those groups
                        if self.device_groups_list:
                            if device.get("id") in allowed_device_ids:
                                all_devices.append(device)
                        else:
                            all_devices.append(device)

        return all_devices

    def _determine_platform(self, device):
        """Determine the platform based on device properties."""
        os_type = device.get("operatingSystem", "").lower()

        if "windows" in os_type:
            return "Windows"
        elif "android" in os_type:
            return "Android"
        elif "ios" in os_type or "ipad" in os_type or "iphone" in os_type:
            return "iOS"
        elif "macos" in os_type or "mac" in os_type:
            return "MacOS"
        elif "linux" in os_type:
            return "Linux"
        else:
            return "Generic"

    def _determine_architecture(self, device):
        """Determine architecture based on device model and OS."""
        model = device.get("model", "").lower()
        manufacturer = device.get("manufacturer", "").lower()
        os_type = device.get("operatingSystem", "").lower()

        # Check for ARM devices
        if "arm" in model or "m1" in model or "m2" in model or "m3" in model:
            return "arm64"
        # Mobile devices are typically ARM
        elif any(
            mobile_os in os_type for mobile_os in ["android", "ios", "ipad", "iphone"]
        ):
            return "arm64"
        # Apple Silicon Macs
        elif "mac" in os_type and "apple" in manufacturer:
            # Newer Macs might be ARM
            return (
                "arm64"
                if any(
                    year in model
                    for year in ["2020", "2021", "2022", "2023", "2024", "2025"]
                )
                else "x86_64"
            )
        # Default to x86_64 for desktops/laptops
        else:
            return "x86_64"

    def _get_mac_addresses(self, device):
        """Extract MAC addresses from device."""
        mac_addresses = []

        # Get WiFi MAC address
        wifi_mac = device.get("wiFiMacAddress")
        if wifi_mac:
            mac_addresses.append(wifi_mac.upper())

        # Get Ethernet MAC address
        ethernet_mac = device.get("ethernetMacAddress")
        if ethernet_mac and ethernet_mac not in mac_addresses:
            mac_addresses.append(ethernet_mac.upper())

        return mac_addresses

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
        """Process message to collect devices and upsert them as endpoints."""
        try:
            self.logger.info("Starting Microsoft Intune device collection...")

            # Get all managed devices
            devices = self._get_managed_devices()
            self.logger.info(f"Found {len(devices)} managed devices in Intune")

            # Process each device and upsert as endpoint
            for device in devices:
                device_name = device.get("deviceName", "unknown")
                device_id = device.get("id", "")

                # Get device properties
                compliance_state = device.get("complianceState", "unknown")
                enrollment_date = device.get("enrolledDateTime", "")
                last_sync = device.get("lastSyncDateTime", "")
                model = device.get("model", "")
                manufacturer = device.get("manufacturer", "")
                serial_number = device.get("serialNumber", "")
                os_type = device.get("operatingSystem", "")

                # Don't skip based on compliance - import all devices

                # Determine platform and architecture
                platform = self._determine_platform(device)
                arch = self._determine_architecture(device)

                # Get MAC addresses
                mac_addresses = self._get_mac_addresses(device)

                # Build description
                description_parts = ["Intune Managed Device"]
                if model:
                    description_parts.append(f"Model: {model}")
                if manufacturer:
                    description_parts.append(f"Manufacturer: {manufacturer}")
                if compliance_state:
                    description_parts.append(f"Compliance: {compliance_state}")
                if serial_number:
                    description_parts.append(f"Serial: {serial_number}")
                if enrollment_date:
                    description_parts.append(
                        f"Enrolled: {enrollment_date[:10]}"
                    )  # Just date part
                if last_sync:
                    description_parts.append(
                        f"Last Sync: {last_sync[:10]}"
                    )  # Just date part

                # Create endpoint object
                endpoint = {
                    "asset_name": device_name,
                    "asset_external_reference": device_id,  # Using Intune device ID as external reference
                    "endpoint_hostname": device.get("deviceName", device_name),
                    "endpoint_platform": platform,
                    "endpoint_arch": arch,
                    "asset_description": ", ".join(description_parts),
                }

                # Add MAC addresses if available
                if mac_addresses:
                    endpoint["endpoint_mac_addresses"] = mac_addresses

                # Create and collect tag IDs
                tag_ids = []
                tag_colors = {
                    "source": "#ef4444",  # Red
                    "compliance": "#10b981",  # Green
                    "enrollment": "#3b82f6",  # Blue
                    "category": "#8b5cf6",  # Purple
                    "manufacturer": "#f59e0b",  # Amber
                    "model": "#06b6d4",  # Cyan
                    "os": "#ec4899",  # Pink
                    "encrypted": "#22c55e",  # Green
                    "supervised": "#14b8a6",  # Teal
                    "agent": "#f97316",  # Orange
                }

                # Add collector source tag
                source_tag_name = "source:microsoft-intune"
                source_tag_id = self._create_or_get_tag(
                    source_tag_name, tag_colors["source"]
                )
                if source_tag_id:
                    tag_ids.append(source_tag_id)

                # Add compliance tag
                if compliance_state:
                    tag_name = f"compliance:{compliance_state.lower()}"
                    tag_id = self._create_or_get_tag(tag_name, tag_colors["compliance"])
                    if tag_id:
                        tag_ids.append(tag_id)

                # Add management agent tag
                if device.get("managementAgent"):
                    tag_name = f"agent:{device.get('managementAgent').lower()}"
                    tag_id = self._create_or_get_tag(tag_name, tag_colors["agent"])
                    if tag_id:
                        tag_ids.append(tag_id)

                # Add enrollment type tag
                if device.get("deviceEnrollmentType"):
                    tag_name = (
                        f"enrollment:{device.get('deviceEnrollmentType').lower()}"
                    )
                    tag_id = self._create_or_get_tag(tag_name, tag_colors["enrollment"])
                    if tag_id:
                        tag_ids.append(tag_id)

                # Add device category tag
                if device.get("deviceCategoryDisplayName"):
                    tag_name = (
                        f"category:{device.get('deviceCategoryDisplayName').lower()}"
                    )
                    tag_id = self._create_or_get_tag(tag_name, tag_colors["category"])
                    if tag_id:
                        tag_ids.append(tag_id)

                # Add manufacturer tag
                if manufacturer and manufacturer.lower() not in ["unknown", "n/a", ""]:
                    tag_name = f"manufacturer:{manufacturer.lower()}"
                    tag_id = self._create_or_get_tag(
                        tag_name, tag_colors["manufacturer"]
                    )
                    if tag_id:
                        tag_ids.append(tag_id)

                # Add model tag (sanitized)
                if model and model.lower() not in ["unknown", "n/a", ""]:
                    # Clean model name for tag
                    model_clean = (
                        model[:50]
                        .replace("/", "-")
                        .replace("\\", "-")
                        .replace(" ", "-")
                    )
                    tag_name = f"model:{model_clean.lower()}"
                    tag_id = self._create_or_get_tag(tag_name, tag_colors["model"])
                    if tag_id:
                        tag_ids.append(tag_id)

                # Add OS tag
                if os_type:
                    os_tag = (
                        os_type.split()[0].lower()
                        if " " in os_type
                        else os_type.lower()
                    )
                    tag_name = f"os:{os_tag}"
                    tag_id = self._create_or_get_tag(tag_name, tag_colors["os"])
                    if tag_id:
                        tag_ids.append(tag_id)

                # Add security tags
                if device.get("isEncrypted"):
                    tag_id = self._create_or_get_tag(
                        "security:encrypted", tag_colors["encrypted"]
                    )
                    if tag_id:
                        tag_ids.append(tag_id)

                if device.get("isSupervised"):
                    tag_id = self._create_or_get_tag(
                        "management:supervised", tag_colors["supervised"]
                    )
                    if tag_id:
                        tag_ids.append(tag_id)

                # Add tags to endpoint if any were created
                if tag_ids:
                    endpoint["asset_tags"] = tag_ids

                # Upsert endpoint
                try:
                    self.api.endpoint.upsert(endpoint)
                    self.logger.info(f"Successfully upserted endpoint: {device_name}")
                except Exception as e:
                    self.logger.error(
                        f"Failed to upsert endpoint {device_name}: {str(e)}"
                    )

            self.logger.info("Microsoft Intune device collection completed")

        except Exception as e:
            self.logger.error(f"Error during device collection: {str(e)}")


if __name__ == "__main__":
    OpenAEVMicrosoftIntune(configuration=ConfigLoader().to_daemon_config()).start()
