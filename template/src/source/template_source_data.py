import secrets

from src.collector.models.data import OAEVData, TraceData


class TemplateSourceData:
    """
    Placeholder source data, meant to follow the source data protocol
    """

    def __init__(self):
        """Generate random placeholder data"""
        self.value = secrets.token_hex(8)

    def to_oaev_data(self):
        """Serialize source data into OAEVData"""
        return OAEVData(parent_process_name=f"{self.value}")

    def to_traces_data(self):
        """Serialize traces data into TraceData"""
        return TraceData(
            alert_name=f"Alert {self.value}", alert_link=f"http://fake.url/{self.value}"
        )

    def is_prevented(self):
        """Placeholder analysis of the data to determine if the threat is prevented"""
        return bool(secrets.randbits(1))

    def is_detected(self):
        """Placeholder analysis of the data to determine if the threat is detected"""
        return bool(secrets.randbits(1))

    def __str__(self):
        """Str output of the source data for logging purposes"""
        return f"{self.value}"
