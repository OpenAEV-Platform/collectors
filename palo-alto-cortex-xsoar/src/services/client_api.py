import random
import uuid
from datetime import datetime, timezone
from typing import Optional

from src.models.authentication import Authentication
from src.models.incident import XSOARSearchIncidentsResponse


class PaloAltoCortexXSOARClientAPI:
    def __init__(self, auth: Authentication, api_url: str) -> None:
        self._auth = auth
        self.api_url = api_url

    def search_incidents(
        self,
        from_date: Optional[str] = None,
        to_date: Optional[str] = None,
        search_from: int = 0,
        search_to: int = 100,
    ) -> XSOARSearchIncidentsResponse:
        _ = (from_date, to_date, search_from, search_to)

        incident_count = random.randint(1, 3)
        detection_timestamp = int(datetime.now(timezone.utc).timestamp() * 1000)

        data = []
        for _ in range(incident_count):
            data.append(
                {
                    "id": str(uuid.uuid4()),
                    "name": "Dummy XSOAR Incident",
                    "CustomFields": {
                        "xdralerts": [
                            {
                                "alert_id": str(uuid.uuid4()),
                                "case_id": random.randint(1, 1000),
                                "action_pretty": random.choice(
                                    ["Detected (Reported)", "Prevented (Blocked)"]
                                ),
                                "actor_process_command_line": (
                                    f"oaev-implant-{uuid.uuid4()}-agent-{uuid.uuid4()}"
                                ),
                                "actor_process_image_name": "oaev-implant.exe",
                                "actor_process_image_path": "C:/Dummy/oaev-implant.exe",
                                "detection_timestamp": detection_timestamp,
                            }
                        ]
                    },
                }
            )

        return XSOARSearchIncidentsResponse.model_validate(
            {"total": len(data), "data": data}
        )
