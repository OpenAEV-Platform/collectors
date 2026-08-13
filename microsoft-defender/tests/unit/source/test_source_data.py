import unittest

import src.source.source_data as module
from src.source.models.evidences import processEvidence


class TestAlert(unittest.TestCase):
    def test_alert_init_minimal(self):
        data = {
            "id": "my-id",
            "title": "this is a title",
            "status": "inProgress",
            "serviceSource": "microsoftDefenderForEndpoint",
            "alertWebUrl": "http://endpoint.tld",
            "createdDateTime": "1987-06-05T04:03:02.1",
            "evidence": [],
        }

        alert = module.Alert(**data)

        self.assertEqual(alert.id, "my-id")
        self.assertEqual(alert.title, "this is a title")
        self.assertEqual(alert.status, "inProgress")
        self.assertEqual(alert.service_source, "microsoftDefenderForEndpoint")
        self.assertEqual(str(alert.alert_web_url), "http://endpoint.tld/")
        self.assertEqual(alert.created_date_time.isoformat(), "1987-06-05T04:03:02.100000")
        self.assertEqual(alert.evidence, [])
        self.assertEqual(alert.raw, data)

    def test_alert_extract_evidences(self):
        data = {
            "id": "my-id",
            "title": "this is a title",
            "status": "inProgress",
            "serviceSource": "microsoftDefenderForEndpoint",
            "alertWebUrl": "http://endpoint.tld",
            "createdDateTime": "1987-06-05T04:03:02.1",
            "evidence": [
                {
                    "@odata.type": "#microsoft.graph.security.processEvidence",
                    "imageFile": {"fileName": "cuckoo_agent.exe"}
                },
            ],
        }

        alert = module.Alert(**data)

        self.assertIsInstance(alert.evidence[0], processEvidence)

        evidences = alert._extract_evidences()

        self.assertIn(module.SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME, evidences)
        self.assertEqual(evidences[module.SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME], set(["cuckoo_agent.exe"]))

    def test_alert_to_oaev_data(self):
        data = {
            "id": "my-id",
            "title": "this is a title",
            "status": "inProgress",
            "serviceSource": "microsoftDefenderForEndpoint",
            "alertWebUrl": "http://endpoint.tld",
            "createdDateTime": "1987-06-05T04:03:02.1",
            "evidence": [
                {
                    "@odata.type": "#microsoft.graph.security.processEvidence",
                    "imageFile": {"fileName": "cuckoo_agent.exe"}
                },
            ],
        }

        alert = module.Alert(**data)

        oaev_data = alert.to_oaev_data()

        self.assertIsInstance(oaev_data, module.OAEVData)
        self.assertEqual(oaev_data.parent_process_name, ["cuckoo_agent.exe"])

    def test_alert_to_traces_data(self):
        data = {
            "id": "my-id",
            "title": "this is a title",
            "status": "inProgress",
            "serviceSource": "microsoftDefenderForEndpoint",
            "alertWebUrl": "http://endpoint.tld",
            "createdDateTime": "1987-06-05T04:03:02.1",
            "evidence": [
                {
                    "@odata.type": "#microsoft.graph.security.processEvidence",
                    "imageFile": {"fileName": "cuckoo_agent.exe"}
                },
            ],
        }

        alert = module.Alert(**data)

        traces_data = alert.to_traces_data()

        self.assertIsInstance(traces_data, module.TraceData)
        self.assertEqual(traces_data.alert_name, data["title"])
        self.assertEqual(str(traces_data.alert_link), "http://endpoint.tld/")

    def test_alert_is_prevented_detected(self):
        data = {
            "id": "my-id",
            "title": "this is a title",
            "status": "inProgress",
            "serviceSource": "microsoftDefenderForEndpoint",
            "alertWebUrl": "http://endpoint.tld",
            "createdDateTime": "1987-06-05T04:03:02.1",
            "evidence": [
                {
                    "@odata.type": "#microsoft.graph.security.processEvidence",
                    "imageFile": {"fileName": "cuckoo_agent.exe"}
                },
            ],
        }

        alert = module.Alert(**data)

        self.assertTrue(alert.is_detected())
        
        for status in ["inProgress", "resolved"]:
            alert.status = status
            self.assertTrue(alert.is_prevented())

        for status in ["unknown", "new", "unknownFutureValue"]:
            alert.status = status
            self.assertFalse(alert.is_prevented())
