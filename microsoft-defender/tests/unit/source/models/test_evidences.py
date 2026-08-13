import unittest

import src.source.models.evidences as module


class FakeAlert(module.BaseModel):
    evidence: module.Evidence

class TestEvidence(unittest.TestCase):
    def test_process_evidence(self):
        process_data = {
            "@odata.type": "#microsoft.graph.security.processEvidence",
            "imageFile": {"fileName": "deadbeef.exe"},
            "parentProcessImageFile": {"fileName": "badc0ffee.exe"},
        }

        process_evidence = FakeAlert(evidence=process_data).evidence

        self.assertIsInstance(process_evidence, module.processEvidence)
        self.assertEqual(
            process_evidence.odata_type, "#microsoft.graph.security.processEvidence"
        )
        self.assertEqual(process_evidence.image_file.file_name, "deadbeef.exe")
        self.assertEqual(
            process_evidence.parent_process_image_file.file_name, "badc0ffee.exe"
        )
        self.assertIsNone(process_evidence.process_command_line)

        extracted_evidences = process_evidence.extract_evidences()

        self.assertIn(module.SignatureTypes.SIG_TYPE_PROCESS_NAME, extracted_evidences)
        self.assertEqual(
            extracted_evidences[module.SignatureTypes.SIG_TYPE_PROCESS_NAME],
            ["deadbeef.exe", "badc0ffee.exe"],
        )
        self.assertIn(
            module.SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME, extracted_evidences
        )
        self.assertEqual(
            extracted_evidences[module.SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME],
            ["deadbeef.exe", "badc0ffee.exe"],
        )
        self.assertNotIn(
            module.SignatureTypes.SIG_TYPE_COMMAND_LINE, extracted_evidences
        )

    def test_device_evidence(self):
        device_data = {
            "@odata.type": "#microsoft.graph.security.deviceEvidence",
            "deviceDnsName": "me.here",
            "hostName": "me",
            "lastIpAddress": "1.2.3.4",
        }

        device_evidence = FakeAlert(evidence=device_data).evidence

        self.assertIsInstance(device_evidence, module.deviceEvidence)
        self.assertEqual(
            device_evidence.odata_type, "#microsoft.graph.security.deviceEvidence"
        )
        self.assertEqual(device_evidence.device_dns_name, "me.here")
        self.assertEqual(device_evidence.host_name, "me")
        self.assertEqual(str(device_evidence.last_ip_address), "1.2.3.4")
        self.assertIsNone(device_evidence.last_external_ip_address)

        extracted_evidences = device_evidence.extract_evidences()

        self.assertIn(
            module.SignatureTypes.SIG_TYPE_TARGET_HOSTNAME_ADDRESS, extracted_evidences
        )
        self.assertEqual(
            extracted_evidences[module.SignatureTypes.SIG_TYPE_TARGET_HOSTNAME_ADDRESS],
            ["me.here", "me"],
        )
        self.assertIn(
            module.SignatureTypes.SIG_TYPE_TARGET_IPV4_ADDRESS, extracted_evidences
        )
        self.assertEqual(
            extracted_evidences[module.SignatureTypes.SIG_TYPE_TARGET_IPV4_ADDRESS],
            ["1.2.3.4"],
        )

    def test_file_evidence(self):
        file_data = {
            "@odata.type": "#microsoft.graph.security.fileEvidence",
            "fileDetails": {
                "fileName": "myfile.exe",
                "filePath": "/this/is/myfile.exe",
            },
        }
        file_evidence = FakeAlert(evidence=file_data).evidence

        self.assertIsInstance(file_evidence, module.fileEvidence)
        self.assertEqual(
            file_evidence.odata_type, "#microsoft.graph.security.fileEvidence"
        )
        self.assertEqual(file_evidence.file_details.file_name, "myfile.exe")
        self.assertEqual(file_evidence.file_details.file_path, "/this/is/myfile.exe")

        extracted_evidences = file_evidence.extract_evidences()

        self.assertIn(module.SignatureTypes.SIG_TYPE_FILE_NAME, extracted_evidences)
        self.assertEqual(
            extracted_evidences[module.SignatureTypes.SIG_TYPE_FILE_NAME],
            ["myfile.exe", "/this/is/myfile.exe"],
        )

    def test_ip_evidence(self):
        ip_data = {
            "@odata.type": "#microsoft.graph.security.ipEvidence",
            "ipAddress": "1.2.3.4",
        }
        ip_evidence = FakeAlert(evidence=ip_data).evidence

        self.assertIsInstance(ip_evidence, module.ipEvidence)
        self.assertEqual(ip_evidence.odata_type, "#microsoft.graph.security.ipEvidence")
        self.assertEqual(str(ip_evidence.ip_address), "1.2.3.4")

        extracted_evidences = ip_evidence.extract_evidences()

        self.assertIn(
            module.SignatureTypes.SIG_TYPE_TARGET_IPV4_ADDRESS, extracted_evidences
        )
        self.assertEqual(
            extracted_evidences[module.SignatureTypes.SIG_TYPE_TARGET_IPV4_ADDRESS],
            ["1.2.3.4"],
        )

    def test_generic_evidence(self):
        generic_data = {
            "@odata.type": "#microsoft.graph.security.userEvidence",
            "key": "value",
        }
        generic_evidence = FakeAlert(evidence=generic_data).evidence

        self.assertIsInstance(generic_evidence, module.genericEvidence)
        self.assertEqual(
            generic_evidence.odata_type, "#microsoft.graph.security.userEvidence"
        )
        self.assertEqual(generic_evidence.extract_evidences(), {})

    def test_evidence_discriminator(self):
        supported = [
            "#microsoft.graph.security.fileEvidence",
            "#microsoft.graph.security.deviceEvidence",
            "#microsoft.graph.security.processEvidence",
            "#microsoft.graph.security.ipEvidence",
        ]
        for odata_type in supported:
            self.assertEqual(
                odata_type,
                module.discriminate_evidence_type({"@odata.type": odata_type}),
            )

        unsupported = [
            "#microsoft.graph.security.userEvidence",
            "#microsoft.graph.notsecurity.somethingelse",
            "foobar",
        ]
        for odata_type in unsupported:
            self.assertEqual(
                "generic",
                module.discriminate_evidence_type({"@odata.type": odata_type}),
            )
