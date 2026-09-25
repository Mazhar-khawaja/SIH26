import unittest
from app.intelligence.providers.local import LocalProvider
from app.intelligence.service import IntelligenceService
from app.config.settings import settings

class TestIntelligence(unittest.TestCase):
    def setUp(self):
        self.provider = LocalProvider()
        self.service = IntelligenceService()
        settings.intelligence_enabled = True
        settings.ai_classification_threshold = 0.8

    def test_json_classification(self):
        log = '{"src_ip": "10.0.0.1", "action": "allow"}'
        res = self.provider.classify_format(log)
        self.assertEqual(res.format, "json")
        self.assertGreaterEqual(res.confidence, 0.95)

    def test_aws_cloudtrail_classification(self):
        log = '{"Records": [{"eventVersion": "1.08"}]}'
        res = self.provider.classify_format(log)
        self.assertEqual(res.format, "aws_cloudtrail")
        self.assertGreaterEqual(res.confidence, 0.95)

    def test_syslog_classification(self):
        log = '<34>Oct 11 22:14:15 mymachine su: su root failed for joe on /dev/pts/2'
        res = self.provider.classify_format(log)
        self.assertEqual(res.format, "syslog")
        self.assertGreaterEqual(res.confidence, 0.8)

    def test_cef_classification(self):
        log = 'CEF:0|Vendor|Product|1.0|1|Alert|3|src=10.0.0.1 dst=10.0.0.2'
        res = self.provider.classify_format(log)
        self.assertEqual(res.format, "cef")
        self.assertGreaterEqual(res.confidence, 0.9)

    def test_leef_classification(self):
        log = 'LEEF:1.0|Vendor|Product|1.0|1|src=10.0.0.1'
        res = self.provider.classify_format(log)
        self.assertEqual(res.format, "leef")
        self.assertGreaterEqual(res.confidence, 0.9)

    def test_xml_classification(self):
        log = '<Event><System><Provider Name="Microsoft"/></System></Event>'
        res = self.provider.classify_format(log)
        self.assertIn(res.format, ["xml", "windows_event"])
        self.assertGreaterEqual(res.confidence, 0.8)

    def test_csv_classification(self):
        log = '2023-10-11,10.0.0.1,192.168.1.1,443,ALLOW'
        res = self.provider.classify_format(log)
        self.assertEqual(res.format, "csv")
        self.assertGreaterEqual(res.confidence, 0.7)

    def test_unknown_classification(self):
        log = 'Just some random text without structure'
        res = self.provider.classify_format(log)
        self.assertEqual(res.format, "unknown")
        self.assertEqual(res.confidence, 0.0)

    def test_field_mapping(self):
        log = 'src_ip=10.0.0.1 dst_port=443 act=blocked'
        suggestions = self.provider.suggest_field_mapping(log, format_hint="unknown")

        targets = {s.target_field for s in suggestions}
        self.assertIn("source_ip", targets)
        self.assertIn("destination_port", targets)
        self.assertIn("action", targets)

    def test_service_approval_workflow(self):
        log = 'src=10.1.1.1 dst=8.8.8.8'
        approval = self.service.generate_mapping(log, "unknown")
        self.assertEqual(approval.status, "suggestion")

        approved = self.service.approve_mapping(approval.approval_id, "admin")
        self.assertEqual(approved.status, "approved")
        self.assertEqual(approved.approved_by, "admin")

        rejected = self.service.reject_mapping(approval.approval_id, "admin")
        self.assertEqual(rejected.status, "rejected")

    def test_service_disabled(self):
        settings.intelligence_enabled = False
        res = self.service.classify_log('{"a": 1}')
        self.assertEqual(res.format, "unknown")
        self.assertIn("disabled", res.reasons[0])

if __name__ == '__main__':
    unittest.main()
