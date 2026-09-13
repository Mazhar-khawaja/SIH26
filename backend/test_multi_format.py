import os
import unittest
from app.ingestion.ingestion_manager import IngestionManager


class TestMultiFormatIngestion(unittest.TestCase):
    def setUp(self):
        self.db_file = "data/test_ulpf.db"
        if os.path.exists(self.db_file):
            os.remove(self.db_file)
        self.manager = IngestionManager(database_path=self.db_file)

    def tearDown(self):
        if os.path.exists(self.db_file):
            os.remove(self.db_file)

    def test_supported_formats(self):
        formats = self.manager.supported_formats()
        expected = ["json", "cef", "leef", "syslog", "xml", "csv"]
        self.assertEqual(formats, expected)

    def test_pipeline_syslog(self):
        log = "<134>Sep 13 22:00:00 server1 src=192.168.1.1 dst=10.0.0.1 action=ALLOW"
        res = self.manager.process_log(log)
        self.assertEqual(res["event"]["parser"], "syslog")
        self.assertEqual(res["event"]["raw_event"], log)
        self.assertTrue(res["integrity"]["verified"])

    def test_pipeline_json(self):
        log = '{"source_ip": "192.168.1.2", "destination_ip": "10.0.0.2", "action": "DENY"}'
        res = self.manager.process_log(log)
        self.assertEqual(res["event"]["parser"], "json")
        self.assertEqual(res["event"]["raw_event"], log)
        self.assertTrue(res["integrity"]["verified"])

    def test_pipeline_cef(self):
        log = "CEF:0|Vendor|Product|1.0|100|Event|5|src=192.168.1.3 dst=10.0.0.3 act=ALLOW"
        res = self.manager.process_log(log)
        self.assertEqual(res["event"]["parser"], "cef")
        self.assertEqual(res["event"]["raw_event"], log)
        self.assertTrue(res["integrity"]["verified"])

    def test_pipeline_xml(self):
        log = "<security><source_ip>192.168.1.4</source_ip><destination_ip>10.0.0.4</destination_ip><action>ALLOW</action></security>"
        res = self.manager.process_log(log)
        self.assertEqual(res["event"]["parser"], "xml")
        self.assertEqual(res["event"]["source_ip"], "192.168.1.4")
        self.assertEqual(res["event"]["destination_ip"], "10.0.0.4")
        self.assertEqual(res["event"]["raw_event"], log)
        self.assertTrue(res["integrity"]["verified"])

    def test_pipeline_csv(self):
        log = "src,dst,sport,dport,act\n192.168.1.5,10.0.0.5,1234,80,ALLOW"
        res = self.manager.process_log(log)
        self.assertEqual(res["event"]["parser"], "csv")
        self.assertEqual(res["event"]["source_ip"], "192.168.1.5")
        self.assertEqual(res["event"]["destination_ip"], "10.0.0.5")
        self.assertEqual(res["event"]["raw_event"], log)
        self.assertTrue(res["integrity"]["verified"])

    def test_pipeline_leef(self):
        log = "LEEF:2.0|CheckPoint|FW|1.0|Login\tsrc=192.168.1.6\tdst=10.0.0.6\tact=ALLOW"
        res = self.manager.process_log(log)
        self.assertEqual(res["event"]["parser"], "leef")
        self.assertEqual(res["event"]["source_ip"], "192.168.1.6")
        self.assertEqual(res["event"]["destination_ip"], "10.0.0.6")
        self.assertEqual(res["event"]["raw_event"], log)
        self.assertTrue(res["integrity"]["verified"])

    def test_pipeline_unknown(self):
        log = "UNSTRUCTURED_LOG_MESSAGE_12345"
        res = self.manager.process_log(log)
        self.assertEqual(res["event"]["parser"], "unknown")
        self.assertEqual(res["event"]["raw_event"], log)
        self.assertTrue(res["integrity"]["verified"])


if __name__ == "__main__":
    unittest.main()
