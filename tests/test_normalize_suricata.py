import unittest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from sift.core.normalize import normalize_suricata, normalize_crowdstrike, normalize_osquery


SURICATA_ALERT = {
    "timestamp": "2025-06-13T03:22:10.123456+0000",
    "event_type": "alert",
    "src_ip": "45.146.165.37",
    "dest_ip": "10.0.0.5",
    "host": "sensor-01",
    "alert": {
        "signature_id": 2024897,
        "signature": "ET MALWARE Cobalt Strike Beacon Activity",
        "category": "A Network Trojan was detected",
        "severity": 1,
    },
}


class TestNormalizeSuricata(unittest.TestCase):

    def test_alert_event_parsed(self):
        a = normalize_suricata(SURICATA_ALERT)
        self.assertIsNotNone(a)
        self.assertEqual(a["source"], "suricata")
        self.assertEqual(a["rule_id"], "2024897")
        self.assertEqual(a["src_ip"], "45.146.165.37")
        self.assertEqual(a["target"], "10.0.0.5")

    def test_severity_1_maps_to_level_15(self):
        a = normalize_suricata(SURICATA_ALERT)
        self.assertEqual(a["rule_level"], 15)

    def test_severity_3_maps_to_level_5(self):
        raw = {**SURICATA_ALERT, "alert": {**SURICATA_ALERT["alert"], "severity": 3}}
        a = normalize_suricata(raw)
        self.assertEqual(a["rule_level"], 5)

    def test_non_alert_event_skipped(self):
        raw = {**SURICATA_ALERT, "event_type": "flow"}
        self.assertIsNone(normalize_suricata(raw))

    def test_dns_event_skipped(self):
        self.assertIsNone(normalize_suricata({"event_type": "dns", "dns": {}}))

    def test_non_dict_skipped(self):
        self.assertIsNone(normalize_suricata("not a dict"))
        self.assertIsNone(normalize_suricata(None))

    def test_missing_alert_key_skipped(self):
        self.assertIsNone(normalize_suricata({"event_type": "alert"}))

    def test_file_hash_from_fileinfo(self):
        raw = {**SURICATA_ALERT, "fileinfo": {"sha256": "deadbeef", "md5": "cafebabe"}}
        a = normalize_suricata(raw)
        self.assertEqual(a["file_hash"], "deadbeef")


class TestNormalizeCrowdStrike(unittest.TestCase):

    DETECTION = {
        "event": {
            "EventType": "DetectionSummaryEvent",
            "DetectId": "ldt:abc:123",
            "DetectDescription": "Credential dumping",
            "SeverityName": "Critical",
            "ComputerName": "dc01",
            "UserName": "svc_backup",
            "RemoteAddress": "45.146.165.37",
            "SHA256String": "abc123",
            "ProcessStartTime": 1718500000,
        }
    }

    def test_detection_parsed(self):
        a = normalize_crowdstrike(self.DETECTION)
        self.assertIsNotNone(a)
        self.assertEqual(a["source"], "crowdstrike")
        self.assertEqual(a["rule_level"], 15)
        self.assertEqual(a["target"], "dc01")
        self.assertEqual(a["src_user"], "svc_backup")
        self.assertEqual(a["file_hash"], "abc123")

    def test_non_detection_event_skipped(self):
        raw = {"event": {"EventType": "UserActivityAuditEvent"}}
        self.assertIsNone(normalize_crowdstrike(raw))

    def test_missing_event_type_skipped(self):
        self.assertIsNone(normalize_crowdstrike({"event": {}}))

    def test_severity_levels(self):
        for name, expected in [("critical", 15), ("high", 12), ("medium", 8), ("low", 4)]:
            raw = {"event": {**self.DETECTION["event"], "SeverityName": name}}
            a = normalize_crowdstrike(raw)
            self.assertEqual(a["rule_level"], expected, f"failed for {name}")


class TestNormalizeOsquery(unittest.TestCase):

    RESULT = {
        "name": "process_network_connections",
        "hostIdentifier": "web-01",
        "action": "added",
        "unixTime": 1718500447,
        "columns": {
            "pid": "4821",
            "remote_address": "45.146.165.37",
            "username": "www-data",
        },
    }

    def test_result_parsed(self):
        a = normalize_osquery(self.RESULT)
        self.assertIsNotNone(a)
        self.assertEqual(a["source"], "osquery")
        self.assertEqual(a["rule_id"], "process_network_connections")
        self.assertEqual(a["target"], "web-01")
        self.assertEqual(a["src_ip"], "45.146.165.37")
        self.assertEqual(a["src_user"], "www-data")

    def test_missing_columns_skipped(self):
        self.assertIsNone(normalize_osquery({"name": "something"}))

    def test_missing_name_skipped(self):
        self.assertIsNone(normalize_osquery({"columns": {}}))

    def test_non_dict_skipped(self):
        self.assertIsNone(normalize_osquery(None))

    def test_severity_keywords(self):
        raw = {**self.RESULT, "name": "kernel_modules_added"}
        a = normalize_osquery(raw)
        self.assertGreaterEqual(a["rule_level"], 9)


if __name__ == "__main__":
    unittest.main()
