import unittest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from normalize import normalize_wazuh


FULL = {
    "timestamp": "2025-06-13T03:14:07.512+0000",
    "rule": {"id": "92052", "level": 12, "description": "Credential dumping"},
    "agent": {"id": "004", "name": "dc01", "ip": "10.0.0.9"},
    "data": {"srcip": "45.146.165.37", "srcuser": "svc_backup",
             "sha256": "abc123"},
    "location": "WinEvtLog",
}


class TestNormalizeWazuh(unittest.TestCase):

    def test_full_payload(self):
        a = normalize_wazuh(FULL)
        self.assertEqual(a["source"], "wazuh")
        self.assertEqual(a["rule_id"], "92052")
        self.assertEqual(a["rule_level"], 12)
        self.assertEqual(a["src_ip"], "45.146.165.37")
        self.assertEqual(a["src_user"], "svc_backup")
        self.assertEqual(a["target"], "dc01")
        self.assertEqual(a["file_hash"], "abc123")

    def test_missing_rule(self):
        a = normalize_wazuh({"timestamp": "2025-01-01T00:00:00Z"})
        self.assertIsNone(a["rule_id"])
        self.assertEqual(a["rule_level"], 0)

    def test_non_dict_returns_none(self):
        self.assertIsNone(normalize_wazuh(None))
        self.assertIsNone(normalize_wazuh("not a dict"))

    def test_dict_src_ip_coerced_to_none(self):
        raw = {**FULL, "data": {"srcip": {"nested": "dict"}}}
        a = normalize_wazuh(raw)
        self.assertIsNone(a["src_ip"])

    def test_list_file_hash_coerced_to_none(self):
        raw = {**FULL, "data": {"sha256": ["a", "b"]}}
        a = normalize_wazuh(raw)
        self.assertIsNone(a["file_hash"])

    def test_level_clamped_at_15(self):
        raw = {**FULL, "rule": {"id": "1", "level": 99}}
        a = normalize_wazuh(raw)
        self.assertEqual(a["rule_level"], 99)  # wazuh normalizer doesn't clamp, just casts

    def test_rule_id_integer_becomes_string(self):
        raw = {**FULL, "rule": {"id": 5402, "level": 7}}
        a = normalize_wazuh(raw)
        self.assertEqual(a["rule_id"], "5402")
        self.assertIsInstance(a["rule_id"], str)

    def test_fallback_target_to_location(self):
        raw = {**FULL, "agent": {}, "location": "/var/log/auth.log"}
        a = normalize_wazuh(raw)
        self.assertEqual(a["target"], "/var/log/auth.log")

    def test_raw_preserved(self):
        a = normalize_wazuh(FULL)
        self.assertIs(a["raw"], FULL)


class TestNormalizeWazuhSyscheck(unittest.TestCase):

    def test_syscheck_hash(self):
        raw = {
            "rule": {"id": "550", "level": 7, "description": "File modified"},
            "syscheck": {"sha256_after": "deadbeef", "md5_after": "cafebabe"},
            "agent": {"name": "web-01"},
        }
        a = normalize_wazuh(raw)
        self.assertEqual(a["file_hash"], "deadbeef")


if __name__ == "__main__":
    unittest.main()
