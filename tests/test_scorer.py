import os
import sys
import tempfile
import unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import config
from sift.core.scorer import decide, score_alert


def setUpModule():
    """Use a temp DB so scorer's DB lookups don't fail with 'no such table'."""
    global _tmp_db
    _tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    _tmp_db.close()
    config.DB_PATH = _tmp_db.name
    from sift.storage import db
    db.init_db()


def tearDownModule():
    os.unlink(_tmp_db.name)


class TestDecide(unittest.TestCase):

    def test_below_junk(self):
        self.assertEqual(decide(config.JUNK_BELOW - 1), "JUNK")

    def test_exactly_junk_boundary(self):
        self.assertEqual(decide(config.JUNK_BELOW), "REVIEW")

    def test_review_range(self):
        mid = (config.JUNK_BELOW + config.ESCALATE_AT) // 2
        self.assertEqual(decide(mid), "REVIEW")

    def test_at_escalate(self):
        self.assertEqual(decide(config.ESCALATE_AT), "ESCALATE")

    def test_above_escalate(self):
        self.assertEqual(decide(999), "ESCALATE")

    def test_zero_is_junk(self):
        self.assertEqual(decide(0), "JUNK")

    def test_negative_is_junk(self):
        self.assertEqual(decide(-50), "JUNK")


class TestScoreAlert(unittest.TestCase):

    def _alert(self, **kw):
        base = {
            "source": "wazuh",
            "rule_id": "test_rule",
            "rule_desc": "test",
            "rule_level": 0,
            "severity_detail": "",
            "src_ip": None,
            "src_user": None,
            "target": None,
            "file_hash": None,
            "timestamp": None,
            "raw": {},
        }
        base.update(kw)
        return base

    def test_returns_tuple(self):
        score, verdict, receipt = score_alert(self._alert())
        self.assertIsInstance(score, int)
        self.assertIn(verdict, ("JUNK", "REVIEW", "ESCALATE"))
        self.assertIsInstance(receipt, list)

    def test_zero_level_minimal_score(self):
        score, verdict, receipt = score_alert(self._alert(rule_level=0))
        self.assertEqual(decide(score), verdict)

    def test_high_severity_raises_score(self):
        score_low, _, _ = score_alert(self._alert(rule_level=1))
        score_high, _, _ = score_alert(self._alert(rule_level=15))
        self.assertGreater(score_high, score_low)

    def test_critical_asset_adds_points(self):
        score_plain, _, _ = score_alert(self._alert(rule_level=5))
        score_crit, _, _ = score_alert(self._alert(rule_level=5, target="dc01"))
        self.assertGreater(score_crit, score_plain)

    def test_receipt_labels_are_strings(self):
        _, _, receipt = score_alert(self._alert(rule_level=5, target="dc01"))
        for item in receipt:
            self.assertIn("label", item)
            self.assertIsInstance(item["label"], str)

    def test_score_equals_sum_of_receipt(self):
        alert = self._alert(rule_level=7, target="prod-db")
        score, _, receipt = score_alert(alert)
        self.assertEqual(score, sum(item["points"] for item in receipt))

    def test_off_hours_adds_points(self):
        score_day, _, _ = score_alert(self._alert(
            rule_level=5, timestamp="2025-06-13T10:00:00Z"
        ))
        score_night, _, _ = score_alert(self._alert(
            rule_level=5, timestamp="2025-06-13T02:00:00Z"
        ))
        self.assertGreater(score_night, score_day)

    def test_verdict_matches_decide(self):
        alert = self._alert(rule_level=12, target="dc01")
        score, verdict, _ = score_alert(alert)
        self.assertEqual(verdict, decide(score))


if __name__ == "__main__":
    unittest.main()
