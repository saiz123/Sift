import os
import sys
import tempfile
import unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


def _make_db(path):
    import config as cfg
    cfg.DB_PATH = path
    from sift.storage import db
    db.init_db()
    return db


def _insert_alert(db, rule_id="R1", target="host1", verdict="REVIEW"):
    alert = {
        "source": "wazuh", "rule_id": rule_id, "rule_desc": "test",
        "rule_level": 5, "src_ip": "1.2.3.4", "src_user": "bob",
        "target": target, "file_hash": None, "raw": {},
    }
    return db.insert_alert(alert, 30, verdict, [])


class TestRecordFeedback(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self._tmp.close()
        self.db = _make_db(self._tmp.name)

    def tearDown(self):
        os.unlink(self._tmp.name)

    def test_true_positive_increments_total(self):
        aid = _insert_alert(self.db)
        self.db.record_feedback(aid, "true_positive")
        stats = self.db.get_rule_stats("R1")
        self.assertEqual(stats["total"], 1)
        self.assertEqual(stats["fp"], 0)

    def test_false_positive_increments_fp(self):
        aid = _insert_alert(self.db)
        self.db.record_feedback(aid, "false_positive")
        stats = self.db.get_rule_stats("R1")
        self.assertEqual(stats["total"], 1)
        self.assertEqual(stats["fp"], 1)

    def test_re_decision_adjusts_tally(self):
        aid = _insert_alert(self.db)
        self.db.record_feedback(aid, "false_positive")
        self.db.record_feedback(aid, "true_positive")
        stats = self.db.get_rule_stats("R1")
        self.assertEqual(stats["total"], 1)
        self.assertEqual(stats["fp"], 0)

    def test_multiple_alerts_accumulate(self):
        aid1 = _insert_alert(self.db)
        aid2 = _insert_alert(self.db)
        self.db.record_feedback(aid1, "false_positive")
        self.db.record_feedback(aid2, "false_positive")
        stats = self.db.get_rule_stats("R1")
        self.assertEqual(stats["total"], 2)
        self.assertEqual(stats["fp"], 2)

    def test_nonexistent_alert_returns_false(self):
        self.assertFalse(self.db.record_feedback(9999, "true_positive"))

    def test_invalid_verdict_raises(self):
        aid = _insert_alert(self.db)
        with self.assertRaises(ValueError):
            self.db.record_feedback(aid, "maybe")

    def test_per_target_stats_updated(self):
        aid = _insert_alert(self.db, rule_id="R2", target="dc01")
        self.db.record_feedback(aid, "false_positive")
        stats = self.db.get_rule_target_stats("R2", "dc01")
        self.assertIsNotNone(stats)
        self.assertEqual(stats["fp"], 1)

    def test_no_rule_id_does_not_crash(self):
        aid = _insert_alert(self.db, rule_id=None)
        result = self.db.record_feedback(aid, "true_positive")
        self.assertTrue(result)


class TestAuditLog(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self._tmp.close()
        self.db = _make_db(self._tmp.name)

    def tearDown(self):
        os.unlink(self._tmp.name)

    def test_insert_logs_events(self):
        aid = _insert_alert(self.db)
        events = self.db.get_alert_events(aid)
        event_types = [e["event_type"] for e in events]
        self.assertIn("alert_ingested", event_types)
        self.assertIn("alert_scored", event_types)

    def test_feedback_logs_event(self):
        aid = _insert_alert(self.db)
        self.db.record_feedback(aid, "true_positive")
        events = self.db.get_alert_events(aid)
        event_types = [e["event_type"] for e in events]
        self.assertIn("feedback_true_positive", event_types)

    def test_snooze_logs_event(self):
        aid = _insert_alert(self.db)
        self.db.snooze_alert(aid, "2099-01-01T00:00:00")
        events = self.db.get_alert_events(aid)
        self.assertIn("snoozed", [e["event_type"] for e in events])

    def test_unsnooze_logs_event(self):
        aid = _insert_alert(self.db)
        self.db.snooze_alert(aid, "2099-01-01T00:00:00")
        self.db.unsnooze_alert(aid)
        events = self.db.get_alert_events(aid)
        self.assertIn("unsnoozed", [e["event_type"] for e in events])


class TestCacheGetTTL(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self._tmp.close()
        self.db = _make_db(self._tmp.name)

    def tearDown(self):
        os.unlink(self._tmp.name)

    def test_cache_hit_within_ttl(self):
        self.db.cache_set("test_key", {"data": 1})
        result = self.db.cache_get("test_key", max_age_hours=24)
        self.assertIsNotNone(result)
        self.assertEqual(result["data"], 1)

    def test_cache_miss_expired_ttl(self):
        # Write an entry with a very old cached_at timestamp
        import sqlite3, contextlib, config as cfg
        with contextlib.closing(sqlite3.connect(cfg.DB_PATH)) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO enrich_cache (cache_key, value_json, cached_at) VALUES (?,?,?)",
                ("old_key", '{"data": 2}', "2000-01-01T00:00:00"),
            )
            conn.commit()
        result = self.db.cache_get("old_key", max_age_hours=1)
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
