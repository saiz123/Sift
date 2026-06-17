import unittest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import config
from sift.core.checks import (
    _wilson_lower_bound, _ip_in_list,
    check_severity, check_critical_asset, check_bad_ip, check_bad_hash,
    check_off_hours, check_new_source_for_user, check_velocity,
    check_allowlisted_ip, check_allowlisted_user, check_allowlisted_hash,
    check_noisy_rule, check_duplicate_flood, check_threat_feed_ip, check_tor_exit,
)


def _ctx(**kw):
    base = {
        "hour": None, "rule_stats": None, "rule_target_stats": None,
        "rule_activity": None, "duplicate_count": 0, "ip_intel": None,
        "ip_feed_hit": None, "hash_intel": None,
        "user_history": {"total": 0, "seen_this_ip": False},
        "recent_ips": set(),
    }
    base.update(kw)
    return base


class TestWilsonLowerBound(unittest.TestCase):

    def test_zero_total(self):
        self.assertEqual(_wilson_lower_bound(0, 0, 1.96), 0.0)

    def test_zero_successes(self):
        self.assertAlmostEqual(_wilson_lower_bound(0, 10, 1.96), 0.0, places=10)

    def test_all_fp(self):
        lb = _wilson_lower_bound(10, 10, 1.96)
        self.assertGreater(lb, 0.7)
        self.assertLessEqual(lb, 1.0)

    def test_conservative_with_few_samples(self):
        lb_few = _wilson_lower_bound(1, 1, 1.96)
        lb_many = _wilson_lower_bound(100, 100, 1.96)
        self.assertLess(lb_few, lb_many)


class TestIpInList(unittest.TestCase):

    def test_exact_match(self):
        self.assertTrue(_ip_in_list("1.2.3.4", ["1.2.3.4"]))

    def test_cidr_match(self):
        self.assertTrue(_ip_in_list("192.168.1.50", ["192.168.1.0/24"]))

    def test_cidr_no_match(self):
        self.assertFalse(_ip_in_list("10.0.0.1", ["192.168.1.0/24"]))

    def test_invalid_ip_returns_false(self):
        self.assertFalse(_ip_in_list("not-an-ip", ["1.2.3.4"]))

    def test_empty_list(self):
        self.assertFalse(_ip_in_list("1.2.3.4", []))


class TestCheckSeverity(unittest.TestCase):

    def test_zero_level_returns_none(self):
        self.assertIsNone(check_severity({"rule_level": 0}, _ctx()))

    def test_positive_level_scores(self):
        line = check_severity({"rule_level": 5}, _ctx())
        self.assertIsNotNone(line)
        self.assertEqual(line["points"], 5 * config.WEIGHTS["severity_multiplier"])

    def test_missing_level_returns_none(self):
        self.assertIsNone(check_severity({}, _ctx()))


class TestCheckCriticalAsset(unittest.TestCase):

    def test_match(self):
        line = check_critical_asset({"target": "DC01"}, _ctx())
        self.assertIsNotNone(line)
        self.assertEqual(line["points"], config.WEIGHTS["critical_asset"])

    def test_no_match(self):
        self.assertIsNone(check_critical_asset({"target": "workstation-01"}, _ctx()))

    def test_no_target(self):
        self.assertIsNone(check_critical_asset({}, _ctx()))


class TestCheckBadIp(unittest.TestCase):

    def test_high_confidence(self):
        ctx = _ctx(ip_intel={"abuse_score": 85, "reports": 20})
        line = check_bad_ip({"src_ip": "1.2.3.4"}, ctx)
        self.assertIsNotNone(line)
        self.assertEqual(line["points"], config.WEIGHTS["bad_ip"])

    def test_borderline_half_weight(self):
        ctx = _ctx(ip_intel={"abuse_score": 30, "reports": 5})
        line = check_bad_ip({"src_ip": "1.2.3.4"}, ctx)
        self.assertEqual(line["points"], config.WEIGHTS["bad_ip"] // 2)

    def test_below_threshold(self):
        ctx = _ctx(ip_intel={"abuse_score": 10, "reports": 1})
        self.assertIsNone(check_bad_ip({"src_ip": "1.2.3.4"}, ctx))

    def test_no_intel(self):
        self.assertIsNone(check_bad_ip({"src_ip": "1.2.3.4"}, _ctx()))


class TestCheckBadHash(unittest.TestCase):

    def test_flagged_hash(self):
        ctx = _ctx(hash_intel={"malicious": 15, "total": 72})
        line = check_bad_hash({"file_hash": "abc"}, ctx)
        self.assertIsNotNone(line)
        self.assertEqual(line["points"], config.WEIGHTS["bad_hash"])

    def test_clean_hash(self):
        ctx = _ctx(hash_intel={"malicious": 0, "total": 72})
        self.assertIsNone(check_bad_hash({"file_hash": "abc"}, ctx))


class TestCheckOffHours(unittest.TestCase):

    def test_off_hours(self):
        line = check_off_hours({}, _ctx(hour=2))
        self.assertIsNotNone(line)
        self.assertEqual(line["points"], config.WEIGHTS["off_hours"])

    def test_business_hours(self):
        self.assertIsNone(check_off_hours({}, _ctx(hour=10)))

    def test_no_hour(self):
        self.assertIsNone(check_off_hours({}, _ctx(hour=None)))


class TestCheckNewSourceForUser(unittest.TestCase):

    def test_unfamiliar_source(self):
        ctx = _ctx(user_history={"total": 10, "seen_this_ip": False})
        alert = {"src_user": "bob", "src_ip": "9.9.9.9"}
        line = check_new_source_for_user(alert, ctx)
        self.assertIsNotNone(line)

    def test_familiar_source_no_signal(self):
        ctx = _ctx(user_history={"total": 10, "seen_this_ip": True})
        self.assertIsNone(check_new_source_for_user({"src_user": "bob", "src_ip": "1.2.3.4"}, ctx))

    def test_not_enough_history(self):
        ctx = _ctx(user_history={"total": 1, "seen_this_ip": False})
        self.assertIsNone(check_new_source_for_user({"src_user": "bob", "src_ip": "9.9.9.9"}, ctx))


class TestCheckVelocity(unittest.TestCase):

    def test_velocity_triggered(self):
        ctx = _ctx(recent_ips={"1.1.1.1", "2.2.2.2", "3.3.3.3"})
        alert = {"src_user": "bob", "src_ip": "4.4.4.4"}
        line = check_velocity(alert, ctx)
        self.assertIsNotNone(line)

    def test_few_ips_no_signal(self):
        ctx = _ctx(recent_ips={"1.1.1.1"})
        self.assertIsNone(check_velocity({"src_user": "bob", "src_ip": "1.1.1.1"}, ctx))


class TestAllowlists(unittest.TestCase):

    def test_allowlisted_ip(self):
        alert = {"src_ip": "203.0.113.10"}
        line = check_allowlisted_ip(alert, _ctx())
        self.assertIsNotNone(line)
        self.assertLess(line["points"], 0)

    def test_non_allowlisted_ip(self):
        self.assertIsNone(check_allowlisted_ip({"src_ip": "9.9.9.9"}, _ctx()))

    def test_allowlisted_user(self):
        config.ALLOWLIST_USERS.append("_test_svc_account_")
        try:
            line = check_allowlisted_user({"src_user": "_test_svc_account_"}, _ctx())
            self.assertIsNotNone(line)
            self.assertLess(line["points"], 0)
        finally:
            config.ALLOWLIST_USERS.remove("_test_svc_account_")

    def test_allowlisted_hash(self):
        config.ALLOWLIST_HASHES.append("TESTHASH123")
        try:
            line = check_allowlisted_hash({"file_hash": "testhash123"}, _ctx())
            self.assertIsNotNone(line)
        finally:
            config.ALLOWLIST_HASHES.remove("TESTHASH123")


class TestCheckNoisyRule(unittest.TestCase):

    def test_noisy_rule_penalised(self):
        ctx = _ctx(rule_stats={"total": 20, "fp": 18})
        line = check_noisy_rule({"rule_id": "5710"}, ctx)
        self.assertIsNotNone(line)
        self.assertLess(line["points"], 0)

    def test_zero_fp_no_signal(self):
        ctx = _ctx(rule_stats={"total": 20, "fp": 0})
        self.assertIsNone(check_noisy_rule({}, ctx))

    def test_no_stats_no_signal(self):
        self.assertIsNone(check_noisy_rule({}, _ctx()))


class TestCheckDuplicateFlood(unittest.TestCase):

    def test_flood_detected(self):
        ctx = _ctx(duplicate_count=config.DUPLICATE_FLOOD_COUNT)
        line = check_duplicate_flood({}, ctx)
        self.assertIsNotNone(line)
        self.assertLess(line["points"], 0)

    def test_below_threshold(self):
        ctx = _ctx(duplicate_count=config.DUPLICATE_FLOOD_COUNT - 1)
        self.assertIsNone(check_duplicate_flood({}, ctx))


class TestThreatFeedChecks(unittest.TestCase):

    def test_feed_hit(self):
        ctx = _ctx(ip_feed_hit={"feeds": ["feodotracker"]})
        line = check_threat_feed_ip({"src_ip": "1.2.3.4"}, ctx)
        self.assertIsNotNone(line)

    def test_tor_exit_separate(self):
        ctx = _ctx(ip_feed_hit={"feeds": ["tor_exit"]})
        self.assertIsNone(check_threat_feed_ip({"src_ip": "1.2.3.4"}, ctx))
        line = check_tor_exit({"src_ip": "1.2.3.4"}, ctx)
        self.assertIsNotNone(line)

    def test_no_feed_hit(self):
        self.assertIsNone(check_threat_feed_ip({"src_ip": "1.2.3.4"}, _ctx()))


if __name__ == "__main__":
    unittest.main()
