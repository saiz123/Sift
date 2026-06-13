"""
The scorer ties the checks together.

It gathers the few facts that need a lookup (the rule's track record, how many
duplicates we've seen, optional threat-intel) exactly once, hands that context
to every check, sums the line items into a score, and maps the score to a
verdict. The receipt it returns is the full, ordered list of line items — the
"why" that travels with the alert everywhere it goes.
"""

import re

import config
import db
import enrich
from checks import ALL_CHECKS


def _parse_hour(timestamp):
    """Best-effort hour-of-day (0-23) from a Wazuh timestamp, else None."""
    if not timestamp:
        return None
    try:
        import datetime as dt
        return dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00")).hour
    except Exception:
        pass
    # Fall back to pulling the first HH:MM out of the string.
    match = re.search(r"[T\s](\d{2}):\d{2}", str(timestamp))
    if match:
        return int(match.group(1))
    return None


def _build_context(alert):
    return {
        "hour": _parse_hour(alert.get("timestamp")),
        "rule_stats": db.get_rule_stats(alert.get("rule_id")),
        "rule_target_stats": db.get_rule_target_stats(alert.get("rule_id"), alert.get("target")),
        "rule_activity": db.rule_activity_stats(alert.get("rule_id"), config.DRIFT_WINDOW_HOURS),
        "duplicate_count": db.count_recent_duplicates(
            alert.get("rule_id"),
            alert.get("src_ip"),
            config.DUPLICATE_WINDOW_HOURS,
        ),
        "ip_intel": enrich.check_ip(alert.get("src_ip")),
        "hash_intel": enrich.check_hash(alert.get("file_hash")),
        "user_history": db.user_source_history(alert.get("src_user"), alert.get("src_ip")),
        "recent_ips": db.recent_distinct_source_ips(alert.get("src_user"), config.VELOCITY_WINDOW_HOURS),
    }


def decide(score):
    if score < config.JUNK_BELOW:
        return "JUNK"
    if score >= config.ESCALATE_AT:
        return "ESCALATE"
    return "REVIEW"


def score_alert(alert):
    """Returns (score, verdict, receipt) without touching the database."""
    ctx = _build_context(alert)
    receipt = []
    for check in ALL_CHECKS:
        line = check(alert, ctx)
        if line:
            receipt.append(line)
    score = sum(line["points"] for line in receipt)
    return score, decide(score), receipt
