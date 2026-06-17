"""
The scorer ties the checks together.

It gathers the few facts that need a lookup (the rule's track record, how many
duplicates we've seen, optional threat-intel) exactly once, hands that context
to every check, sums the line items into a score, and maps the score to a
verdict. The receipt it returns is the full, ordered list of line items — the
"why" that travels with the alert everywhere it goes.
"""

import datetime as dt
import re
import sys

import config
import db
import enrich
from checks import ALL_CHECKS


def _parse_hour(timestamp):
    """Best-effort hour-of-day (0-23) from an ISO timestamp, else None."""
    if not timestamp:
        return None
    try:
        return dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00")).hour
    except Exception:
        pass
    match = re.search(r"[T\s](\d{2}):\d{2}", str(timestamp))
    if match:
        return int(match.group(1))
    return None


def _build_local_context(alert):
    """Gather context from the local DB only — no network calls."""
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
        "user_history": db.user_source_history(alert.get("src_user"), alert.get("src_ip")),
        "recent_ips": db.recent_distinct_source_ips(alert.get("src_user"), config.VELOCITY_WINDOW_HOURS),
        "ip_intel": None,
        "ip_feed_hit": None,
        "hash_intel": None,
    }


def _build_enrich_context(alert):
    """Fetch threat-intel from external APIs — may block on network."""
    ip = alert.get("src_ip")
    file_hash = alert.get("file_hash")

    ip_intel = enrich.check_ip(ip)
    ip_feed_hit = enrich.check_ip_feeds(ip)
    hash_intel = enrich.check_hash(file_hash)

    meta = {
        "ip_checked": ip_intel is not None,
        "ip_skipped": (None if ip_intel is not None
                       else ("no ip" if not ip else ("no key" if not config.ABUSEIPDB_KEY else "failed"))),
        "hash_checked": hash_intel is not None,
        "hash_skipped": (None if hash_intel is not None
                         else ("no hash" if not file_hash else ("no key" if not config.VIRUSTOTAL_KEY else "failed"))),
        "feeds_checked": ip_feed_hit is not None or config.ENABLE_THREAT_FEEDS,
    }

    return {
        "ip_intel": ip_intel,
        "ip_feed_hit": ip_feed_hit,
        "hash_intel": hash_intel,
        "_enrich_meta": meta,
    }


def _run_checks(alert, ctx):
    receipt = []
    for check in ALL_CHECKS:
        try:
            line = check(alert, ctx)
        except Exception as exc:
            print(f"  [scorer] {check.__name__} raised {exc!r}", file=sys.stderr)
            continue
        if line:
            receipt.append(line)
    return receipt


def decide(score):
    if score < config.JUNK_BELOW:
        return "JUNK"
    if score >= config.ESCALATE_AT:
        return "ESCALATE"
    return "REVIEW"


def score_alert(alert):
    """Returns (score, verdict, receipt) using local DB context only (no network)."""
    ctx = _build_local_context(alert)
    receipt = _run_checks(alert, ctx)
    score = sum(line["points"] for line in receipt)
    return score, decide(score), receipt


def enrich_and_rescore(alert_id, alert, initial_verdict):
    """
    Run in a background thread after initial ingest. Fetches threat-intel,
    re-scores with the full context, and updates the stored alert. If the
    enriched verdict escalates beyond the initial one, fires a notification.
    """
    try:
        enrich_ctx = _build_enrich_context(alert)
        ctx = {**_build_local_context(alert), **enrich_ctx}
        receipt = _run_checks(alert, ctx)
        # Append enrichment metadata as a non-scoring sentinel entry
        if "_enrich_meta" in enrich_ctx:
            receipt = receipt + [{"_enrich_meta": enrich_ctx["_enrich_meta"]}]
        score = sum(line.get("points", 0) for line in receipt)
        verdict = decide(score)
        db.update_alert_score(alert_id, score, verdict, receipt)
        if verdict == "ESCALATE" and initial_verdict != "ESCALATE":
            import notify
            notify.notify_escalation(alert_id, alert, score, receipt)
    except Exception as exc:
        print(f"  [scorer] enrich_and_rescore #{alert_id} failed: {exc!r}", file=sys.stderr)
