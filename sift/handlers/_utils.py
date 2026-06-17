"""Shared route helpers used by both dashboard and feedback handlers."""

import urllib.parse

from ..storage import db


def _parse_filter(params):
    verdict = params.get("verdict", [None])[0]
    if verdict not in (None, "ESCALATE", "REVIEW", "JUNK"):
        verdict = None
    q = (params.get("q", [""])[0] or "").strip() or None
    snoozed = params.get("snoozed", [""])[0] == "1"
    age_raw = params.get("age", [""])[0]
    age_hours = int(age_raw) if age_raw.isdigit() else None
    return verdict, q, snoozed, age_hours


def _filter_qs(verdict, q, snoozed, age_hours):
    pairs = []
    if verdict:
        pairs.append(("verdict", verdict))
    if q:
        pairs.append(("q", q))
    if snoozed:
        pairs.append(("snoozed", "1"))
    if age_hours:
        pairs.append(("age", str(age_hours)))
    return urllib.parse.urlencode(pairs)


def _neighbor_ids(alert_id, verdict, q, snoozed, age_hours):
    ids = db.list_alert_ids(verdict_filter=verdict, q=q, snoozed=snoozed, min_age_hours=age_hours)
    if alert_id not in ids:
        return None, None
    i = ids.index(alert_id)
    return (ids[i - 1] if i > 0 else None), (ids[i + 1] if i + 1 < len(ids) else None)
