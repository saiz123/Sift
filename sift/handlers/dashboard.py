"""GET route handlers: triage queue, alert detail, cases."""

import urllib.parse

import config
from ..storage import db
from ..ui import views
from ._utils import _parse_filter, _filter_qs, _neighbor_ids


def handle_dashboard(h, parsed, sess):
    params = urllib.parse.parse_qs(parsed.query)
    verdict, q, snoozed, age_hours = _parse_filter(params)
    alerts = db.list_alerts(verdict_filter=verdict, q=q, snoozed=snoozed, min_age_hours=age_hours)
    h._send(200, views.render_dashboard(
        alerts, db.verdict_counts(), verdict, q,
        snoozed=snoozed, age=age_hours, snoozed_n=db.snoozed_count(),
        username=sess["username"], csrf_token=sess["csrf_token"],
    ))


def handle_alert_detail(h, parsed, alert_id, sess):
    alert = db.get_alert(alert_id)
    if not alert:
        return h._send(404, views.page("Not found", "<p>No such alert.</p>"))
    params = urllib.parse.parse_qs(parsed.query)
    verdict, q, snoozed, age_hours = _parse_filter(params)
    filter_qs = _filter_qs(verdict, q, snoozed, age_hours)
    prev_id, next_id = _neighbor_ids(alert_id, verdict, q, snoozed, age_hours)
    h._send(200, views.render_detail(
        alert, filter_qs=filter_qs, prev_id=prev_id, next_id=next_id,
        username=sess["username"], csrf_token=sess["csrf_token"],
    ))


def handle_cases(h, sess):
    cases = db.list_cases(config.CASE_WINDOW_HOURS, config.CASE_MIN_ALERTS)
    h._send(200, views.render_cases(cases, username=sess["username"]))


def handle_case(h, dimension, value, sess):
    alerts = db.list_case_alerts(dimension, value, config.CASE_WINDOW_HOURS)
    if not alerts:
        return h._send(404, views.page("Not found", "<p>No such case.</p>"))
    h._send(200, views.render_case(
        dimension, value, alerts,
        username=sess["username"], csrf_token=sess["csrf_token"],
    ))
