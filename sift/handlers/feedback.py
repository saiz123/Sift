"""POST action handlers: login, logout, feedback, snooze, bulk-feedback."""

import datetime as dt
import urllib.parse

import config
from ..storage import db
from ..ui import views
from ._utils import _parse_filter, _filter_qs, _neighbor_ids


def handle_login(h):
    body = h._read_body()
    if body is None:
        return h._send_json(413, {"error": "request body too large"})
    form = urllib.parse.parse_qs(body.decode("utf-8"))
    username = form.get("username", [""])[0].strip()
    password = form.get("password", [""])[0]
    user = db.verify_user(username, password)
    if user is None:
        return h._send(200, views.render_login(error="Invalid username or password."))
    sess = db.create_session(user["username"])
    max_age = config.SESSION_MAX_HOURS * 3600
    h.send_response(303)
    h.send_header("Location", "/")
    h.send_header(
        "Set-Cookie",
        f"sift_session={sess['token']}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}",
    )
    h.end_headers()


def handle_logout(h):
    from ..routes import _parse_session_cookie
    token = _parse_session_cookie(h.headers)
    db.delete_session(token)
    h.send_response(303)
    h.send_header("Location", "/login")
    h.send_header("Set-Cookie", "sift_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
    h.end_headers()


def handle_feedback(h, alert_id):
    body = h._read_body()
    if body is None:
        return h._send_json(413, {"error": "request body too large"})
    form = urllib.parse.parse_qs(body.decode("utf-8"))
    sess = h._require_write()
    if sess is None:
        return
    if not h._check_csrf(form, sess):
        return h._send(403, views.page("Forbidden", "<p>CSRF token invalid. Please reload the page.</p>"))
    verdict = form.get("verdict", [""])[0]
    if verdict not in ("true_positive", "false_positive"):
        return h._send_json(400, {"error": "verdict must be true_positive or false_positive"})
    if not db.record_feedback(alert_id, verdict, actor=sess["username"]):
        return h._send_json(404, {"error": "no such alert"})
    from_qs = form.get("from", [""])[0]
    suffix = f"?{from_qs}" if from_qs else ""
    fverdict, fq, fsnoozed, fage = _parse_filter(urllib.parse.parse_qs(from_qs))
    _, next_id = _neighbor_ids(alert_id, fverdict, fq, fsnoozed, fage)
    if next_id:
        return h._redirect(f"/alert/{next_id}{suffix}")
    h._redirect(f"/{suffix}")


def handle_snooze(h, alert_id):
    body = h._read_body()
    if body is None:
        return h._send_json(413, {"error": "request body too large"})
    form = urllib.parse.parse_qs(body.decode("utf-8"))
    sess = h._require_write()
    if sess is None:
        return
    if not h._check_csrf(form, sess):
        return h._send(403, views.page("Forbidden", "<p>CSRF token invalid. Please reload the page.</p>"))
    try:
        hours = float(form.get("hours", [""])[0])
    except ValueError:
        return h._send_json(400, {"error": "hours must be a number"})
    if hours <= 0:
        return h._send_json(400, {"error": "hours must be positive"})
    until = (dt.datetime.now() + dt.timedelta(hours=hours)).isoformat(timespec="seconds")
    if not db.snooze_alert(alert_id, until):
        return h._send_json(404, {"error": "no such alert"})
    from_qs = form.get("from", [""])[0]
    suffix = f"?{from_qs}" if from_qs else ""
    h._redirect(f"/alert/{alert_id}{suffix}")


def handle_unsnooze(h, alert_id):
    body = h._read_body()
    if body is None:
        return h._send_json(413, {"error": "request body too large"})
    form = urllib.parse.parse_qs(body.decode("utf-8"))
    sess = h._require_write()
    if sess is None:
        return
    if not h._check_csrf(form, sess):
        return h._send(403, views.page("Forbidden", "<p>CSRF token invalid. Please reload the page.</p>"))
    if not db.unsnooze_alert(alert_id):
        return h._send_json(404, {"error": "no such alert"})
    from_qs = form.get("from", [""])[0]
    suffix = f"?{from_qs}" if from_qs else ""
    h._redirect(f"/alert/{alert_id}{suffix}")


def handle_bulk_feedback(h):
    body = h._read_body()
    if body is None:
        return h._send_json(413, {"error": "request body too large"})
    form = urllib.parse.parse_qs(body.decode("utf-8"))
    sess = h._require_write()
    if sess is None:
        return
    if not h._check_csrf(form, sess):
        return h._send(403, views.page("Forbidden", "<p>CSRF token invalid. Please reload the page.</p>"))
    verdict = form.get("analyst_verdict", [""])[0]
    if verdict not in ("true_positive", "false_positive"):
        return h._send_json(400, {"error": "analyst_verdict must be true_positive or false_positive"})
    for raw_id in form.get("ids", []):
        if raw_id.isdigit():
            db.record_feedback(int(raw_id), verdict, actor=sess["username"])
    case_path = form.get("case", [""])[0]
    if case_path:
        return h._redirect(f"/case/{case_path}")
    keep = [(k, form[k][0]) for k in ("verdict", "q", "snoozed", "age") if form.get(k, [""])[0]]
    h._redirect("/?" + urllib.parse.urlencode(keep) if keep else "/")
