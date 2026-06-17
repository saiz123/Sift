"""
sift — transparent, self-hosted alert triage.

Run it:           python3 sift.py
Then send alerts: python3 send_sample.py sample_alerts/real_attack.json
Or point a SIEM:  POST your alerts to  http://<host>:<port>/webhook/<source>

Routes
  GET  /                     triage queue (optional ?verdict=&q=&snoozed=1&age=<hours>)
  GET  /alert/<id>           the alert and its receipt
  GET  /cases                alerts grouped by shared user/IP/target (see config.CASE_*)
  GET  /case/<dim>/<value>   the alerts in one case (<dim> is user, ip, or target)
  POST /alert/<id>/feedback  record an analyst verdict (teaches the noisy-rule signal)
  POST /alert/<id>/snooze    hide this alert from the queue for N hours
  POST /alert/<id>/unsnooze  bring a snoozed alert back into the queue now
  POST /bulk-feedback        record an analyst verdict for many alerts at once
  POST /webhook/wazuh        ingest a raw Wazuh alert
  POST /webhook/suricata     ingest a Suricata EVE JSON "alert" event
  POST /webhook/elastic      ingest an Elastic/ECS detection alert
  POST /webhook/guardduty    ingest an AWS GuardDuty finding
  POST /webhook/m365         ingest a Microsoft Graph Security API alert
  POST /webhook/generic      ingest any JSON, mapped via config.GENERIC_FIELD_MAP
                             (each /webhook/* route returns the verdict as JSON)
  GET  /healthz              liveness check

Pure Python standard library — no pip install, nothing to pull from a CDN.
"""

import datetime as dt
import hmac
import json
import re
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import config
import db
import notify
import views
from normalize import (
    normalize_crowdstrike,
    normalize_elastic,
    normalize_generic,
    normalize_guardduty,
    normalize_m365,
    normalize_osquery,
    normalize_suricata,
    normalize_wazuh,
)
from scorer import enrich_and_rescore, score_alert


def _parse_session_cookie(headers):
    for part in headers.get("Cookie", "").split(";"):
        name, _, value = part.strip().partition("=")
        if name.strip() == "sift_session":
            return value.strip()
    return ""


WEBHOOK_NORMALIZERS = {
    "/webhook/wazuh": normalize_wazuh,
    "/webhook/suricata": normalize_suricata,
    "/webhook/elastic": normalize_elastic,
    "/webhook/guardduty": normalize_guardduty,
    "/webhook/m365": normalize_m365,
    "/webhook/crowdstrike": normalize_crowdstrike,
    "/webhook/osquery": normalize_osquery,
    "/webhook/generic": normalize_generic,
}


def _parse_filter(params):
    """Extract the queue filter (verdict/q/snoozed/age) from parsed query params."""
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
    """The previous/next alert ids in the same filtered queue, for j/k navigation."""
    ids = db.list_alert_ids(verdict_filter=verdict, q=q, snoozed=snoozed, min_age_hours=age_hours)
    if alert_id not in ids:
        return None, None
    i = ids.index(alert_id)
    prev_id = ids[i - 1] if i > 0 else None
    next_id = ids[i + 1] if i + 1 < len(ids) else None
    return prev_id, next_id


class Handler(BaseHTTPRequestHandler):
    server_version = "sift/1.0"

    # --- tiny response helpers --------------------------------------------
    def _send(self, status, body, content_type="text/html; charset=utf-8"):
        payload = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _send_json(self, status, obj):
        self._send(status, json.dumps(obj, indent=2), "application/json; charset=utf-8")

    def _redirect(self, location):
        self.send_response(303)
        self.send_header("Location", location)
        self.end_headers()

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length > config.MAX_BODY_BYTES:
            return None  # caller should return 413
        return self.rfile.read(length) if length else b""

    # --- auth helpers -----------------------------------------------------
    def _require_auth(self):
        """Return session dict or None (after sending redirect).
        When no users are configured, returns an anonymous session so the tool
        works out-of-the-box — auth only enforces once at least one user exists."""
        if not db.has_any_user():
            return {"username": None, "role": "admin", "csrf_token": ""}
        token = _parse_session_cookie(self.headers)
        sess = db.get_session(token)
        if sess is None:
            self._redirect("/login")
            return None
        return sess

    def _require_write(self):
        """Like _require_auth but blocks read_only role."""
        sess = self._require_auth()
        if sess is None:
            return None
        if sess["role"] == "read_only":
            self._send(403, views.page("Forbidden", "<p>Your account is read-only.</p>"))
            return None
        return sess

    def _check_csrf(self, form, sess):
        if not sess["csrf_token"]:
            return True  # no-auth mode — skip CSRF
        token = form.get("csrf_token", [""])[0]
        if not token:
            return False
        return hmac.compare_digest(token, sess["csrf_token"])

    # --- routing ----------------------------------------------------------
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/healthz":
            return self._send_json(200, {"status": "ok"})

        if path == "/login":
            no_users = not db.has_any_user()
            if not no_users:
                token = _parse_session_cookie(self.headers)
                if db.get_session(token):
                    return self._redirect("/")
            return self._send(200, views.render_login(no_users=no_users))

        sess = self._require_auth()
        if sess is None:
            return

        username = sess["username"]
        csrf_token = sess["csrf_token"]

        if path == "/":
            params = urllib.parse.parse_qs(parsed.query)
            verdict, q, snoozed, age_hours = _parse_filter(params)
            alerts = db.list_alerts(
                verdict_filter=verdict, q=q, snoozed=snoozed, min_age_hours=age_hours
            )
            return self._send(200, views.render_dashboard(
                alerts, db.verdict_counts(), verdict, q,
                snoozed=snoozed, age=age_hours, snoozed_n=db.snoozed_count(),
                username=username, csrf_token=csrf_token,
            ))

        m = re.fullmatch(r"/alert/(\d+)", path)
        if m:
            alert_id = int(m.group(1))
            alert = db.get_alert(alert_id)
            if not alert:
                return self._send(404, views.page("Not found", "<p>No such alert.</p>"))
            params = urllib.parse.parse_qs(parsed.query)
            verdict, q, snoozed, age_hours = _parse_filter(params)
            filter_qs = _filter_qs(verdict, q, snoozed, age_hours)
            prev_id, next_id = _neighbor_ids(alert_id, verdict, q, snoozed, age_hours)
            return self._send(200, views.render_detail(
                alert, filter_qs=filter_qs, prev_id=prev_id, next_id=next_id,
                username=username, csrf_token=csrf_token,
            ))

        if path == "/cases":
            cases = db.list_cases(config.CASE_WINDOW_HOURS, config.CASE_MIN_ALERTS)
            return self._send(200, views.render_cases(cases, username=username))

        m = re.fullmatch(r"/case/(user|ip|target)/([^/]+)", path)
        if m:
            dimension = m.group(1)
            value = urllib.parse.unquote(m.group(2))
            alerts = db.list_case_alerts(dimension, value, config.CASE_WINDOW_HOURS)
            if not alerts:
                return self._send(404, views.page("Not found", "<p>No such case.</p>"))
            return self._send(200, views.render_case(
                dimension, value, alerts, username=username, csrf_token=csrf_token,
            ))

        return self._send(404, views.page("Not found", "<p>Not found.</p>"))

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path

        if path == "/login":
            return self._handle_login()

        if path == "/logout":
            return self._handle_logout()

        normalize_fn = WEBHOOK_NORMALIZERS.get(path)
        if normalize_fn:
            if config.SIFT_WEBHOOK_TOKEN:
                incoming = self.headers.get("X-Sift-Webhook-Token", "")
                if incoming != config.SIFT_WEBHOOK_TOKEN:
                    return self._send_json(401, {"error": "invalid or missing X-Sift-Webhook-Token"})
            return self._ingest(normalize_fn)

        m = re.fullmatch(r"/alert/(\d+)/feedback", path)
        if m:
            return self._feedback(int(m.group(1)))

        m = re.fullmatch(r"/alert/(\d+)/snooze", path)
        if m:
            return self._snooze(int(m.group(1)))

        m = re.fullmatch(r"/alert/(\d+)/unsnooze", path)
        if m:
            return self._unsnooze(int(m.group(1)))

        if path == "/bulk-feedback":
            return self._bulk_feedback()

        return self._send_json(404, {"error": "not found"})

    def do_HEAD(self):
        self.do_GET()

    # --- login / logout ---------------------------------------------------
    def _handle_login(self):
        body = self._read_body()
        if body is None:
            return self._send_json(413, {"error": "request body too large"})
        form = urllib.parse.parse_qs(body.decode("utf-8"))
        username = form.get("username", [""])[0].strip()
        password = form.get("password", [""])[0]
        user = db.verify_user(username, password)
        if user is None:
            return self._send(200, views.render_login(error="Invalid username or password."))
        sess = db.create_session(user["username"])
        max_age = config.SESSION_MAX_HOURS * 3600
        self.send_response(303)
        self.send_header("Location", "/")
        self.send_header(
            "Set-Cookie",
            f"sift_session={sess['token']}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}",
        )
        self.end_headers()

    def _handle_logout(self):
        token = _parse_session_cookie(self.headers)
        db.delete_session(token)
        self.send_response(303)
        self.send_header("Location", "/login")
        self.send_header(
            "Set-Cookie",
            "sift_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0",
        )
        self.end_headers()

    # --- actions ----------------------------------------------------------
    def _ingest(self, normalize_fn):
        body = self._read_body()
        if body is None:
            return self._send_json(413, {"error": "request body too large"})
        try:
            raw = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return self._send_json(400, {"error": "body must be valid JSON"})

        try:
            alert = normalize_fn(raw)
            if alert is None:
                return self._send_json(200, {"status": "skipped"})

            score, verdict, receipt = score_alert(alert)
            alert_id = db.insert_alert(alert, score, verdict, receipt)
        except Exception as exc:
            print(f"  [ingest] normalize/score/insert failed: {exc!r}", file=sys.stderr)
            return self._send_json(500, {"error": "ingest failed"})

        if verdict == "ESCALATE":
            notify.notify_escalation(alert_id, alert, score, receipt)

        threading.Thread(
            target=enrich_and_rescore,
            args=(alert_id, alert, verdict),
            daemon=True,
        ).start()

        return self._send_json(200, {
            "id": alert_id,
            "score": score,
            "verdict": verdict,
            "receipt": receipt,
        })

    def _feedback(self, alert_id):
        body = self._read_body()
        if body is None:
            return self._send_json(413, {"error": "request body too large"})
        form = urllib.parse.parse_qs(body.decode("utf-8"))
        sess = self._require_write()
        if sess is None:
            return
        if not self._check_csrf(form, sess):
            return self._send(403, views.page("Forbidden", "<p>CSRF token invalid. Please reload the page.</p>"))
        verdict = form.get("verdict", [""])[0]
        if verdict not in ("true_positive", "false_positive"):
            return self._send_json(400, {"error": "verdict must be true_positive or false_positive"})
        if not db.record_feedback(alert_id, verdict, actor=sess["username"]):
            return self._send_json(404, {"error": "no such alert"})
        from_qs = form.get("from", [""])[0]
        suffix = f"?{from_qs}" if from_qs else ""
        fverdict, fq, fsnoozed, fage = _parse_filter(urllib.parse.parse_qs(from_qs))
        _, next_id = _neighbor_ids(alert_id, fverdict, fq, fsnoozed, fage)
        if next_id:
            return self._redirect(f"/alert/{next_id}{suffix}")
        return self._redirect(f"/{suffix}")

    def _snooze(self, alert_id):
        body = self._read_body()
        if body is None:
            return self._send_json(413, {"error": "request body too large"})
        form = urllib.parse.parse_qs(body.decode("utf-8"))
        sess = self._require_write()
        if sess is None:
            return
        if not self._check_csrf(form, sess):
            return self._send(403, views.page("Forbidden", "<p>CSRF token invalid. Please reload the page.</p>"))
        try:
            hours = float(form.get("hours", [""])[0])
        except ValueError:
            return self._send_json(400, {"error": "hours must be a number"})
        if hours <= 0:
            return self._send_json(400, {"error": "hours must be positive"})
        until = (dt.datetime.now() + dt.timedelta(hours=hours)).isoformat(timespec="seconds")
        if not db.snooze_alert(alert_id, until):
            return self._send_json(404, {"error": "no such alert"})
        from_qs = form.get("from", [""])[0]
        suffix = f"?{from_qs}" if from_qs else ""
        return self._redirect(f"/alert/{alert_id}{suffix}")

    def _unsnooze(self, alert_id):
        body = self._read_body()
        if body is None:
            return self._send_json(413, {"error": "request body too large"})
        form = urllib.parse.parse_qs(body.decode("utf-8"))
        sess = self._require_write()
        if sess is None:
            return
        if not self._check_csrf(form, sess):
            return self._send(403, views.page("Forbidden", "<p>CSRF token invalid. Please reload the page.</p>"))
        if not db.unsnooze_alert(alert_id):
            return self._send_json(404, {"error": "no such alert"})
        from_qs = form.get("from", [""])[0]
        suffix = f"?{from_qs}" if from_qs else ""
        return self._redirect(f"/alert/{alert_id}{suffix}")

    def _bulk_feedback(self):
        body = self._read_body()
        if body is None:
            return self._send_json(413, {"error": "request body too large"})
        form = urllib.parse.parse_qs(body.decode("utf-8"))
        sess = self._require_write()
        if sess is None:
            return
        if not self._check_csrf(form, sess):
            return self._send(403, views.page("Forbidden", "<p>CSRF token invalid. Please reload the page.</p>"))
        verdict = form.get("analyst_verdict", [""])[0]
        if verdict not in ("true_positive", "false_positive"):
            return self._send_json(400, {"error": "analyst_verdict must be true_positive or false_positive"})
        for raw_id in form.get("ids", []):
            if raw_id.isdigit():
                db.record_feedback(int(raw_id), verdict, actor=sess["username"])
        case_path = form.get("case", [""])[0]
        if case_path:
            return self._redirect(f"/case/{case_path}")
        # Redirect back to whatever queue view this came from.
        keep = [(k, form[k][0]) for k in ("verdict", "q", "snoozed", "age") if form.get(k, [""])[0]]
        location = "/?" + urllib.parse.urlencode(keep) if keep else "/"
        return self._redirect(location)

    # quieter, tidier logging
    def log_message(self, fmt, *args):
        print(f"  {self.command} {self.path} -> {args[1] if len(args) > 1 else ''}")


def main():
    db.init_db()
    server = ThreadingHTTPServer((config.HOST, config.PORT), Handler)
    print("\n  sift is listening")
    print(f"  dashboard : http://{config.HOST}:{config.PORT}/")
    sources = ", ".join(sorted(p.rsplit("/", 1)[1] for p in WEBHOOK_NORMALIZERS))
    print(f"  webhooks  : http://{config.HOST}:{config.PORT}/webhook/<source>  ({sources})")
    keys = []
    if config.ABUSEIPDB_KEY:
        keys.append("AbuseIPDB")
    if config.VIRUSTOTAL_KEY:
        keys.append("VirusTotal")
    if config.ENABLE_THREAT_FEEDS:
        keys.append(f"{len(config.THREAT_FEEDS)} threat feed(s)")
    if config.LOCAL_BLOCKLIST_PATH:
        keys.append("local blocklist")
    print(f"  enrichment: {', '.join(keys) if keys else 'off (no API keys set — that is fine)'}")
    if config.THEHIVE_URL and not config.THEHIVE_URL.startswith("https://"):
        print("  WARNING: THEHIVE_URL is not https — API token will be sent in cleartext\n")
    print("  Ctrl-C to stop\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  stopped")
        server.shutdown()


if __name__ == "__main__":
    main()
