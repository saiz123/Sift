"""
sift — transparent, self-hosted alert triage.

Run it:           python3 sift.py
Then send alerts: python3 send_sample.py sample_alerts/real_attack.json
Or point a SIEM:  POST your alerts to  http://<host>:<port>/webhook/<source>

Routes
  GET  /                     triage queue (optional ?verdict=&q=&snoozed=1&age=<hours>)
  GET  /alert/<id>           the alert and its receipt
  POST /alert/<id>/feedback  record an analyst verdict (teaches the noisy-rule signal)
  POST /alert/<id>/snooze    hide this alert from the queue for N hours
  POST /alert/<id>/unsnooze  bring a snoozed alert back into the queue now
  POST /bulk-feedback        record an analyst verdict for many alerts at once
  POST /webhook/wazuh        ingest a raw Wazuh alert
  POST /webhook/suricata     ingest a Suricata EVE JSON "alert" event
  POST /webhook/elastic      ingest an Elastic/ECS detection alert
  POST /webhook/guardduty    ingest an AWS GuardDuty finding
  POST /webhook/generic      ingest any JSON, mapped via config.GENERIC_FIELD_MAP
                             (each /webhook/* route returns the verdict as JSON)
  GET  /healthz              liveness check

Pure Python standard library — no pip install, nothing to pull from a CDN.
"""

import datetime as dt
import json
import re
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import config
import db
import notify
import views
from normalize import (
    normalize_elastic,
    normalize_generic,
    normalize_guardduty,
    normalize_suricata,
    normalize_wazuh,
)
from scorer import score_alert


WEBHOOK_NORMALIZERS = {
    "/webhook/wazuh": normalize_wazuh,
    "/webhook/suricata": normalize_suricata,
    "/webhook/elastic": normalize_elastic,
    "/webhook/guardduty": normalize_guardduty,
    "/webhook/generic": normalize_generic,
}


class Handler(BaseHTTPRequestHandler):
    server_version = "sift/1.0"

    # --- tiny response helpers --------------------------------------------
    def _send(self, status, body, content_type="text/html; charset=utf-8"):
        payload = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
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
        return self.rfile.read(length) if length else b""

    # --- routing ----------------------------------------------------------
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/healthz":
            return self._send_json(200, {"status": "ok"})

        if path == "/":
            params = urllib.parse.parse_qs(parsed.query)
            verdict = params.get("verdict", [None])[0]
            if verdict not in (None, "ESCALATE", "REVIEW", "JUNK"):
                verdict = None
            q = (params.get("q", [""])[0] or "").strip() or None
            snoozed = params.get("snoozed", [""])[0] == "1"
            age_raw = params.get("age", [""])[0]
            age_hours = int(age_raw) if age_raw.isdigit() else None
            alerts = db.list_alerts(
                verdict_filter=verdict, q=q, snoozed=snoozed, min_age_hours=age_hours
            )
            return self._send(200, views.render_dashboard(
                alerts, db.verdict_counts(), verdict, q,
                snoozed=snoozed, age=age_hours, snoozed_n=db.snoozed_count(),
            ))

        m = re.fullmatch(r"/alert/(\d+)", path)
        if m:
            alert = db.get_alert(int(m.group(1)))
            if not alert:
                return self._send(404, views.page("Not found", "<p>No such alert.</p>"))
            return self._send(200, views.render_detail(alert))

        return self._send(404, views.page("Not found", "<p>Not found.</p>"))

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path

        normalize_fn = WEBHOOK_NORMALIZERS.get(path)
        if normalize_fn:
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

    # --- actions ----------------------------------------------------------
    def _ingest(self, normalize_fn):
        try:
            raw = json.loads(self._read_body().decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return self._send_json(400, {"error": "body must be valid JSON"})

        alert = normalize_fn(raw)
        if alert is None:
            return self._send_json(200, {"status": "skipped"})

        score, verdict, receipt = score_alert(alert)
        alert_id = db.insert_alert(alert, score, verdict, receipt)
        if verdict == "ESCALATE":
            notify.notify_escalation(alert_id, alert, score, receipt)
        return self._send_json(200, {
            "id": alert_id,
            "score": score,
            "verdict": verdict,
            "receipt": receipt,
        })

    def _feedback(self, alert_id):
        form = urllib.parse.parse_qs(self._read_body().decode("utf-8"))
        verdict = form.get("verdict", [""])[0]
        if verdict not in ("true_positive", "false_positive"):
            return self._send_json(400, {"error": "verdict must be true_positive or false_positive"})
        if not db.record_feedback(alert_id, verdict):
            return self._send_json(404, {"error": "no such alert"})
        return self._redirect(f"/alert/{alert_id}")

    def _snooze(self, alert_id):
        form = urllib.parse.parse_qs(self._read_body().decode("utf-8"))
        try:
            hours = float(form.get("hours", [""])[0])
        except ValueError:
            return self._send_json(400, {"error": "hours must be a number"})
        if hours <= 0:
            return self._send_json(400, {"error": "hours must be positive"})
        until = (dt.datetime.now() + dt.timedelta(hours=hours)).isoformat(timespec="seconds")
        if not db.snooze_alert(alert_id, until):
            return self._send_json(404, {"error": "no such alert"})
        return self._redirect(f"/alert/{alert_id}")

    def _unsnooze(self, alert_id):
        if not db.unsnooze_alert(alert_id):
            return self._send_json(404, {"error": "no such alert"})
        return self._redirect(f"/alert/{alert_id}")

    def _bulk_feedback(self):
        form = urllib.parse.parse_qs(self._read_body().decode("utf-8"))
        verdict = form.get("analyst_verdict", [""])[0]
        if verdict not in ("true_positive", "false_positive"):
            return self._send_json(400, {"error": "analyst_verdict must be true_positive or false_positive"})
        for raw_id in form.get("ids", []):
            if raw_id.isdigit():
                db.record_feedback(int(raw_id), verdict)
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
    print(f"  enrichment: {', '.join(keys) if keys else 'off (no API keys set — that is fine)'}")
    print("  Ctrl-C to stop\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  stopped")
        server.shutdown()


if __name__ == "__main__":
    main()
