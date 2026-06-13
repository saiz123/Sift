"""
sift — transparent, self-hosted alert triage.

Run it:           python3 sift.py
Then send alerts: python3 send_sample.py sample_alerts/real_attack.json
Or point Wazuh:   POST your alerts to  http://<host>:<port>/webhook/wazuh

Routes
  GET  /                     triage queue (optional ?verdict=ESCALATE|REVIEW|JUNK)
  GET  /alert/<id>           the alert and its receipt
  POST /alert/<id>/feedback  record an analyst verdict (teaches the noisy-rule signal)
  POST /webhook/wazuh        ingest one Wazuh alert; returns the verdict as JSON
  GET  /healthz              liveness check

Pure Python standard library — no pip install, nothing to pull from a CDN.
"""

import json
import re
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import config
import db
import views
from normalize import normalize_wazuh
from scorer import score_alert


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
            alerts = db.list_alerts(verdict_filter=verdict, q=q)
            return self._send(200, views.render_dashboard(alerts, db.verdict_counts(), verdict, q))

        m = re.fullmatch(r"/alert/(\d+)", path)
        if m:
            alert = db.get_alert(int(m.group(1)))
            if not alert:
                return self._send(404, views.page("Not found", "<p>No such alert.</p>"))
            return self._send(200, views.render_detail(alert))

        return self._send(404, views.page("Not found", "<p>Not found.</p>"))

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path

        if path == "/webhook/wazuh":
            return self._ingest()

        m = re.fullmatch(r"/alert/(\d+)/feedback", path)
        if m:
            return self._feedback(int(m.group(1)))

        return self._send_json(404, {"error": "not found"})

    def do_HEAD(self):
        self.do_GET()

    # --- actions ----------------------------------------------------------
    def _ingest(self):
        try:
            raw = json.loads(self._read_body().decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return self._send_json(400, {"error": "body must be valid JSON"})

        alert = normalize_wazuh(raw)
        score, verdict, receipt = score_alert(alert)
        alert_id = db.insert_alert(alert, score, verdict, receipt)
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

    # quieter, tidier logging
    def log_message(self, fmt, *args):
        print(f"  {self.command} {self.path} -> {args[1] if len(args) > 1 else ''}")


def main():
    db.init_db()
    server = ThreadingHTTPServer((config.HOST, config.PORT), Handler)
    print("\n  sift is listening")
    print(f"  dashboard : http://{config.HOST}:{config.PORT}/")
    print(f"  webhook   : http://{config.HOST}:{config.PORT}/webhook/wazuh")
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
