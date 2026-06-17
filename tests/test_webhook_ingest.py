"""
End-to-end ingest tests — starts a real ThreadingHTTPServer on a random port,
POSTs alert payloads, and validates the response. Zero mocks; validates the
full normalize → score → insert pipeline.
"""
import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
import urllib.error
from http.server import ThreadingHTTPServer
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


def _start_server():
    """Launch a sift server on a free port; return (server, port)."""
    import config as cfg
    # Isolated DB per test run
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    cfg.DB_PATH = tmp.name
    cfg.SIFT_WEBHOOK_TOKEN = ""  # no token by default

    from sift.storage import db
    db.init_db()

    from sift import Handler
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server, port, tmp.name


def _post(port, path, body, headers=None):
    data = json.dumps(body).encode() if isinstance(body, dict) else body
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", data=data, headers=h, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


class TestWebhookIngest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.server, cls.port, cls.db_path = _start_server()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        os.unlink(cls.db_path)

    def test_wazuh_ingest_returns_200(self):
        payload = {
            "rule": {"id": "92052", "level": 12, "description": "Cred dump"},
            "agent": {"name": "dc01"},
            "data": {"srcip": "45.1.2.3"},
            "timestamp": "2025-06-13T03:14:07Z",
        }
        status, result = _post(self.port, "/webhook/wazuh", payload)
        self.assertEqual(status, 200)
        self.assertIn("verdict", result)
        self.assertIn(result["verdict"], ("JUNK", "REVIEW", "ESCALATE"))
        self.assertIn("id", result)
        self.assertIn("score", result)

    def test_suricata_non_alert_skipped(self):
        payload = {"event_type": "flow", "flow": {}}
        status, result = _post(self.port, "/webhook/suricata", payload)
        self.assertEqual(status, 200)
        self.assertEqual(result.get("status"), "skipped")

    def test_invalid_json_returns_400(self):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/webhook/wazuh",
            data=b"not json",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=5)
        self.assertEqual(ctx.exception.code, 400)

    def test_body_too_large_returns_413(self):
        import config
        big_body = b'{"x": "' + b"a" * (config.MAX_BODY_BYTES + 1) + b'"}'
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/webhook/wazuh",
            data=big_body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=5)
        self.assertEqual(ctx.exception.code, 413)

    def test_webhook_token_accepted(self):
        import config
        config.SIFT_WEBHOOK_TOKEN = "testsecret"
        try:
            payload = {"rule": {"id": "1", "level": 3}, "agent": {"name": "host"}}
            status, result = _post(
                self.port, "/webhook/wazuh", payload,
                headers={"X-Sift-Webhook-Token": "testsecret"},
            )
            self.assertEqual(status, 200)
        finally:
            config.SIFT_WEBHOOK_TOKEN = ""

    def test_webhook_token_rejected(self):
        import config
        config.SIFT_WEBHOOK_TOKEN = "testsecret"
        try:
            payload = {"rule": {"id": "1", "level": 3}, "agent": {"name": "host"}}
            status, result = _post(
                self.port, "/webhook/wazuh", payload,
                headers={"X-Sift-Webhook-Token": "wrongtoken"},
            )
            self.assertEqual(status, 401)
        finally:
            config.SIFT_WEBHOOK_TOKEN = ""

    def test_crowdstrike_ingest(self):
        payload = {
            "event": {
                "EventType": "DetectionSummaryEvent",
                "DetectId": "ldt:test:1",
                "DetectDescription": "Malicious process",
                "SeverityName": "High",
                "ComputerName": "workstation-1",
                "UserName": "jdoe",
                "ProcessStartTime": 1718500000,
            }
        }
        status, result = _post(self.port, "/webhook/crowdstrike", payload)
        self.assertEqual(status, 200)
        self.assertIn("verdict", result)

    def test_osquery_ingest(self):
        payload = {
            "name": "process_network_connections",
            "hostIdentifier": "web-01",
            "action": "added",
            "columns": {"remote_address": "8.8.8.8", "username": "root"},
        }
        status, result = _post(self.port, "/webhook/osquery", payload)
        self.assertEqual(status, 200)
        self.assertIn("verdict", result)

    def test_healthz(self):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/healthz", method="GET"
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            result = json.loads(resp.read())
        self.assertEqual(result["status"], "ok")

    def test_unknown_route_404(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(
                f"http://127.0.0.1:{self.port}/webhook/unknown", timeout=5
            )
        self.assertEqual(ctx.exception.code, 404)


if __name__ == "__main__":
    unittest.main()
