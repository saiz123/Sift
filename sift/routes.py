"""HTTP handler: routing, auth helpers, and tiny response primitives."""

import hmac
import json
import re
import urllib.parse
from http.server import BaseHTTPRequestHandler

import config
from .storage import db
from .ui import views
from .handlers.dashboard import handle_dashboard, handle_alert_detail, handle_cases, handle_case
from .handlers.webhooks import WEBHOOK_NORMALIZERS, handle_ingest
from .handlers.feedback import (
    handle_login, handle_logout,
    handle_feedback, handle_snooze, handle_unsnooze, handle_bulk_feedback,
)


def _parse_session_cookie(headers):
    for part in headers.get("Cookie", "").split(";"):
        name, _, value = part.strip().partition("=")
        if name.strip() == "sift_session":
            return value.strip()
    return ""


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
            return None
        return self.rfile.read(length) if length else b""

    # --- auth helpers -----------------------------------------------------
    def _require_auth(self):
        if not db.has_any_user():
            return {"username": None, "role": "admin", "csrf_token": ""}
        token = _parse_session_cookie(self.headers)
        sess = db.get_session(token)
        if sess is None:
            self._redirect("/login")
            return None
        return sess

    def _require_write(self):
        sess = self._require_auth()
        if sess is None:
            return None
        if sess["role"] == "read_only":
            self._send(403, views.page("Forbidden", "<p>Your account is read-only.</p>"))
            return None
        return sess

    def _check_csrf(self, form, sess):
        if not sess["csrf_token"]:
            return True
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

        if path == "/":
            return handle_dashboard(self, parsed, sess)

        m = re.fullmatch(r"/alert/(\d+)", path)
        if m:
            return handle_alert_detail(self, parsed, int(m.group(1)), sess)

        if path == "/cases":
            return handle_cases(self, sess)

        m = re.fullmatch(r"/case/(user|ip|target)/([^/]+)", path)
        if m:
            dimension = m.group(1)
            value = urllib.parse.unquote(m.group(2))
            return handle_case(self, dimension, value, sess)

        return self._send(404, views.page("Not found", "<p>Not found.</p>"))

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path

        if path == "/login":
            return handle_login(self)

        if path == "/logout":
            return handle_logout(self)

        normalize_fn = WEBHOOK_NORMALIZERS.get(path)
        if normalize_fn:
            if config.SIFT_WEBHOOK_TOKEN:
                incoming = self.headers.get("X-Sift-Webhook-Token", "")
                if incoming != config.SIFT_WEBHOOK_TOKEN:
                    return self._send_json(401, {"error": "invalid or missing X-Sift-Webhook-Token"})
            return handle_ingest(self, normalize_fn)

        m = re.fullmatch(r"/alert/(\d+)/feedback", path)
        if m:
            return handle_feedback(self, int(m.group(1)))

        m = re.fullmatch(r"/alert/(\d+)/snooze", path)
        if m:
            return handle_snooze(self, int(m.group(1)))

        m = re.fullmatch(r"/alert/(\d+)/unsnooze", path)
        if m:
            return handle_unsnooze(self, int(m.group(1)))

        if path == "/bulk-feedback":
            return handle_bulk_feedback(self)

        return self._send_json(404, {"error": "not found"})

    def do_HEAD(self):
        self.do_GET()

    def log_message(self, fmt, *args):
        print(f"  {self.command} {self.path} -> {args[1] if len(args) > 1 else ''}")
