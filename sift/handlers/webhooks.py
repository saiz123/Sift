"""Webhook ingest handler and normalizer route table."""

import json
import sys
import threading

import config
import notify
from ..storage import db
from ..core.scorer import enrich_and_rescore, score_alert
from ..core.normalize import (
    normalize_crowdstrike,
    normalize_elastic,
    normalize_generic,
    normalize_guardduty,
    normalize_m365,
    normalize_osquery,
    normalize_suricata,
    normalize_wazuh,
)

WEBHOOK_NORMALIZERS = {
    "/webhook/wazuh":        normalize_wazuh,
    "/webhook/suricata":     normalize_suricata,
    "/webhook/elastic":      normalize_elastic,
    "/webhook/guardduty":    normalize_guardduty,
    "/webhook/m365":         normalize_m365,
    "/webhook/crowdstrike":  normalize_crowdstrike,
    "/webhook/osquery":      normalize_osquery,
    "/webhook/generic":      normalize_generic,
}


def handle_ingest(h, normalize_fn):
    body = h._read_body()
    if body is None:
        return h._send_json(413, {"error": "request body too large"})
    try:
        raw = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return h._send_json(400, {"error": "body must be valid JSON"})

    try:
        alert = normalize_fn(raw)
        if alert is None:
            return h._send_json(200, {"status": "skipped"})
        score, verdict, receipt = score_alert(alert)
        alert_id = db.insert_alert(alert, score, verdict, receipt)
    except Exception as exc:
        print(f"  [ingest] normalize/score/insert failed: {exc!r}", file=sys.stderr)
        return h._send_json(500, {"error": "ingest failed"})

    if verdict == "ESCALATE":
        notify.notify_escalation(alert_id, alert, score, receipt)

    threading.Thread(
        target=enrich_and_rescore, args=(alert_id, alert, verdict), daemon=True
    ).start()

    h._send_json(200, {"id": alert_id, "score": score, "verdict": verdict, "receipt": receipt})
