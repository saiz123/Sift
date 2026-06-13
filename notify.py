"""
Outbound notification — push a short summary to a chat webhook when sift
scores an alert ESCALATE.

Set ESCALATE_WEBHOOK_URL (env var or .env) to a Slack, Mattermost, or Discord
incoming-webhook URL and sift will POST there on every ESCALATE verdict.
Leave it unset and this module does nothing else.

The POST runs on a background thread with a short timeout, and any failure is
swallowed — a slow or unreachable webhook never delays or breaks ingestion.
"""

import json
import threading
import urllib.error
import urllib.request

import config


def notify_escalation(alert_id, alert, score, receipt):
    url = config.ESCALATE_WEBHOOK_URL
    if not url:
        return
    text = _format_message(alert_id, alert, score, receipt)
    threading.Thread(target=_post, args=(url, text), daemon=True).start()


def _format_message(alert_id, alert, score, receipt):
    top = sorted(receipt, key=lambda line: -line["points"])[:3]
    signals = "; ".join(f"{line['label']} ({line['points']:+d})" for line in top)
    return (
        f"sift ESCALATE -- alert #{alert_id} (score {score})\n"
        f"Rule: {alert.get('rule_id') or '?'} -- {alert.get('rule_desc') or ''}\n"
        f"Target: {alert.get('target') or '-'}  Source: {alert.get('src_ip') or '-'}\n"
        f"Top signals: {signals or 'none'}"
    )


def _post(url, text):
    # "text" is read by Slack/Mattermost, "content" by Discord — send both so
    # the same URL works with either, harmlessly ignored by the other.
    body = json.dumps({"text": text, "content": text}).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}
    )
    try:
        urllib.request.urlopen(req, timeout=5)
    except (urllib.error.URLError, OSError):
        pass
