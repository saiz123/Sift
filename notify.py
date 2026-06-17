"""
Outbound actions — when sift scores an alert ESCALATE, push a short summary
to a chat webhook and/or create an alert in TheHive.

Set ESCALATE_WEBHOOK_URL (env var or .env) to a Slack, Mattermost, or Discord
incoming-webhook URL for a chat summary. Set THEHIVE_URL and THEHIVE_API_KEY
to also (or instead) create a TheHive alert carrying the full receipt. Either,
both, or neither can be configured — leave them unset and this module does
nothing.

Each POST runs on its own background thread with a short timeout, and any
failure is swallowed — a slow or unreachable endpoint never delays or breaks
alert ingestion.
"""

import json
import sys
import threading
import urllib.error
import urllib.request

import config


def notify_escalation(alert_id, alert, score, receipt):
    if config.ESCALATE_WEBHOOK_URL:
        text = _format_message(alert_id, alert, score, receipt)
        threading.Thread(
            target=_post_chat, args=(config.ESCALATE_WEBHOOK_URL, text), daemon=True
        ).start()
    if config.THEHIVE_URL and config.THEHIVE_API_KEY:
        threading.Thread(
            target=_post_thehive, args=(alert_id, alert, score, receipt), daemon=True
        ).start()


def _slack_escape(s):
    """Prevent Slack mrkdwn injection: <!channel>, <URL|label>, @mentions."""
    s = str(s) if s else ""
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _format_message(alert_id, alert, score, receipt):
    top = sorted(receipt, key=lambda line: -line["points"])[:3]
    signals = "; ".join(f"{line['label']} ({line['points']:+d})" for line in top)
    return (
        f"sift ESCALATE -- alert #{alert_id} (score {score})\n"
        f"Rule: {_slack_escape(alert.get('rule_id') or '?')} -- {_slack_escape(alert.get('rule_desc') or '')}\n"
        f"Target: {_slack_escape(alert.get('target') or '-')}  Source: {_slack_escape(alert.get('src_ip') or '-')}\n"
        f"Top signals: {signals or 'none'}"
    )


def _post_chat(url, text):
    # "text" is read by Slack/Mattermost, "content" by Discord — send both so
    # the same URL works with either, harmlessly ignored by the other.
    body = json.dumps({"text": text, "content": text}).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}
    )
    try:
        urllib.request.urlopen(req, timeout=5)
    except Exception as exc:
        print(f"  [notify] chat webhook failed: {exc!r}", file=sys.stderr)


def _thehive_severity(score):
    """Map sift's score onto TheHive's 1 (low) - 4 (critical) alert severity."""
    if score >= 100:
        return 4
    if score >= 80:
        return 3
    return 2


def _thehive_description(alert_id, alert, score, receipt):
    lines = [
        f"**{alert.get('rule_desc') or alert.get('rule_id') or 'Alert'}**",
        "",
        f"sift alert #{alert_id}  |  score {score}  |  source `{alert.get('source') or '?'}`",
        f"Target: {alert.get('target') or '-'}  |  Source IP: {alert.get('src_ip') or '-'}"
        f"  |  User: {alert.get('src_user') or '-'}",
        "",
        "Receipt:",
    ]
    for line in receipt:
        lines.append(f"- {line['points']:+d}  {line['label']} -- {line['detail']}")
    return "\n".join(lines)


def _post_thehive(alert_id, alert, score, receipt):
    if not config.THEHIVE_URL.startswith("https://"):
        print("  [notify] warning: THEHIVE_URL is not https — API token sent in cleartext", file=sys.stderr)
    tags = ["sift"]
    if alert.get("source"):
        tags.append(f"source:{alert['source']}")
    if alert.get("rule_id"):
        tags.append(f"rule:{alert['rule_id']}")

    body = json.dumps({
        "type": "sift",
        "source": "sift",
        "sourceRef": str(alert_id),
        "title": f"sift ESCALATE #{alert_id}: {alert.get('rule_desc') or alert.get('rule_id') or 'alert'}",
        "description": _thehive_description(alert_id, alert, score, receipt),
        "severity": _thehive_severity(score),
        "tags": tags,
        "tlp": 2,
        "pap": 2,
    }).encode("utf-8")
    req = urllib.request.Request(
        config.THEHIVE_URL + "/api/v1/alert",
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {config.THEHIVE_API_KEY}",
        },
    )
    try:
        urllib.request.urlopen(req, timeout=5)
    except Exception as exc:
        print(f"  [notify] TheHive create-alert failed: {exc!r}", file=sys.stderr)
