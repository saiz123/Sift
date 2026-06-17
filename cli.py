"""
sift CLI — convenience wrapper for common operations.

    python cli.py serve              start the sift server
    python cli.py send <file.json>   POST an alert file to a running sift
    python cli.py init-db            initialise / migrate the database
    python cli.py export             dump all alerts as JSON lines to stdout
    python cli.py reset-demo         clear the DB and load all sample_alerts/

send auto-detects the source type (same logic as send_sample.py).
"""

import argparse
import glob
import json
import os
import sys
import urllib.error
import urllib.request


def _guess_endpoint(raw):
    if not isinstance(raw, dict):
        return "/webhook/wazuh"
    event = raw.get("event") if isinstance(raw.get("event"), dict) else {}
    if event.get("EventType") == "DetectionSummaryEvent":
        return "/webhook/crowdstrike"
    if "name" in raw and "columns" in raw:
        return "/webhook/osquery"
    if "schemaVersion" in raw and "type" in raw and "severity" in raw:
        return "/webhook/guardduty"
    if "vendorInformation" in raw or "azureTenantId" in raw:
        return "/webhook/m365"
    if raw.get("event_type") == "alert" and "alert" in raw:
        return "/webhook/suricata"
    if "rule" in raw and "agent" in raw:
        return "/webhook/wazuh"
    if "@timestamp" in raw:
        return "/webhook/elastic"
    return "/webhook/generic"


def cmd_serve(args):
    import sift
    sift.main()


def cmd_send(args):
    base = args.url.rstrip("/")
    with open(args.file, "rb") as fh:
        body = fh.read()
    raw = json.loads(body.decode("utf-8"))
    endpoint = args.endpoint or _guess_endpoint(raw)
    headers = {"Content-Type": "application/json"}
    if args.token:
        headers["X-Sift-Webhook-Token"] = args.token
    req = urllib.request.Request(
        base + endpoint, data=body, headers=headers, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        print(f"  error: could not reach sift at {base} — is it running? ({exc})")
        sys.exit(1)

    if result.get("status") == "skipped":
        print("  skipped (normalizer returned None for this payload)")
        return

    sign = lambda p: f"+{p}" if p >= 0 else str(p)
    print(f"\n  verdict : {result['verdict']}   score: {result['score']}   (alert #{result['id']})")
    print("  receipt :")
    for item in result.get("receipt", []):
        if "_enrich_meta" in item:
            continue
        print(f"    {sign(item['points']):>5}  {item['label']}  —  {item['detail']}")
    print(f"\n  view at : {base}/alert/{result['id']}\n")


def cmd_init_db(args):
    import db
    db.init_db()
    print("  database initialised / migrated.")


def cmd_export(args):
    import db
    alerts = db.list_alerts(limit=999999)
    for alert in alerts:
        # receipt_json and raw_json are stored as strings; decode for clean output
        alert["receipt"] = json.loads(alert.pop("receipt_json", "[]"))
        alert["raw"] = json.loads(alert.pop("raw_json", "{}"))
        print(json.dumps(alert))


def cmd_reset_demo(args):
    import config
    import db

    confirm = input("  This will DELETE all alerts and reload sample data. Type 'yes' to continue: ")
    if confirm.strip().lower() != "yes":
        print("  aborted.")
        return

    import sqlite3, contextlib
    with contextlib.closing(sqlite3.connect(config.DB_PATH)) as conn:
        conn.execute("DELETE FROM alerts")
        conn.execute("DELETE FROM rule_stats")
        conn.execute("DELETE FROM rule_target_stats")
        conn.execute("DELETE FROM alert_events")
        conn.execute("DELETE FROM enrich_cache")
        conn.commit()
    print("  database cleared.")

    # Reload sample alerts via send_sample logic
    sample_dir = os.path.join(os.path.dirname(__file__), "sample_alerts")
    files = sorted(glob.glob(os.path.join(sample_dir, "*.json")))
    if not files:
        print("  no sample_alerts/*.json found — done.")
        return

    # Import and insert directly (no running server needed)
    from normalize import (
        normalize_crowdstrike, normalize_elastic, normalize_generic,
        normalize_guardduty, normalize_m365, normalize_osquery,
        normalize_suricata, normalize_wazuh,
    )
    from scorer import score_alert

    normalizers = [
        normalize_wazuh, normalize_suricata, normalize_elastic,
        normalize_guardduty, normalize_m365, normalize_crowdstrike,
        normalize_osquery, normalize_generic,
    ]

    loaded = 0
    for fpath in files:
        with open(fpath, encoding="utf-8") as fh:
            raw = json.load(fh)
        for fn in normalizers:
            try:
                alert = fn(raw)
                if alert is not None:
                    score, verdict, receipt = score_alert(alert)
                    db.insert_alert(alert, score, verdict, receipt)
                    loaded += 1
                    break
            except Exception:
                continue

    print(f"  loaded {loaded}/{len(files)} sample alerts — visit http://127.0.0.1:{config.PORT}/")


def main():
    parser = argparse.ArgumentParser(
        prog="python cli.py",
        description="sift command-line interface",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("serve", help="start the sift server")

    p_send = sub.add_parser("send", help="POST an alert file to a running sift")
    p_send.add_argument("file", help="path to a JSON alert file")
    p_send.add_argument("--url", default="http://127.0.0.1:8000", help="sift base URL")
    p_send.add_argument("--endpoint", default="", help="override /webhook/<source>")
    p_send.add_argument("--token", default=os.environ.get("SIFT_WEBHOOK_TOKEN", ""),
                        help="X-Sift-Webhook-Token (reads $SIFT_WEBHOOK_TOKEN by default)")

    sub.add_parser("init-db", help="initialise or migrate the database")

    p_export = sub.add_parser("export", help="dump all alerts as JSON lines")
    p_export  # no extra args

    sub.add_parser("reset-demo", help="clear DB and reload sample_alerts/")

    args = parser.parse_args()
    {
        "serve": cmd_serve,
        "send": cmd_send,
        "init-db": cmd_init_db,
        "export": cmd_export,
        "reset-demo": cmd_reset_demo,
    }[args.command](args)


if __name__ == "__main__":
    main()
