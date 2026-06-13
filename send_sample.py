"""
Send one alert file to a running sift and print the verdict it returns.

    python3 send_sample.py sample_alerts/real_attack.json
    python3 send_sample.py sample_alerts/real_attack.json http://127.0.0.1:8000

Handy for trying things out and for wiring into your own test scripts.
"""

import json
import sys
import urllib.request


def main():
    if len(sys.argv) < 2:
        print("usage: python3 send_sample.py <alert.json> [base_url]")
        sys.exit(1)

    path = sys.argv[1]
    base = sys.argv[2].rstrip("/") if len(sys.argv) > 2 else "http://127.0.0.1:8000"

    with open(path, "rb") as fh:
        body = fh.read()

    req = urllib.request.Request(
        base + "/webhook/wazuh", data=body,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        print(f"could not reach sift at {base} — is it running?  ({exc})")
        sys.exit(1)

    sign = lambda p: f"+{p}" if p >= 0 else str(p)
    print(f"\n  verdict: {result['verdict']}   score: {result['score']}   (alert #{result['id']})")
    print("  receipt:")
    for item in result["receipt"]:
        print(f"    {sign(item['points']):>5}  {item['label']}  —  {item['detail']}")
    print(f"\n  see it: {base}/alert/{result['id']}\n")


if __name__ == "__main__":
    main()
