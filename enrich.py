"""
Optional threat-intelligence enrichment.

Two lookups, both standard-library HTTP (urllib), both entirely optional:
  - AbuseIPDB for source-IP reputation
  - VirusTotal for file-hash reputation

If the matching API key isn't set, or the network call fails for any reason,
the lookup quietly returns None and that signal is simply skipped. sift never
blocks on enrichment and never crashes because a feed was unreachable — which
also means it runs fine in an air-gapped environment with no keys at all.

Results are cached in SQLite so the same IP or hash isn't queried twice.
"""

import json
import urllib.request
import urllib.parse

import config
import db

TIMEOUT_SECONDS = 6


def _http_get_json(url, headers):
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
        return json.loads(resp.read().decode("utf-8"))


def check_ip(ip):
    """
    Returns {'abuse_score': 0-100, 'reports': int} or None.
    abuse_score is AbuseIPDB's confidence that the IP is malicious.
    """
    if not ip or not config.ABUSEIPDB_KEY:
        return None

    cache_key = f"ip:{ip}"
    cached = db.cache_get(cache_key)
    if cached is not None:
        return cached

    try:
        url = "https://api.abuseipdb.com/api/v2/check?" + urllib.parse.urlencode(
            {"ipAddress": ip, "maxAgeInDays": 90}
        )
        payload = _http_get_json(
            url,
            headers={"Key": config.ABUSEIPDB_KEY, "Accept": "application/json"},
        )
        data = payload.get("data", {})
        result = {
            "abuse_score": int(data.get("abuseConfidenceScore", 0)),
            "reports": int(data.get("totalReports", 0)),
        }
    except Exception:
        return None

    db.cache_set(cache_key, result)
    return result


def check_hash(file_hash):
    """
    Returns {'malicious': int, 'total': int} or None.
    malicious is the number of VirusTotal engines that flagged the file.
    """
    if not file_hash or not config.VIRUSTOTAL_KEY:
        return None

    cache_key = f"hash:{file_hash}"
    cached = db.cache_get(cache_key)
    if cached is not None:
        return cached

    try:
        url = f"https://www.virustotal.com/api/v3/files/{urllib.parse.quote(file_hash)}"
        payload = _http_get_json(url, headers={"x-apikey": config.VIRUSTOTAL_KEY})
        stats = (
            payload.get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )
        malicious = int(stats.get("malicious", 0))
        total = sum(int(v) for v in stats.values()) if stats else 0
        result = {"malicious": malicious, "total": total}
    except Exception:
        return None

    db.cache_set(cache_key, result)
    return result
