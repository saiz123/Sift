"""
Optional threat-intelligence enrichment.

Two keyed lookups, both standard-library HTTP (urllib), both entirely
optional:
  - AbuseIPDB for source-IP reputation
  - VirusTotal for file-hash reputation

Plus a set of free, keyless bulk IP blocklists (see config.THREAT_FEEDS):
abuse.ch Feodo Tracker and SSLBL, the Tor exit-node list, and an optional
local CSV/text blocklist file for fully air-gapped use.

If the matching API key isn't set, a feed is disabled, or any network call
fails for any reason, the lookup quietly returns None/empty and that signal
is simply skipped. sift never blocks on enrichment and never crashes because
a feed was unreachable — which also means it runs fine in an air-gapped
environment with no keys and no internet access at all.

Results are cached in SQLite so the same IP, hash, or feed isn't fetched
again before it's due to be refreshed.
"""

import datetime as dt
import ipaddress
import json
import sys
import urllib.request
import urllib.parse

import config
from ..storage import db

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

    # Short-TTL negative sentinel: skip if a recent lookup failed.
    if db.cache_get(f"neg:{cache_key}", max_age_hours=config.ENRICH_NEGATIVE_CACHE_TTL_HOURS) is not None:
        return None

    cached = db.cache_get(cache_key, max_age_hours=config.ENRICH_CACHE_IP_TTL_HOURS)
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
    except Exception as exc:
        print(f"  [enrich] AbuseIPDB lookup for {ip} failed: {exc!r}", file=sys.stderr)
        db.cache_set(f"neg:{cache_key}", {"_negative": True})
        return None

    db.cache_set(cache_key, result)
    return result


# --- bulk IP threat feeds ---------------------------------------------------

def _fetch_lines(url):
    req = urllib.request.Request(url, headers={"User-Agent": "sift/1.0"})
    with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
        return resp.read().decode("utf-8", errors="replace").splitlines()


def _parse_ip_list(lines):
    """
    Pull bare IP addresses out of a bulk feed: skip blank lines and '#'
    comments, and take the first whitespace/comma-separated token from each
    remaining line (some feeds append extra columns after the IP).
    """
    ips = set()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        candidate = line.split()[0].split(",")[0]
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        ips.add(candidate)
    return ips


def _feed_ip_set(name, url):
    """
    The IP set for one configured threat feed, cached in enrich_cache and
    refreshed at most every config.THREAT_FEED_REFRESH_HOURS. Falls back to
    the last successfully-fetched copy (or an empty set if there's never been
    one) if the feed can't be reached right now.
    """
    cache_key = f"feed:{name}"
    cached = db.cache_get(cache_key)
    if cached:
        fetched_at = dt.datetime.fromisoformat(cached["fetched_at"])
        age_hours = (dt.datetime.now() - fetched_at).total_seconds() / 3600
        if age_hours < config.THREAT_FEED_REFRESH_HOURS:
            return set(cached["ips"])

    try:
        ips = _parse_ip_list(_fetch_lines(url))
    except Exception as exc:
        print(f"  [enrich] threat feed '{name}' fetch failed: {exc!r}", file=sys.stderr)
        return set(cached["ips"]) if cached else set()

    db.cache_set(cache_key, {
        "ips": sorted(ips),
        "fetched_at": dt.datetime.now().isoformat(timespec="seconds"),
    })
    return ips


def local_blocklist_ips():
    """
    IPs from config.LOCAL_BLOCKLIST_PATH, if set — same format as the bulk
    feeds above (one IP per line, '#' comments). Read fresh every call since
    it's a small local file an analyst may edit at any time.
    """
    if not config.LOCAL_BLOCKLIST_PATH:
        return set()
    try:
        with open(config.LOCAL_BLOCKLIST_PATH, "r", encoding="utf-8") as fh:
            return _parse_ip_list(fh)
    except OSError:
        return set()


def check_ip_feeds(ip):
    """
    Returns {'feeds': [names...]} listing which configured threat feeds (see
    config.THREAT_FEEDS) and/or the local blocklist contain this IP, or None
    if the IP is empty or matches nothing.
    """
    if not ip:
        return None
    hits = []
    if config.ENABLE_THREAT_FEEDS:
        for name, url in config.THREAT_FEEDS.items():
            if ip in _feed_ip_set(name, url):
                hits.append(name)
    if ip in local_blocklist_ips():
        hits.append("local_blocklist")
    return {"feeds": hits} if hits else None


def check_hash(file_hash):
    """
    Returns {'malicious': int, 'total': int} or None.
    malicious is the number of VirusTotal engines that flagged the file.
    """
    if not file_hash or not config.VIRUSTOTAL_KEY:
        return None

    cache_key = f"hash:{file_hash}"

    # Short-TTL negative sentinel: skip if a recent lookup failed.
    if db.cache_get(f"neg:{cache_key}", max_age_hours=config.ENRICH_NEGATIVE_CACHE_TTL_HOURS) is not None:
        return None

    cached = db.cache_get(cache_key, max_age_hours=config.ENRICH_CACHE_HASH_TTL_HOURS)
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
    except Exception as exc:
        print(f"  [enrich] VirusTotal lookup for {file_hash} failed: {exc!r}", file=sys.stderr)
        db.cache_set(f"neg:{cache_key}", {"_negative": True})
        return None

    db.cache_set(cache_key, result)
    return result
