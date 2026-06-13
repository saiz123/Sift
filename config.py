"""
sift configuration — this is the file you tune.

Everything that decides how alerts are scored lives here in plain numbers and
lists, so you can change behaviour without touching the engine. Edit, save,
restart sift. Nothing here is secret except the optional API keys, which are
read from the environment (or a local .env file) instead.
"""

import os

# ---------------------------------------------------------------------------
# Verdict thresholds
# An alert's signals are summed into a single score. The score lands it in one
# of three buckets:
#
#     score < JUNK_BELOW      -> "JUNK"      (auto-closed, but kept with reasons)
#     score >= ESCALATE_AT    -> "ESCALATE"  (a human should look now)
#     anything in between     -> "REVIEW"    (a human should judge when able)
# ---------------------------------------------------------------------------
JUNK_BELOW = 20
ESCALATE_AT = 60

# ---------------------------------------------------------------------------
# Signal weights — how many points each signal adds (+) or removes (-).
# These are the dials you'll turn most often as you learn your environment.
# ---------------------------------------------------------------------------
WEIGHTS = {
    # Trust the SIEM's own severity as a baseline: points = level * multiplier.
    # A Wazuh rule at level 12 contributes 12 * 4 = 48 points.
    "wazuh_level_multiplier": 4,

    # Source IP flagged as malicious by AbuseIPDB (needs ABUSEIPDB_KEY).
    "bad_ip": 50,

    # File hash flagged as malicious by VirusTotal (needs VIRUSTOTAL_KEY).
    "bad_hash": 50,

    # The alert fired on an asset you marked critical (see CRITICAL_ASSETS).
    "critical_asset": 30,

    # The activity happened outside business hours.
    "off_hours": 15,

    # This user has alerts in sift's history, but never from this source IP —
    # could be a new device, could be a stolen credential used elsewhere.
    "new_source_for_user": 25,

    # The source IP is on your trusted allowlist — strong pull toward junk.
    "allowlisted_ip": -60,

    # The source user is on your trusted allowlist (e.g. a known service
    # account) — strong pull toward junk.
    "allowlisted_user": -40,

    # The file hash is on your trusted allowlist (e.g. a known-good internal
    # tool) — strong pull toward junk.
    "allowlisted_hash": -40,

    # Maximum penalty for a rule that is historically almost always a false
    # alarm. The actual penalty scales with the rule's false-positive rate,
    # so a rule wrong 90% of the time gets ~90% of this.
    "noisy_rule_max_penalty": -45,

    # Many identical alerts (same rule + same source) seen recently — usually
    # a scanner or a misconfiguration, not an incident.
    "duplicate_flood": -20,
}

# ---------------------------------------------------------------------------
# Assets whose compromise matters most. Matched as a case-insensitive
# substring against the alert's target (the agent/host the alert fired on).
# ---------------------------------------------------------------------------
CRITICAL_ASSETS = [
    "dc01", "dc02", "domain-controller",
    "vault", "prod-db", "jump-host",
]

# ---------------------------------------------------------------------------
# Source IPs you trust. Plain addresses or CIDR ranges both work.
# ---------------------------------------------------------------------------
ALLOWLIST_IPS = [
    "203.0.113.10",      # example: the office static IP
    "198.51.100.0/24",   # example: a trusted partner range
]

# ---------------------------------------------------------------------------
# Usernames you trust even when they trigger noisy rules — e.g. service
# accounts or scanners that legitimately do unusual things. Case-insensitive.
# ---------------------------------------------------------------------------
ALLOWLIST_USERS = [
    # "svc-backup",
    # "vuln-scanner",
]

# ---------------------------------------------------------------------------
# File hashes you trust — e.g. an internal tool that AV/EDR sometimes flags.
# Any algorithm (md5/sha1/sha256), matched case-insensitively.
# ---------------------------------------------------------------------------
ALLOWLIST_HASHES = [
    # "44d88612fea8a8f36de82e1278abb02f",
]

# ---------------------------------------------------------------------------
# Local business hours, 24-hour clock, in the server's local time.
# Used by the off-hours signal.
# ---------------------------------------------------------------------------
BUSINESS_START = 8
BUSINESS_END = 18

# ---------------------------------------------------------------------------
# Duplicate-flood detection.
# If at least DUPLICATE_FLOOD_COUNT alerts with the same rule + source have
# arrived within the last DUPLICATE_WINDOW_HOURS, treat this as noise.
# ---------------------------------------------------------------------------
DUPLICATE_WINDOW_HOURS = 24
DUPLICATE_FLOOD_COUNT = 50

# How conservatively to read a rule's false-positive track record. The noisy-
# rule penalty is scaled by the lower bound of a Wilson confidence interval on
# the false-positive rate, not the raw rate — so one early false positive
# barely moves the score, and the penalty firms up as decisions accumulate.
# Higher = more conservative (slower to penalise). 1.96 ~= 95% confidence.
NOISY_RULE_CONFIDENCE_Z = 1.96

# A user needs at least this many prior alerts before "never seen from this
# IP" is meaningful. Stops every user's very first alert from being flagged.
MIN_OBSERVATIONS_FOR_USER_HISTORY = 3

# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------
HOST = os.environ.get("SIFT_HOST", "127.0.0.1")
PORT = int(os.environ.get("SIFT_PORT", "8000"))
DB_PATH = os.environ.get("SIFT_DB", "sift.db")

# ---------------------------------------------------------------------------
# Optional enrichment API keys. Leave unset and sift simply skips those
# signals — it still works, just with less to go on. Set them via real
# environment variables or a local .env file (KEY=value per line).
# ---------------------------------------------------------------------------

def _load_dotenv(path=".env"):
    """Minimal .env loader so we keep zero third-party dependencies."""
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_dotenv()

ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_KEY", "")
VIRUSTOTAL_KEY = os.environ.get("VIRUSTOTAL_KEY", "")
