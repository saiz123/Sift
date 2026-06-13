"""
The scoring checks — the heart of sift.

Each check looks at one aspect of an alert and either stays silent (returns
None) or returns a single receipt line: a human-readable label, a point value
(+ raises suspicion, - lowers it), and a short detail explaining itself.

The whole design rule here is: every point that moves the score must come with
a sentence a tired analyst can read at 3am and immediately agree or disagree
with. No hidden math. Adding a new signal = adding one function to this file
and listing it in ALL_CHECKS at the bottom.
"""

import ipaddress

import config


def _line(label, points, detail):
    return {"label": label, "points": int(points), "detail": detail}


def _ip_in_list(ip, entries):
    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return False
    for entry in entries:
        try:
            if "/" in entry:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            elif addr == ipaddress.ip_address(entry):
                return True
        except ValueError:
            continue
    return False


# --- checks ---------------------------------------------------------------
# Signature: check(alert: dict, ctx: dict) -> line dict | None
# ctx holds anything that needed a database or network lookup, gathered once
# by the scorer so individual checks stay cheap and pure.


def check_wazuh_level(alert, ctx):
    level = alert.get("rule_level") or 0
    if level <= 0:
        return None
    points = level * config.WEIGHTS["wazuh_level_multiplier"]
    return _line(
        "SIEM severity",
        points,
        f"Wazuh rule level {level} of 15",
    )


def check_bad_ip(alert, ctx):
    intel = ctx.get("ip_intel")
    if not intel:
        return None
    score = intel.get("abuse_score", 0)
    if score < 25:
        return None
    # Full weight for a confident hit, half for a borderline one.
    weight = config.WEIGHTS["bad_ip"]
    points = weight if score >= 50 else weight // 2
    return _line(
        "Malicious source IP",
        points,
        f"{alert.get('src_ip')} — AbuseIPDB confidence {score}% "
        f"({intel.get('reports', 0)} reports)",
    )


def check_bad_hash(alert, ctx):
    intel = ctx.get("hash_intel")
    if not intel:
        return None
    malicious = intel.get("malicious", 0)
    if malicious < 1:
        return None
    return _line(
        "Malicious file hash",
        config.WEIGHTS["bad_hash"],
        f"Flagged by {malicious}/{intel.get('total', '?')} VirusTotal engines",
    )


def check_critical_asset(alert, ctx):
    target = (alert.get("target") or "").lower()
    if not target:
        return None
    for asset in config.CRITICAL_ASSETS:
        if asset.lower() in target:
            return _line(
                "Critical asset",
                config.WEIGHTS["critical_asset"],
                f"Target '{alert.get('target')}' matches critical asset '{asset}'",
            )
    return None


def check_off_hours(alert, ctx):
    hour = ctx.get("hour")
    if hour is None:
        return None
    if config.BUSINESS_START <= hour < config.BUSINESS_END:
        return None
    return _line(
        "Outside business hours",
        config.WEIGHTS["off_hours"],
        f"Activity at {hour:02d}:00, outside "
        f"{config.BUSINESS_START:02d}:00-{config.BUSINESS_END:02d}:00",
    )


def check_allowlisted_ip(alert, ctx):
    ip = alert.get("src_ip")
    if ip and _ip_in_list(ip, config.ALLOWLIST_IPS):
        return _line(
            "Trusted source",
            config.WEIGHTS["allowlisted_ip"],
            f"{ip} is on the allowlist",
        )
    return None


def check_noisy_rule(alert, ctx):
    stats = ctx.get("rule_stats")
    if not stats:
        return None
    total = stats.get("total", 0)
    if total < config.MIN_OBSERVATIONS_FOR_TRACK_RECORD:
        return None
    fp = stats.get("fp", 0)
    fp_rate = fp / total
    if fp_rate <= 0:
        return None
    points = round(config.WEIGHTS["noisy_rule_max_penalty"] * fp_rate)
    if points == 0:
        return None
    return _line(
        "Historically noisy rule",
        points,
        f"This rule was a false alarm {fp}/{total} times ({fp_rate:.0%})",
    )


def check_duplicate_flood(alert, ctx):
    count = ctx.get("duplicate_count", 0)
    if count < config.DUPLICATE_FLOOD_COUNT:
        return None
    return _line(
        "Repeated noise",
        config.WEIGHTS["duplicate_flood"],
        f"{count} identical alerts in the last {config.DUPLICATE_WINDOW_HOURS}h "
        f"(same rule + source)",
    )


# Order here is the order line items appear on the receipt.
ALL_CHECKS = [
    check_wazuh_level,
    check_critical_asset,
    check_bad_ip,
    check_bad_hash,
    check_off_hours,
    check_noisy_rule,
    check_duplicate_flood,
    check_allowlisted_ip,
]
