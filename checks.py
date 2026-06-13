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


def _wilson_lower_bound(successes, total, z):
    """
    Lower bound of the Wilson score confidence interval for a proportion.

    With few observations this sits well below the raw rate (so a rule with
    one false positive isn't treated as "100% noisy"); as observations pile
    up it converges on the raw rate. That single curve replaces a hard
    minimum-observations cutoff.
    """
    if total <= 0:
        return 0.0
    p = successes / total
    z2 = z * z
    denom = 1 + z2 / total
    center = p + z2 / (2 * total)
    margin = z * ((p * (1 - p) / total + z2 / (4 * total * total)) ** 0.5)
    return (center - margin) / denom


# --- checks ---------------------------------------------------------------
# Signature: check(alert: dict, ctx: dict) -> line dict | None
# ctx holds anything that needed a database or network lookup, gathered once
# by the scorer so individual checks stay cheap and pure.


def check_severity(alert, ctx):
    level = alert.get("rule_level") or 0
    if level <= 0:
        return None
    points = level * config.WEIGHTS["severity_multiplier"]
    detail = alert.get("severity_detail") or f"Severity level {level} of 15"
    return _line("SIEM severity", points, detail)


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


def check_new_source_for_user(alert, ctx):
    user = alert.get("src_user")
    ip = alert.get("src_ip")
    if not user or not ip:
        return None
    history = ctx.get("user_history") or {}
    if history.get("total", 0) < config.MIN_OBSERVATIONS_FOR_USER_HISTORY:
        return None
    if history.get("seen_this_ip"):
        return None
    return _line(
        "Unfamiliar source for user",
        config.WEIGHTS["new_source_for_user"],
        f"'{user}' has never alerted from {ip} before "
        f"(seen from other sources in {history['total']} prior alerts)",
    )


def check_velocity(alert, ctx):
    user = alert.get("src_user")
    ip = alert.get("src_ip")
    if not user or not ip:
        return None
    ips = (ctx.get("recent_ips") or set()) | {ip}
    if len(ips) < config.VELOCITY_IP_THRESHOLD:
        return None
    return _line(
        "Source-IP velocity",
        config.WEIGHTS["velocity"],
        f"'{user}' alerted from {len(ips)} different source IPs "
        f"({', '.join(sorted(ips))}) within {config.VELOCITY_WINDOW_HOURS}h — "
        f"possible impossible travel or a shared/stolen credential",
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


def check_allowlisted_user(alert, ctx):
    user = alert.get("src_user")
    if not user:
        return None
    allowed = {u.lower() for u in config.ALLOWLIST_USERS}
    if user.lower() in allowed:
        return _line(
            "Trusted user",
            config.WEIGHTS["allowlisted_user"],
            f"'{user}' is on the user allowlist",
        )
    return None


def check_allowlisted_hash(alert, ctx):
    file_hash = alert.get("file_hash")
    if not file_hash:
        return None
    allowed = {h.lower() for h in config.ALLOWLIST_HASHES}
    if file_hash.lower() in allowed:
        return _line(
            "Trusted file hash",
            config.WEIGHTS["allowlisted_hash"],
            f"{file_hash} is on the hash allowlist",
        )
    return None


def check_noisy_rule(alert, ctx):
    stats = ctx.get("rule_stats")
    if not stats:
        return None
    total = stats.get("total", 0)
    fp = stats.get("fp", 0)
    if total == 0 or fp == 0:
        return None
    confidence = _wilson_lower_bound(fp, total, config.NOISY_RULE_CONFIDENCE_Z)
    points = round(config.WEIGHTS["noisy_rule_max_penalty"] * confidence)
    if points == 0:
        return None
    fp_rate = fp / total
    return _line(
        "Historically noisy rule",
        points,
        f"False alarm {fp}/{total} times ({fp_rate:.0%}) — "
        f"{confidence:.0%} confident it's at least that noisy",
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
    check_severity,
    check_critical_asset,
    check_bad_ip,
    check_bad_hash,
    check_off_hours,
    check_new_source_for_user,
    check_velocity,
    check_noisy_rule,
    check_duplicate_flood,
    check_allowlisted_ip,
    check_allowlisted_user,
    check_allowlisted_hash,
]
