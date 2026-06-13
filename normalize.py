"""
Turn a raw Wazuh alert into the small, flat shape the scorer understands.

Wazuh alerts are deeply nested and vary by rule type, so we reach into the
likely places for each field and fall back gracefully when something's
missing. Adding a second SIEM later means adding a sibling normaliser here;
nothing downstream needs to know which SIEM an alert came from.
"""


def _dig(d, *path, default=None):
    """Safely walk a chain of dict keys."""
    cur = d
    for key in path:
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        else:
            return default
    return cur


def _first(*values):
    for v in values:
        if v not in (None, "", []):
            return v
    return None


def normalize_wazuh(raw):
    rule = raw.get("rule", {}) if isinstance(raw, dict) else {}
    data = raw.get("data", {}) if isinstance(raw, dict) else {}
    agent = raw.get("agent", {}) if isinstance(raw, dict) else {}
    syscheck = raw.get("syscheck", {}) if isinstance(raw, dict) else {}

    try:
        level = int(rule.get("level", 0))
    except (TypeError, ValueError):
        level = 0

    src_ip = _first(
        data.get("srcip"),
        _dig(data, "src_ip"),
        _dig(raw, "src_ip"),
    )

    file_hash = _first(
        data.get("sha256"),
        data.get("md5"),
        syscheck.get("sha256_after"),
        syscheck.get("md5_after"),
        _dig(data, "hash"),
    )

    # The asset the alert fired on is the most useful "target" for judging
    # blast radius, so we prefer the agent name and fall back to the location.
    target = _first(
        agent.get("name"),
        raw.get("location"),
        agent.get("ip"),
    )

    return {
        "rule_id": str(rule.get("id")) if rule.get("id") is not None else None,
        "rule_desc": rule.get("description"),
        "rule_level": level,
        "src_ip": src_ip,
        "src_user": _first(data.get("srcuser"), data.get("dstuser"), data.get("user")),
        "target": target,
        "file_hash": file_hash,
        "timestamp": raw.get("timestamp"),
        "raw": raw,
    }
