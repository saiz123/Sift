"""
Turn a raw alert from any supported source into the small, flat shape the
scorer understands.

Source alerts are deeply nested and vary by rule type, so we reach into the
likely places for each field and fall back gracefully when something's
missing. Adding a new source means adding a sibling normaliser here and
wiring it to a route in sift.py; nothing downstream needs to know which tool
an alert came from.

Every normaliser returns either ``None`` (skip this payload — e.g. a
Suricata "flow" event that isn't an alert) or a dict with these keys:

    source          short name of the source, e.g. "wazuh"
    rule_id         the source's rule/signature/finding identifier
    rule_desc       a human description of what fired
    rule_level      severity normalised onto sift's 0-15 scale
    severity_detail a sentence explaining how rule_level was derived
    src_ip          the source/attacker IP, if any
    src_user        the user involved, if any
    target          the asset the alert concerns (host, instance, etc.)
    file_hash       a file hash involved, if any
    timestamp       the source's own timestamp for the event
    raw             the untouched original payload
"""

import config


def _dig(d, *path, default=None):
    """Safely walk a chain of dict keys."""
    cur = d
    for key in path:
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        else:
            return default
    return cur


def _dig_path(d, path, default=None):
    """Like _dig, but the path is a single dotted string, e.g. "alert.severity"."""
    if not path:
        return default
    return _dig(d, *str(path).split("."), default=default)


def _first(*values):
    for v in values:
        if v not in (None, "", []):
            return v
    return None


def _first_of(items):
    """The first dict in a list field (e.g. hostStates[0]), or {} if empty/missing."""
    if isinstance(items, list) and items and isinstance(items[0], dict):
        return items[0]
    return {}


def _to_str(v):
    """Coerce a scalar to str, or return None for dict/list — prevents SQLite bind errors."""
    if v is None:
        return None
    if isinstance(v, (dict, list)):
        return None
    return str(v)


def _clamp_level(value):
    """Round to the nearest int and clamp onto sift's 0-15 severity scale."""
    try:
        level = round(float(value))
    except (TypeError, ValueError):
        return 0
    return max(0, min(15, level))


def _scale_to_15(value, max_value):
    """Map a 0..max_value severity onto sift's 0-15 scale."""
    try:
        value = float(value)
        max_value = float(max_value)
    except (TypeError, ValueError):
        return 0
    if max_value <= 0:
        return 0
    return _clamp_level(value / max_value * 15)


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
        "source": "wazuh",
        "rule_id": _to_str(rule.get("id")),
        "rule_desc": _to_str(rule.get("description")),
        "rule_level": level,
        "severity_detail": f"Wazuh rule level {level} of 15",
        "src_ip": _to_str(src_ip),
        "src_user": _to_str(_first(data.get("srcuser"), data.get("dstuser"), data.get("user"))),
        "target": _to_str(target),
        "file_hash": _to_str(file_hash),
        "timestamp": raw.get("timestamp"),
        "raw": raw,
    }


def normalize_suricata(raw):
    """
    Turn a Suricata EVE JSON "alert" event into sift's flat shape.

    eve.json carries many event types (flow, dns, http, tls, ...); only
    "alert" events represent a signature firing, so anything else is skipped
    by returning None — point sift at the whole eve.json without flooding
    the queue with non-alert traffic records.
    """
    if not isinstance(raw, dict):
        return None
    alert = raw.get("alert")
    if raw.get("event_type") != "alert" or not isinstance(alert, dict):
        return None

    fileinfo = raw.get("fileinfo") if isinstance(raw.get("fileinfo"), dict) else {}

    try:
        severity = int(alert.get("severity", 3))
    except (TypeError, ValueError):
        severity = 3

    # Suricata severity runs 1 (highest priority) to 3 (lowest) — the
    # opposite direction from sift's scale, so flip it before spreading it
    # across 0-15.
    level = _clamp_level((4 - severity) * 5)

    sig_id = alert.get("signature_id")

    return {
        "source": "suricata",
        "rule_id": _to_str(sig_id),
        "rule_desc": _to_str(_first(alert.get("signature"), alert.get("category"))),
        "rule_level": level,
        "severity_detail": f"Suricata severity {severity} (1=highest, 3=lowest) -> level {level} of 15",
        "src_ip": _to_str(raw.get("src_ip")),
        "src_user": None,
        "target": _to_str(_first(raw.get("dest_ip"), raw.get("host"))),
        "file_hash": _to_str(_first(fileinfo.get("sha256"), fileinfo.get("md5"))),
        "timestamp": raw.get("timestamp"),
        "raw": raw,
    }


# ECS's free-text rule.severity (low/medium/high/critical) spread evenly
# across sift's 0-15 scale.
_ECS_SEVERITY_LEVELS = {"low": 4, "medium": 8, "high": 12, "critical": 15}


def normalize_elastic(raw):
    """
    Turn an Elastic Common Schema (ECS) document — e.g. a Kibana detection
    alert sent via a webhook connector, or any ECS-shaped JSON from Beats/
    Elastic Agent/Logstash — into sift's flat shape.
    """
    if not isinstance(raw, dict):
        return None

    rule = raw.get("rule") if isinstance(raw.get("rule"), dict) else {}
    event = raw.get("event") if isinstance(raw.get("event"), dict) else {}
    source = raw.get("source") if isinstance(raw.get("source"), dict) else {}
    destination = raw.get("destination") if isinstance(raw.get("destination"), dict) else {}
    host = raw.get("host") if isinstance(raw.get("host"), dict) else {}
    user = raw.get("user") if isinstance(raw.get("user"), dict) else {}
    file_ = raw.get("file") if isinstance(raw.get("file"), dict) else {}
    file_hash = file_.get("hash") if isinstance(file_.get("hash"), dict) else {}

    label = (rule.get("severity") or "").lower()
    risk_score = _first(rule.get("risk_score"), event.get("risk_score"))

    if label in _ECS_SEVERITY_LEVELS:
        level = _ECS_SEVERITY_LEVELS[label]
        severity_detail = f"Elastic rule severity '{label}' -> level {level} of 15"
    elif risk_score is not None:
        level = _scale_to_15(risk_score, 100)
        severity_detail = f"Elastic risk score {risk_score}/100 -> level {level} of 15"
    elif event.get("severity") is not None:
        raw_severity = event.get("severity")
        level = _scale_to_15(raw_severity, 100)
        severity_detail = f"Elastic event severity {raw_severity} -> level {level} of 15"
    else:
        level = 0
        severity_detail = "Elastic alert carried no severity field"

    rule_id = _first(rule.get("id"), rule.get("uuid"))

    return {
        "source": "elastic",
        "rule_id": _to_str(rule_id),
        "rule_desc": _to_str(_first(rule.get("description"), rule.get("name"))),
        "rule_level": level,
        "severity_detail": severity_detail,
        "src_ip": _to_str(source.get("ip")),
        "src_user": _to_str(user.get("name")),
        "target": _to_str(_first(host.get("name"), destination.get("ip"))),
        "file_hash": _to_str(_first(file_hash.get("sha256"), file_hash.get("md5"), file_hash.get("sha1"))),
        "timestamp": raw.get("@timestamp"),
        "raw": raw,
    }


def _guardduty_remote_ip(raw):
    """GuardDuty buries the attacker IP under whichever action type fired."""
    action = _dig(raw, "service", "action", default={})
    if not isinstance(action, dict):
        return None
    for action_key in (
        "networkConnectionAction",
        "awsApiCallAction",
        "portProbeAction",
        "kubernetesApiCallAction",
    ):
        details = action.get(action_key)
        if not isinstance(details, dict):
            continue
        remote = details.get("remoteIpDetails")
        if isinstance(remote, dict) and remote.get("ipAddressV4"):
            return remote["ipAddressV4"]
        for probe in details.get("portProbeDetails") or []:
            remote = _dig(probe, "remoteIpDetails", default={})
            if isinstance(remote, dict) and remote.get("ipAddressV4"):
                return remote["ipAddressV4"]
    return None


def normalize_guardduty(raw):
    """Turn an AWS GuardDuty finding into sift's flat shape."""
    if not isinstance(raw, dict):
        return None
    if "type" not in raw or "severity" not in raw:
        return None

    try:
        severity = float(raw.get("severity", 0))
    except (TypeError, ValueError):
        severity = 0.0

    # GuardDuty severity runs 0.1 (informational) to 8.9 (critical).
    level = _scale_to_15(severity, 8.9)

    instance_id = _dig(raw, "resource", "instanceDetails", "instanceId")
    access_key_user = _dig(raw, "resource", "accessKeyDetails", "userName")

    return {
        "source": "guardduty",
        "rule_id": _to_str(raw.get("type")),
        "rule_desc": _to_str(_first(raw.get("title"), raw.get("description"))),
        "rule_level": level,
        "severity_detail": f"GuardDuty severity {severity:g} of 8.9 -> level {level} of 15",
        "src_ip": _to_str(_guardduty_remote_ip(raw)),
        "src_user": _to_str(access_key_user),
        "target": _to_str(_first(instance_id, raw.get("accountId"))),
        "file_hash": None,
        "timestamp": _first(raw.get("updatedAt"), raw.get("createdAt")),
        "raw": raw,
    }


# Microsoft Graph's free-text alert severity (informational/low/medium/high)
# spread across sift's 0-15 scale. The legacy alerts API has no "critical"
# tier, so "high" lands below the very top of the range.
_M365_SEVERITY_LEVELS = {"informational": 2, "low": 5, "medium": 9, "high": 13}


def normalize_m365(raw):
    """
    Turn a Microsoft Graph Security API alert (the `/security/alerts` shape —
    e.g. forwarded from Defender for Endpoint, Defender for Identity, Defender
    for Cloud Apps, or Sentinel) into sift's flat shape.
    """
    if not isinstance(raw, dict):
        return None
    if "vendorInformation" not in raw and "azureTenantId" not in raw:
        return None

    label = str(raw.get("severity") or "").lower()
    if label in _M365_SEVERITY_LEVELS:
        level = _M365_SEVERITY_LEVELS[label]
        severity_detail = f"Microsoft Graph severity '{label}' -> level {level} of 15"
    else:
        level = 0
        severity_detail = "Microsoft Graph alert carried no recognised severity"

    host = _first_of(raw.get("hostStates"))
    user = _first_of(raw.get("userStates"))
    network = _first_of(raw.get("networkConnections"))
    file_state = _first_of(raw.get("fileStates"))
    file_hash = file_state.get("fileHash") if isinstance(file_state.get("fileHash"), dict) else {}

    src_ip = _first(
        network.get("sourceAddress"),
        user.get("logonIp"),
        host.get("publicIpAddress"),
        host.get("privateIpAddress"),
    )

    category = raw.get("category")

    return {
        "source": "m365",
        "rule_id": _to_str(category),
        "rule_desc": _to_str(_first(raw.get("title"), raw.get("description"))),
        "rule_level": level,
        "severity_detail": severity_detail,
        "src_ip": _to_str(src_ip),
        "src_user": _to_str(_first(user.get("userPrincipalName"), user.get("accountName"))),
        "target": _to_str(_first(host.get("fqdn"), host.get("netBiosName"))),
        "file_hash": _to_str(file_hash.get("hashValue")),
        "timestamp": _first(raw.get("eventDateTime"), raw.get("createdDateTime")),
        "raw": raw,
    }


def normalize_generic(raw):
    """
    Turn arbitrary JSON into sift's flat shape using config.GENERIC_FIELD_MAP
    — a dict of dotted paths into `raw`, one per sift field, configured by
    the user for whatever tool they're wiring up. No Python required.
    """
    if not isinstance(raw, dict):
        return None

    field_map = config.GENERIC_FIELD_MAP

    def get(field):
        return _dig_path(raw, field_map.get(field))

    severity_raw = get("severity")
    severity_max = field_map.get("severity_max", 15)
    if severity_raw is not None:
        level = _scale_to_15(severity_raw, severity_max)
        severity_detail = f"severity {severity_raw}/{severity_max} -> level {level} of 15"
    else:
        level = 0
        severity_detail = "no severity field configured in GENERIC_FIELD_MAP"

    rule_id = get("rule_id")

    return {
        "source": "generic",
        "rule_id": _to_str(rule_id),
        "rule_desc": _to_str(get("rule_desc")),
        "rule_level": level,
        "severity_detail": severity_detail,
        "src_ip": _to_str(get("src_ip")),
        "src_user": _to_str(get("src_user")),
        "target": _to_str(get("target")),
        "file_hash": _to_str(get("file_hash")),
        "timestamp": get("timestamp"),
        "raw": raw,
    }
