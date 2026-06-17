"""
Generate SVG mockup screenshots of the sift UI.
Run: python docs/make_screenshots.py
Outputs: docs/screenshots/dashboard.svg, alert-detail.svg, cases.svg
"""

import os

OUT = os.path.join(os.path.dirname(__file__), "screenshots")
os.makedirs(OUT, exist_ok=True)

# ── color palette (matches views.py CSS vars) ──────────────────────────────
S900 = "#191f26"
S850 = "#1f262e"
S800 = "#252e38"
LINE = "#374350"
TEXT = "#e7ebf0"
MUTED = "#94a0ad"
FAINT = "#6c7884"
PAPER = "#f6f4ec"
PAPER_INK = "#23282d"
PAPER_LINE = "#d8d2c2"
ESC = "#d64541"
REV = "#d99a2b"
JUNK = "#7f8b98"
ACCENT = "#46a3a0"
GREEN = "#2f7d52"


def svg_header(w, h):
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" '
        f'viewBox="0 0 {w} {h}">'
        f'<defs>'
        f'<style>'
        f'text {{ font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; }}'
        f'.sans {{ font-family: system-ui, -apple-system, "Segoe UI", sans-serif; }}'
        f'</style>'
        f'</defs>'
        f'<rect width="{w}" height="{h}" fill="{S900}"/>'
    )


def pill(x, y, verdict):
    color = ESC if verdict == "ESCALATE" else (REV if verdict == "REVIEW" else JUNK)
    label = verdict
    w = 82 if verdict == "ESCALATE" else (70 if verdict == "REVIEW" else 50)
    return (
        f'<rect x="{x}" y="{y-13}" width="{w}" height="20" rx="10" '
        f'fill="{color}22" stroke="{color}" stroke-width="1"/>'
        f'<text x="{x+w//2}" y="{y+1}" text-anchor="middle" '
        f'font-size="10" font-weight="700" fill="{color}" letter-spacing="0.8">'
        f'{label}</text>'
    )


def masthead(w):
    return (
        f'<rect x="0" y="0" width="{w}" height="58" fill="{S900}"/>'
        f'<line x1="0" y1="57" x2="{w}" y2="57" stroke="{LINE}" stroke-width="1"/>'
        f'<text x="32" y="36" font-size="22" font-weight="600" fill="{TEXT}" letter-spacing="-0.5">'
        f's<tspan fill="{ACCENT}">i</tspan>ft</text>'
        f'<text x="84" y="36" font-size="12" fill="{MUTED}" class="sans">transparent alert triage</text>'
        f'<text x="{w-160}" y="36" font-size="12" fill="{MUTED}">Dashboard</text>'
        f'<text x="{w-96}" y="36" font-size="12" fill="{MUTED}">Cases</text>'
        f'<text x="{w-40}" y="36" font-size="12" fill="{ACCENT}">admin</text>'
    )


# ── 1. DASHBOARD ────────────────────────────────────────────────────────────
def make_dashboard():
    W, H = 960, 640
    parts = [svg_header(W, H), masthead(W)]

    # summary chips row
    cy = 100
    chips = [
        ("14", "Total",     TEXT,  S850),
        ("5",  "Escalate",  ESC,   S850),
        ("6",  "Review",    REV,   S850),
        ("3",  "Junk",      JUNK,  S850),
    ]
    cx = 32
    for n, label, num_color, bg in chips:
        cw = 110
        parts.append(
            f'<rect x="{cx}" y="{cy-26}" width="{cw}" height="56" rx="8" '
            f'fill="{bg}" stroke="{LINE}" stroke-width="1"/>'
            f'<text x="{cx+14}" y="{cy+4}" font-size="20" font-weight="700" fill="{num_color}">{n}</text>'
            f'<text x="{cx+14}" y="{cy+18}" font-size="11" fill="{MUTED}" class="sans">{label}</text>'
        )
        cx += cw + 10

    # search bar
    parts.append(
        f'<rect x="{W-320}" y="{cy-26}" width="200" height="36" rx="8" '
        f'fill="{S850}" stroke="{LINE}" stroke-width="1"/>'
        f'<text x="{W-308}" y="{cy-2}" font-size="12" fill="{FAINT}">Search alerts…</text>'
        f'<rect x="{W-108}" y="{cy-26}" width="76" height="36" rx="8" '
        f'fill="{S850}" stroke="{LINE}" stroke-width="1"/>'
        f'<text x="{W-98}" y="{cy-2}" font-size="12" fill="{MUTED}">All ▾</text>'
    )

    # table wrapper
    ty = 160
    parts.append(
        f'<rect x="32" y="{ty}" width="{W-64}" height="{H-ty-40}" rx="10" '
        f'fill="{S900}" stroke="{LINE}" stroke-width="1"/>'
    )

    # table header
    parts.append(
        f'<rect x="32" y="{ty}" width="{W-64}" height="36" rx="10" fill="{S850}"/>'
        f'<rect x="32" y="{ty+18}" width="{W-64}" height="18" fill="{S850}"/>'
    )
    cols = [("", 50), ("Time", 130), ("Source", 80), ("Rule", 260), ("Score", 70), ("Verdict", 100), ("Target", 120), ("IP", 100)]
    hx = 48
    for label, cw in cols:
        parts.append(
            f'<text x="{hx}" y="{ty+23}" font-size="10" font-weight="700" '
            f'fill="{FAINT}" letter-spacing="0.7">{label.upper()}</text>'
        )
        hx += cw
    parts.append(f'<line x1="32" y1="{ty+36}" x2="{W-32}" y2="{ty+36}" stroke="{LINE}" stroke-width="1"/>')

    # table rows
    rows = [
        ("ESCALATE", "2m ago",  "wazuh",       "Credential dumping — LSASS access",    142, "dc01",      "45.146.165.37"),
        ("ESCALATE", "5m ago",  "crowdstrike",  "Malicious process — Cobalt Strike",    138, "workst-01", "—"),
        ("REVIEW",   "12m ago", "suricata",     "ET MALWARE Beacon C2 Activity",         81, "10.0.0.5",  "185.220.101.9"),
        ("REVIEW",   "18m ago", "wazuh",        "Multiple failed SSH logins (>10)",      74, "web-02",    "198.51.100.4"),
        ("REVIEW",   "31m ago", "elastic",      "Unusual process spawned from svchost",  68, "ws-07",     "—"),
        ("JUNK",     "44m ago", "wazuh",        "Successful sudo command",               22, "dev-03",    "—"),
        ("JUNK",     "1h ago",  "osquery",      "Network connection: process_network",   18, "web-01",    "8.8.8.8"),
        ("JUNK",     "2h ago",  "wazuh",        "Log rotation triggered",                 8, "log-01",    "—"),
    ]

    row_h = 52
    for i, (verdict, ts, src, rule, score, target, ip) in enumerate(rows):
        ry = ty + 37 + i * row_h
        vcolor = ESC if verdict == "ESCALATE" else (REV if verdict == "REVIEW" else JUNK)

        # hover bg for first row
        if i == 0:
            parts.append(f'<rect x="33" y="{ry}" width="{W-66}" height="{row_h}" fill="{S850}"/>')

        # left accent bar
        parts.append(f'<rect x="32" y="{ry}" width="3" height="{row_h}" fill="{vcolor}"/>')

        # checkbox
        parts.append(
            f'<rect x="52" y="{ry+17}" width="14" height="14" rx="3" '
            f'fill="{S900}" stroke="{LINE}" stroke-width="1"/>'
        )

        rx = 48
        # time
        rx += 50
        parts.append(f'<text x="{rx}" y="{ry+23}" font-size="12" fill="{MUTED}">{ts}</text>')
        # source
        rx += 130
        parts.append(f'<text x="{rx}" y="{ry+23}" font-size="12" fill="{ACCENT}">{src}</text>')
        # rule
        rx += 80
        display_rule = rule[:38] + "…" if len(rule) > 38 else rule
        parts.append(f'<text x="{rx}" y="{ry+23}" font-size="13" fill="{TEXT}">{display_rule}</text>')
        # score
        rx += 260
        parts.append(
            f'<text x="{rx+60}" y="{ry+23}" text-anchor="end" font-size="13" '
            f'font-weight="700" fill="{vcolor}">{score}</text>'
        )
        # verdict pill
        rx += 70
        parts.append(pill(rx, ry + 22, verdict))
        # target
        rx += 110
        parts.append(f'<text x="{rx}" y="{ry+23}" font-size="12" fill="{MUTED}">{target}</text>')

        if i < len(rows) - 1:
            parts.append(f'<line x1="32" y1="{ry+row_h}" x2="{W-32}" y2="{ry+row_h}" stroke="{S800}" stroke-width="1"/>')

    # bulk actions bar
    by = H - 52
    parts.append(
        f'<text x="48" y="{by+14}" font-size="12" fill="{MUTED}">3 selected —</text>'
        f'<rect x="148" y="{by}" width="110" height="28" rx="6" fill="{S850}" stroke="{LINE}" stroke-width="1"/>'
        f'<text x="158" y="{by+18}" font-size="12" fill="#f0a4a1">✓ True Positive</text>'
        f'<rect x="268" y="{by}" width="114" height="28" rx="6" fill="{S850}" stroke="{LINE}" stroke-width="1"/>'
        f'<text x="278" y="{by+18}" font-size="12" fill="#7ed3a3">✗ False Positive</text>'
        f'<rect x="392" y="{by}" width="84" height="28" rx="6" fill="{S850}" stroke="{LINE}" stroke-width="1"/>'
        f'<text x="402" y="{by+18}" font-size="12" fill="{ACCENT}">💤 Snooze</text>'
    )

    parts.append("</svg>")
    path = os.path.join(OUT, "dashboard.svg")
    with open(path, "w", encoding="utf-8") as f:
        f.write("".join(parts))
    print(f"  wrote {path}")


# ── 2. ALERT DETAIL ─────────────────────────────────────────────────────────
def make_alert_detail():
    W, H = 960, 720
    parts = [svg_header(W, H), masthead(W)]

    # back link + title
    parts.append(
        f'<text x="32" y="88" font-size="13" fill="{MUTED}">← Dashboard</text>'
        f'<text x="32" y="116" font-size="17" font-weight="600" fill="{TEXT}" class="sans">'
        f'Credential dumping — LSASS access</text>'
        f'<text x="32" y="134" font-size="12" fill="{MUTED}">Alert #7 · wazuh · dc01 · 2m ago</text>'
    )

    # ── LEFT PANEL: Facts ──────────────────────────────────────────────────
    lx, ly = 32, 154
    lw = 420
    lh = 340
    parts.append(
        f'<rect x="{lx}" y="{ly}" width="{lw}" height="{lh}" rx="10" '
        f'fill="{S850}" stroke="{LINE}" stroke-width="1"/>'
        f'<text x="{lx+18}" y="{ly+24}" font-size="10" font-weight="700" '
        f'fill="{FAINT}" letter-spacing="0.8">ALERT FACTS</text>'
    )
    facts = [
        ("Source",    "wazuh"),
        ("Rule ID",   "92052"),
        ("Level",     "12 / 15"),
        ("Timestamp", "2026-06-16 22:14:07 UTC"),
        ("Source IP", "45.146.165.37"),
        ("User",      "svc_backup"),
        ("Target",    "dc01 (10.0.0.9)"),
        ("File hash", "abc123def456…"),
        ("Location",  "WinEvtLog"),
    ]
    fy = ly + 46
    for key, val in facts:
        parts.append(
            f'<text x="{lx+18}" y="{fy}" font-size="11.5" fill="{FAINT}">{key}</text>'
            f'<text x="{lx+120}" y="{fy}" font-size="12.5" fill="{TEXT}">{val}</text>'
        )
        fy += 28

    # feedback buttons below facts
    fbx, fby = lx, ly + lh + 18
    parts.append(
        f'<text x="{fbx}" y="{fby+4}" font-size="10" font-weight="700" '
        f'fill="{FAINT}" letter-spacing="0.8">ANALYST FEEDBACK</text>'
        f'<rect x="{fbx}" y="{fby+12}" width="140" height="36" rx="8" '
        f'fill="{S850}" stroke="{ESC}" stroke-width="1"/>'
        f'<text x="{fbx+14}" y="{fby+34}" font-size="12" font-weight="600" fill="#f0a4a1">✓ True Positive</text>'
        f'<rect x="{fbx+152}" y="{fby+12}" width="144" height="36" rx="8" '
        f'fill="{S850}" stroke="{GREEN}" stroke-width="1"/>'
        f'<text x="{fbx+166}" y="{fby+34}" font-size="12" font-weight="600" fill="#7ed3a3">✗ False Positive</text>'
    )

    # snooze
    sbx, sby = lx, fby + 68
    parts.append(
        f'<text x="{sbx}" y="{sby+4}" font-size="10" font-weight="700" '
        f'fill="{FAINT}" letter-spacing="0.8">SNOOZE</text>'
        f'<rect x="{sbx}" y="{sby+12}" width="94" height="36" rx="8" '
        f'fill="{S850}" stroke="{LINE}" stroke-width="1"/>'
        f'<text x="{sbx+14}" y="{sby+34}" font-size="12" fill="{MUTED}">8 hours</text>'
        f'<rect x="{sbx+106}" y="{sby+12}" width="94" height="36" rx="8" '
        f'fill="{S850}" stroke="{LINE}" stroke-width="1"/>'
        f'<text x="{sbx+120}" y="{sby+34}" font-size="12" fill="{MUTED}">24 hours</text>'
        f'<rect x="{sbx+212}" y="{sby+12}" width="94" height="36" rx="8" '
        f'fill="{S850}" stroke="{LINE}" stroke-width="1"/>'
        f'<text x="{sbx+226}" y="{sby+34}" font-size="12" fill="{MUTED}">7 days</text>'
    )

    # ── RIGHT PANEL: Receipt ───────────────────────────────────────────────
    rx2 = lx + lw + 26
    ry2 = ly
    rw = W - rx2 - 32
    rh = 560

    parts.append(
        f'<rect x="{rx2}" y="{ry2}" width="{rw}" height="{rh}" rx="10" '
        f'fill="{PAPER}" stroke="{PAPER_LINE}" stroke-width="1" '
        f'filter="url(#shadow)"/>'
    )

    # receipt header
    rcy = ry2 + 30
    parts.append(
        f'<text x="{rx2+rw//2}" y="{rcy}" text-anchor="middle" font-size="14" '
        f'font-weight="700" fill="{PAPER_INK}">SIFT TRIAGE RECEIPT</text>'
        f'<text x="{rx2+rw//2}" y="{rcy+17}" text-anchor="middle" font-size="11" '
        f'fill="#7c8088">Alert #7 · wazuh · 2026-06-16</text>'
        f'<line x1="{rx2+20}" y1="{rcy+28}" x2="{rx2+rw-20}" y2="{rcy+28}" '
        f'stroke="{PAPER_LINE}" stroke-width="1" stroke-dasharray="5,3"/>'
    )

    # receipt line items
    items = [
        ("Severity lvl 12",       "+60", True),
        ("Critical asset: dc01",  "+30", True),
        ("Known bad IP",          "+35", True),
        ("Off-hours (22:14 UTC)", "+15", True),
        ("New src for svc_backup","+10", True),
        ("Rule noisy? No",         "+0", False),
        ("Allowlisted? No",        "+0", False),
    ]
    iy = rcy + 46
    for label, pts, positive in items:
        clr = ESC if (positive and pts != "+0") else ("#7c8088" if pts == "+0" else GREEN)
        parts.append(
            f'<text x="{rx2+20}" y="{iy}" font-size="12" font-weight="600" fill="{PAPER_INK}">{label}</text>'
            f'<line x1="{rx2+20+len(label)*7+4}" y1="{iy-3}" x2="{rx2+rw-60}" y2="{iy-3}" '
            f'stroke="{PAPER_LINE}" stroke-width="1" stroke-dasharray="1,3"/>'
            f'<text x="{rx2+rw-18}" y="{iy}" text-anchor="end" font-size="12" font-weight="700" fill="{clr}">{pts}</text>'
        )
        iy += 32

    # total line
    parts.append(
        f'<line x1="{rx2+20}" y1="{iy+4}" x2="{rx2+rw-20}" y2="{iy+4}" '
        f'stroke="{PAPER_INK}" stroke-width="2"/>'
        f'<text x="{rx2+20}" y="{iy+22}" font-size="15" font-weight="700" fill="{PAPER_INK}">TOTAL</text>'
        f'<text x="{rx2+rw-18}" y="{iy+22}" text-anchor="end" font-size="15" font-weight="700" fill="{PAPER_INK}">142</text>'
    )

    # ESCALATE stamp
    sx = rx2 + rw // 2
    sy = iy + 70
    parts.append(
        f'<g transform="rotate(-4.5,{sx},{sy})">'
        f'<rect x="{sx-60}" y="{sy-28}" width="120" height="52" rx="6" '
        f'fill="none" stroke="{ESC}" stroke-width="3"/>'
        f'<text x="{sx}" y="{sy+2}" text-anchor="middle" font-size="19" '
        f'font-weight="700" fill="{ESC}" letter-spacing="2">ESCALATE</text>'
        f'<text x="{sx}" y="{sy+18}" text-anchor="middle" font-size="9" '
        f'fill="#7c8088" letter-spacing="1">SCORE ≥ 100</text>'
        f'</g>'
    )

    parts.append("</svg>")
    path = os.path.join(OUT, "alert-detail.svg")
    with open(path, "w", encoding="utf-8") as f:
        f.write("".join(parts))
    print(f"  wrote {path}")


# ── 3. CASES ────────────────────────────────────────────────────────────────
def make_cases():
    W, H = 960, 580
    parts = [svg_header(W, H), masthead(W)]

    # page title
    parts.append(
        f'<text x="32" y="90" font-size="17" font-weight="600" fill="{TEXT}" class="sans">Cases</text>'
        f'<text x="32" y="108" font-size="12" fill="{MUTED}">Alerts grouped by rule × target — pivot to find patterns</text>'
    )

    # pivot selector
    parts.append(
        f'<text x="32" y="136" font-size="11" fill="{FAINT}">GROUP BY</text>'
        f'<rect x="96" y="120" width="100" height="28" rx="6" fill="{S850}" stroke="{ACCENT}" stroke-width="1"/>'
        f'<text x="108" y="138" font-size="12" fill="{TEXT}">rule_id ▾</text>'
        f'<rect x="206" y="120" width="100" height="28" rx="6" fill="{S850}" stroke="{LINE}" stroke-width="1"/>'
        f'<text x="218" y="138" font-size="12" fill="{MUTED}">target ▾</text>'
        f'<rect x="316" y="120" width="100" height="28" rx="6" fill="{S850}" stroke="{LINE}" stroke-width="1"/>'
        f'<text x="328" y="138" font-size="12" fill="{MUTED}">src_user ▾</text>'
    )

    # table
    ty = 160
    parts.append(
        f'<rect x="32" y="{ty}" width="{W-64}" height="{H-ty-32}" rx="10" '
        f'fill="{S900}" stroke="{LINE}" stroke-width="1"/>'
        f'<rect x="32" y="{ty}" width="{W-64}" height="36" rx="10" fill="{S850}"/>'
        f'<rect x="32" y="{ty+18}" width="{W-64}" height="18" fill="{S850}"/>'
    )

    hcols = [("Rule", 240), ("Alerts", 80), ("FP Rate", 90), ("Hosts Affected", 160), ("Worst Score", 110), ("Last Seen", 120), ("Verdict", 100)]
    hx = 48
    for label, cw in hcols:
        parts.append(f'<text x="{hx}" y="{ty+23}" font-size="10" font-weight="700" fill="{FAINT}" letter-spacing="0.7">{label.upper()}</text>')
        hx += cw
    parts.append(f'<line x1="32" y1="{ty+36}" x2="{W-32}" y2="{ty+36}" stroke="{LINE}" stroke-width="1"/>')

    cases = [
        ("92052 · Credential dumping",    "5", "0%",  "dc01, ws-03, srv-01…",  142, "2m ago",  "ESCALATE"),
        ("2024897 · Cobalt Strike Beacon", "3", "0%",  "10.0.0.5, 10.0.0.8",   138, "5m ago",  "ESCALATE"),
        ("5763 · Brute-force SSH",         "8", "12%", "web-01, web-02, dev-01",  81, "18m ago", "REVIEW"),
        ("5501 · Sudo command",            "4", "75%", "dev-01, dev-02",           22, "44m ago", "JUNK"),
        ("554 · File modified (syscheck)", "2", "50%", "prod-db",                  18, "1h ago",  "JUNK"),
    ]

    row_h = 50
    for i, (rule, count, fp, hosts, score, ts, verdict) in enumerate(cases):
        ry = ty + 37 + i * row_h
        vcolor = ESC if verdict == "ESCALATE" else (REV if verdict == "REVIEW" else JUNK)

        if i == 0:
            parts.append(f'<rect x="33" y="{ry}" width="{W-66}" height="{row_h}" fill="{S850}"/>')
        parts.append(f'<rect x="32" y="{ry}" width="3" height="{row_h}" fill="{vcolor}"/>')

        cx2 = 48
        # rule
        parts.append(f'<text x="{cx2}" y="{ry+21}" font-size="12.5" fill="{TEXT}">{rule}</text>')
        cx2 += 240
        # count
        parts.append(f'<text x="{cx2+40}" y="{ry+21}" text-anchor="end" font-size="13" font-weight="700" fill="{TEXT}">{count}</text>')
        cx2 += 80
        # fp rate
        fp_color = GREEN if fp == "0%" else (REV if int(fp[:-1]) < 50 else JUNK)
        parts.append(f'<text x="{cx2}" y="{ry+21}" font-size="12" fill="{fp_color}">{fp}</text>')
        cx2 += 90
        # hosts
        display_hosts = hosts[:22] + "…" if len(hosts) > 22 else hosts
        parts.append(f'<text x="{cx2}" y="{ry+21}" font-size="12" fill="{MUTED}">{display_hosts}</text>')
        cx2 += 160
        # score
        parts.append(f'<text x="{cx2+80}" y="{ry+21}" text-anchor="end" font-size="13" font-weight="700" fill="{vcolor}">{score}</text>')
        cx2 += 110
        # last seen
        parts.append(f'<text x="{cx2}" y="{ry+21}" font-size="12" fill="{MUTED}">{ts}</text>')
        cx2 += 120
        # verdict pill
        parts.append(pill(cx2, ry + 20, verdict))

        if i < len(cases) - 1:
            parts.append(f'<line x1="32" y1="{ry+row_h}" x2="{W-32}" y2="{ry+row_h}" stroke="{S800}" stroke-width="1"/>')

    parts.append("</svg>")
    path = os.path.join(OUT, "cases.svg")
    with open(path, "w", encoding="utf-8") as f:
        f.write("".join(parts))
    print(f"  wrote {path}")


if __name__ == "__main__":
    make_dashboard()
    make_alert_detail()
    make_cases()
    print("Done.")
