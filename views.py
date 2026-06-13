"""
The web views — a triage queue and a per-alert receipt.

The look is deliberately an audit ledger, not a hacker console: light "paper"
cards on cool slate, a monospace ledger for the figures, and the verdict
rendered as a stamped receipt. That's the product's whole argument made
visual — every decision shows its itemised reasoning and a running total, so
the tool earns trust instead of asking for it. No web fonts or CDNs, so it
renders identically on an air-gapped analyst workstation.
"""

import html
import json
import datetime as dt
import urllib.parse

import config


CSS = """
:root {
  --slate-900:#191f26; --slate-850:#1f262e; --slate-800:#252e38;
  --slate-700:#303b47; --line:#374350;
  --text:#e7ebf0; --muted:#94a0ad; --faint:#6c7884;
  --paper:#f6f4ec; --paper-ink:#23282d; --paper-line:#d8d2c2;
  --escalate:#d64541; --review:#d99a2b; --junk:#7f8b98;
  --accent:#46a3a0;
  --mono:ui-monospace,"SF Mono",SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;
  --sans:system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
}
* { box-sizing:border-box; }
body {
  margin:0; background:var(--slate-900); color:var(--text);
  font-family:var(--sans); line-height:1.5;
  -webkit-font-smoothing:antialiased;
}
a { color:inherit; text-decoration:none; }
.wrap { max-width:1040px; margin:0 auto; padding:32px 20px 80px; }

/* header */
.masthead { display:flex; align-items:baseline; gap:14px; flex-wrap:wrap;
  border-bottom:1px solid var(--line); padding-bottom:18px; margin-bottom:26px; }
.wordmark { font-family:var(--mono); font-size:26px; font-weight:600;
  letter-spacing:-0.5px; color:var(--text); }
.wordmark b { color:var(--accent); font-weight:600; }
.tagline { font-size:13px; color:var(--muted); letter-spacing:0.2px; }
.back { font-family:var(--mono); font-size:13px; color:var(--muted); }
.back:hover { color:var(--accent); }

/* summary chips */
.toolbar { display:flex; justify-content:space-between; align-items:flex-start;
  flex-wrap:wrap; gap:14px; margin-bottom:22px; }
.chips { display:flex; gap:10px; flex-wrap:wrap; }
.chip { display:flex; align-items:baseline; gap:8px; padding:10px 14px;
  background:var(--slate-850); border:1px solid var(--line); border-radius:8px;
  font-size:13px; color:var(--muted); }
.chip:hover { border-color:var(--slate-700); }
.chip .n { font-family:var(--mono); font-size:18px; font-weight:600; color:var(--text); }
.chip.active { border-color:var(--accent); }
.chip.escalate .n { color:var(--escalate); }
.chip.review .n { color:var(--review); }
.chip.junk .n { color:var(--junk); }
.chip.snoozed .n { color:var(--accent); }

/* search */
.search { display:flex; gap:8px; align-items:center; }
.search input[type=search], .search select { font-family:var(--mono); font-size:13px;
  padding:9px 12px; border-radius:8px; border:1px solid var(--line);
  background:var(--slate-850); color:var(--text); }
.search input[type=search] { min-width:220px; }
.search input[type=search]::placeholder { color:var(--faint); }
.search input[type=search]:focus, .search select:focus { outline:2px solid var(--accent); outline-offset:-1px; }
.search .clear { font-family:var(--mono); font-size:12px; color:var(--muted); white-space:nowrap; }
.search .clear:hover { color:var(--accent); }

/* table */
.table-wrap { overflow-x:auto; border:1px solid var(--line); border-radius:10px; }
table { width:100%; border-collapse:collapse; font-size:14px; }
thead th { text-align:left; font-size:11px; text-transform:uppercase;
  letter-spacing:0.7px; color:var(--faint); font-weight:600;
  padding:12px 14px; background:var(--slate-850); border-bottom:1px solid var(--line); }
tbody tr { border-bottom:1px solid var(--slate-800); border-left:3px solid transparent; }
tbody tr:last-child { border-bottom:none; }
tbody tr:hover { background:var(--slate-850); }
tbody tr.v-escalate { border-left-color:var(--escalate); }
tbody tr.v-review   { border-left-color:var(--review); }
tbody tr.v-junk     { border-left-color:var(--junk); }
td { padding:12px 14px; vertical-align:top; }
th.check, td.check { width:32px; padding-right:0; text-align:center; }
input[type=checkbox] { width:15px; height:15px; accent-color:var(--accent); cursor:pointer; }

/* bulk actions */
.bulk-actions { display:flex; align-items:center; gap:10px; flex-wrap:wrap;
  margin-top:14px; }
.bulk-actions .bulk-label { font-size:13px; color:var(--muted); }
td.mono, .mono { font-family:var(--mono); }
.rule-desc { color:var(--muted); font-size:12.5px; margin-top:2px; max-width:340px; }
.num { text-align:right; font-family:var(--mono); font-weight:600; font-variant-numeric:tabular-nums; }
.time { color:var(--muted); white-space:nowrap; }

/* verdict pill */
.pill { display:inline-block; font-family:var(--mono); font-size:11px;
  font-weight:600; letter-spacing:0.6px; text-transform:uppercase;
  padding:3px 9px; border-radius:999px; border:1px solid; white-space:nowrap; }
.pill.v-escalate { color:var(--escalate); border-color:var(--escalate); background:rgba(214,69,65,.08); }
.pill.v-review   { color:var(--review);   border-color:var(--review);   background:rgba(217,154,43,.08); }
.pill.v-junk     { color:var(--junk);     border-color:var(--junk);     background:rgba(127,139,152,.08); }

.empty { padding:60px 24px; text-align:center; color:var(--muted); }
.empty code { font-family:var(--mono); color:var(--accent);
  background:var(--slate-850); padding:2px 7px; border-radius:5px; }

/* detail layout */
.detail { display:grid; grid-template-columns:1fr 1.1fr; gap:26px; align-items:start; }
@media (max-width:760px) { .detail { grid-template-columns:1fr; } }
.panel-label { font-size:11px; text-transform:uppercase; letter-spacing:0.8px;
  color:var(--faint); font-weight:600; margin:0 0 12px; }

/* facts */
.facts { background:var(--slate-850); border:1px solid var(--line);
  border-radius:10px; padding:18px 20px; }
.facts dl { margin:0; display:grid; grid-template-columns:auto 1fr; gap:9px 16px; }
.facts dt { color:var(--faint); font-size:12px; padding-top:2px; }
.facts dd { margin:0; font-family:var(--mono); font-size:13.5px; word-break:break-word; }

/* the receipt — the signature element */
.receipt { background:var(--paper); color:var(--paper-ink); border-radius:10px;
  padding:26px 26px 30px; font-family:var(--mono);
  box-shadow:0 1px 0 rgba(0,0,0,.25), 0 14px 40px rgba(0,0,0,.28); }
.receipt-head { text-align:center; border-bottom:2px dashed var(--paper-line);
  padding-bottom:14px; margin-bottom:16px; }
.receipt-head .h { font-weight:600; font-size:15px; letter-spacing:0.3px; }
.receipt-head .sub { color:#7c8088; font-size:11.5px; margin-top:3px; }
.li { display:flex; align-items:baseline; gap:8px; padding:7px 0; }
.li .label { flex:0 0 auto; font-weight:600; }
.li .leader { flex:1 1 auto; border-bottom:1px dotted var(--paper-line); transform:translateY(-3px); }
.li .pts { flex:0 0 auto; font-weight:600; font-variant-numeric:tabular-nums; }
.li .pts.pos { color:var(--escalate); }
.li .pts.neg { color:#2f7d52; }
.li .detail { flex-basis:100%; color:#6b6f77; font-size:11.5px; padding-left:2px; margin-top:-2px; }
.total { display:flex; justify-content:space-between; align-items:baseline;
  border-top:2px solid var(--paper-ink); margin-top:14px; padding-top:12px;
  font-weight:700; font-size:16px; }
.total .pts { font-variant-numeric:tabular-nums; }
.stamp-row { text-align:center; margin-top:22px; }
.stamp { display:inline-block; font-weight:700; letter-spacing:2px;
  text-transform:uppercase; font-size:18px; padding:8px 18px;
  border:3px double currentColor; border-radius:6px; transform:rotate(-4.5deg);
  opacity:.92; }
.stamp.v-escalate { color:var(--escalate); }
.stamp.v-review   { color:#b9821f; }
.stamp.v-junk     { color:var(--junk); }
.stamp .why { display:block; font-size:9.5px; letter-spacing:1px; font-weight:600;
  margin-top:4px; color:#6b6f77; }

/* feedback */
.feedback { margin-top:24px; }
.feedback form { display:flex; gap:12px; flex-wrap:wrap; }
.btn { font-family:var(--mono); font-size:13px; font-weight:600; cursor:pointer;
  padding:11px 16px; border-radius:8px; border:1px solid var(--line);
  background:var(--slate-850); color:var(--text); }
.btn:hover { border-color:var(--slate-700); }
.btn.tp { border-color:var(--escalate); color:#f0a4a1; }
.btn.fp { border-color:#2f7d52; color:#7ed3a3; }
.decided { font-family:var(--mono); font-size:13px; color:var(--muted);
  background:var(--slate-850); border:1px solid var(--line);
  border-radius:8px; padding:12px 16px; }
.decided b.tp { color:#f0a4a1; } .decided b.fp { color:#7ed3a3; }

/* snooze */
.snooze { margin-top:24px; }
.snooze form { display:flex; gap:12px; flex-wrap:wrap; }
.snooze .decided { margin-bottom:12px; }

details.raw { margin-top:26px; }
details.raw summary { cursor:pointer; color:var(--muted); font-family:var(--mono);
  font-size:13px; }
details.raw pre { background:var(--slate-850); border:1px solid var(--line);
  border-radius:8px; padding:16px; overflow:auto; font-size:12.5px;
  color:var(--muted); max-height:420px; }

a:focus-visible, .btn:focus-visible, summary:focus-visible {
  outline:2px solid var(--accent); outline-offset:2px; }
@media (prefers-reduced-motion:reduce) { * { transition:none !important; } }
@media (max-width:560px) { .wrap { padding:22px 14px 60px; } .rule-desc { max-width:200px; } }
"""

VERDICT_CLASS = {"ESCALATE": "v-escalate", "REVIEW": "v-review", "JUNK": "v-junk"}
VERDICT_WHY = {
    "ESCALATE": "look now",
    "REVIEW": "needs a human",
    "JUNK": "auto-closed",
}


def _esc(value):
    return html.escape("" if value is None else str(value))


def _fmt_time(iso):
    try:
        return dt.datetime.fromisoformat(iso).strftime("%b %d, %H:%M")
    except Exception:
        return iso or "—"


def _qs(**params):
    """Build a /?key=value query string from truthy params only."""
    pairs = [(k, str(v)) for k, v in params.items() if v]
    return "/?" + urllib.parse.urlencode(pairs) if pairs else "/"


def page(title, body):
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        "<title>" + _esc(title) + "</title><style>" + CSS + "</style></head>"
        "<body><div class=\"wrap\">" + body + "</div></body></html>"
    )


def _masthead(show_back=False):
    right = (
        '<a class="back" href="/">&larr; back to queue</a>' if show_back else
        '<span class="tagline">transparent alert triage</span>'
    )
    return (
        '<div class="masthead"><span class="wordmark">si<b>ft</b>.</span>'
        + right + "</div>"
    )


AGE_OPTIONS = [
    ("", "Any age"),
    ("1", "Older than 1h"),
    ("24", "Older than 24h"),
    ("168", "Older than 7d"),
]


def render_dashboard(alerts, counts, active_filter, q=None, snoozed=False, age=None, snoozed_n=0):
    chips = []
    chip_defs = [
        (None, "all", sum(counts.values()), ""),
        ("ESCALATE", "escalate", counts["ESCALATE"], "escalate"),
        ("REVIEW", "review", counts["REVIEW"], "review"),
        ("JUNK", "junk", counts["JUNK"], "junk"),
    ]
    for value, label, n, cls in chip_defs:
        href = _qs(verdict=value)
        active = " active" if (not snoozed and active_filter == value) else ""
        chips.append(
            f'<a class="chip {cls}{active}" href="{href}">'
            f'<span class="n">{n}</span> {label}</a>'
        )
    chips.append(
        f'<a class="chip snoozed{" active" if snoozed else ""}" href="{_qs(snoozed="1")}">'
        f'<span class="n">{snoozed_n}</span> snoozed</a>'
    )

    age_str = str(age) if age else ""
    clear_href = _qs(verdict=active_filter, snoozed="1" if snoozed else None)
    hidden = ""
    if active_filter:
        hidden += f'<input type="hidden" name="verdict" value="{_esc(active_filter)}">'
    if snoozed:
        hidden += '<input type="hidden" name="snoozed" value="1">'
    age_select = "<select name=\"age\">" + "".join(
        f'<option value="{v}"{" selected" if v == age_str else ""}>{_esc(label)}</option>'
        for v, label in AGE_OPTIONS
    ) + "</select>"
    search = (
        '<form class="search" method="get" action="/">'
        + hidden
        + '<input type="search" name="q" placeholder="filter by rule, target, IP, user…"'
        + f' value="{_esc(q or "")}">'
        + age_select
        + '<button class="btn" type="submit">Filter</button>'
        + (f'<a class="clear" href="{clear_href}">clear</a>' if (q or age) else "")
        + "</form>"
    )

    if alerts:
        rows = []
        for a in alerts:
            vc = VERDICT_CLASS.get(a["verdict"], "")
            desc = _esc(a["rule_desc"] or "")
            rows.append(
                f'<tr class="{vc}" onclick="location.href=\'/alert/{a["id"]}\'" style="cursor:pointer">'
                f'<td class="check" onclick="event.stopPropagation()">'
                f'<input type="checkbox" name="ids" value="{a["id"]}"></td>'
                f'<td class="time">{_fmt_time(a["received_at"])}</td>'
                f'<td><span class="mono">{_esc(a["rule_id"] or "—")}</span>'
                f'<div class="rule-desc">{desc}</div></td>'
                f'<td class="mono">{_esc(a["target"] or "—")}</td>'
                f'<td class="mono">{_esc(a["src_ip"] or "—")}</td>'
                f'<td class="num">{a["score"]}</td>'
                f'<td><span class="pill {vc}">{_esc(a["verdict"])}</span></td>'
                f"</tr>"
            )
        bulk_hidden = ""
        if active_filter:
            bulk_hidden += f'<input type="hidden" name="verdict" value="{_esc(active_filter)}">'
        if q:
            bulk_hidden += f'<input type="hidden" name="q" value="{_esc(q)}">'
        if snoozed:
            bulk_hidden += '<input type="hidden" name="snoozed" value="1">'
        if age:
            bulk_hidden += f'<input type="hidden" name="age" value="{_esc(age)}">'
        table = (
            '<form class="bulk-form" method="post" action="/bulk-feedback">'
            + bulk_hidden
            + '<div class="table-wrap"><table><thead><tr>'
            '<th class="check"><input type="checkbox" id="select-all" title="select all"></th>'
            "<th>Time</th><th>Rule</th><th>Target</th><th>Source IP</th>"
            "<th style=\"text-align:right\">Score</th><th>Verdict</th>"
            "</tr></thead><tbody>" + "".join(rows) + "</tbody></table></div>"
            '<div class="bulk-actions"><span class="bulk-label">With selected:</span>'
            '<button class="btn tp" type="submit" name="analyst_verdict" value="true_positive">Real threat</button>'
            '<button class="btn fp" type="submit" name="analyst_verdict" value="false_positive">False alarm</button>'
            "</div>"
            "<script>"
            "document.getElementById('select-all').addEventListener('change',function(e){"
            "document.querySelectorAll('input[name=\"ids\"]').forEach(function(c){c.checked=e.target.checked;});"
            "});"
            "</script>"
            "</form>"
        )
    elif snoozed:
        msg = "No snoozed alerts match this filter." if (q or age) else "Nothing snoozed right now."
        table = (
            '<div class="table-wrap"><div class="empty">' + msg + "<br><br>"
            "Alerts you snooze from their detail page reappear here until they wake up."
            "</div></div>"
        )
    elif q or active_filter or age:
        table = (
            '<div class="table-wrap"><div class="empty">No alerts match this filter.<br><br>'
            f'Try <a href="{clear_href}">clearing the search</a>'
            + (f' or the <code>{_esc(active_filter)}</code> filter' if active_filter else "")
            + "</div></div>"
        )
    else:
        table = (
            '<div class="table-wrap"><div class="empty">No alerts yet.<br><br>'
            "Point Wazuh at <code>POST /webhook/wazuh</code>, or try<br>"
            "<code>python3 send_sample.py sample_alerts/real_attack.json</code>"
            "</div></div>"
        )

    toolbar = '<div class="toolbar"><div class="chips">' + "".join(chips) + "</div>" + search + "</div>"
    body = _masthead() + toolbar + table
    return page("sift — triage queue", body)


def _receipt_html(alert):
    receipt = json.loads(alert["receipt_json"])
    lines = []
    for item in receipt:
        pts = item["points"]
        sign = "+" if pts >= 0 else "-"
        cls = "pos" if pts >= 0 else "neg"
        lines.append(
            '<div class="li">'
            f'<span class="label">{_esc(item["label"])}</span>'
            '<span class="leader"></span>'
            f'<span class="pts {cls}">{sign}{abs(pts)}</span>'
            f'<span class="detail">{_esc(item["detail"])}</span>'
            "</div>"
        )
    if not lines:
        lines.append('<div class="li"><span class="label">No signals fired</span>'
                     '<span class="leader"></span><span class="pts">0</span></div>')

    score = alert["score"]
    total_sign = "+" if score >= 0 else "-"
    vc = VERDICT_CLASS.get(alert["verdict"], "")
    why = VERDICT_WHY.get(alert["verdict"], "")
    return (
        '<div class="receipt">'
        '<div class="receipt-head"><div class="h">Why this verdict</div>'
        f'<div class="sub">alert #{alert["id"]} &middot; scored on arrival</div></div>'
        + "".join(lines)
        + f'<div class="total"><span>TOTAL</span><span class="pts">{total_sign}{abs(score)}</span></div>'
        + f'<div class="stamp-row"><span class="stamp {vc}">{_esc(alert["verdict"])}'
          f'<span class="why">{why}</span></span></div>'
        + "</div>"
    )


def _facts_html(alert):
    fields = [
        ("Rule", alert["rule_id"]),
        ("Description", alert["rule_desc"]),
        ("Level", alert["rule_level"]),
        ("Target", alert["target"]),
        ("Source IP", alert["src_ip"]),
        ("Source user", alert["src_user"]),
        ("File hash", alert["file_hash"]),
        ("Received", _fmt_time(alert["received_at"])),
    ]
    rows = "".join(
        f"<dt>{_esc(k)}</dt><dd>{_esc(v) if v not in (None, '') else '—'}</dd>"
        for k, v in fields
    )
    return '<div class="facts"><dl>' + rows + "</dl></div>"


def _feedback_html(alert):
    if alert["analyst_verdict"] == "true_positive":
        return ('<div class="feedback"><div class="decided">Marked '
                '<b class="tp">real threat</b> &middot; the rule\'s track record was updated.'
                "</div></div>")
    if alert["analyst_verdict"] == "false_positive":
        return ('<div class="feedback"><div class="decided">Marked '
                '<b class="fp">false alarm</b> &middot; this rule will be trusted less next time.'
                "</div></div>")
    aid = alert["id"]
    return (
        '<div class="feedback"><p class="panel-label">Your call teaches sift</p>'
        f'<form method="post" action="/alert/{aid}/feedback">'
        '<button class="btn tp" name="verdict" value="true_positive">Confirm real threat</button>'
        '<button class="btn fp" name="verdict" value="false_positive">Mark false alarm</button>'
        "</form></div>"
    )


def _snooze_html(alert):
    aid = alert["id"]
    snoozed_until = alert.get("snoozed_until")
    active = False
    if snoozed_until:
        try:
            active = dt.datetime.fromisoformat(snoozed_until) > dt.datetime.now()
        except ValueError:
            active = False
    if active:
        return (
            '<div class="snooze">'
            f'<div class="decided">Snoozed until <b>{_esc(_fmt_time(snoozed_until))}</b>'
            " &mdash; hidden from the queue until then.</div>"
            f'<form method="post" action="/alert/{aid}/unsnooze">'
            '<button class="btn" type="submit">Wake now</button>'
            "</form></div>"
        )
    return (
        '<div class="snooze"><p class="panel-label">Snooze</p>'
        f'<form method="post" action="/alert/{aid}/snooze">'
        '<button class="btn" name="hours" value="1">1h</button>'
        '<button class="btn" name="hours" value="4">4h</button>'
        '<button class="btn" name="hours" value="24">24h</button>'
        '<button class="btn" name="hours" value="168">7d</button>'
        "</form></div>"
    )


def render_detail(alert):
    raw_pretty = json.dumps(json.loads(alert["raw_json"]), indent=2)
    left = (
        '<div><p class="panel-label">Alert</p>' + _facts_html(alert)
        + _feedback_html(alert)
        + _snooze_html(alert)
        + '<details class="raw"><summary>Raw alert JSON</summary><pre>'
        + _esc(raw_pretty) + "</pre></details></div>"
    )
    right = '<div><p class="panel-label">Receipt</p>' + _receipt_html(alert) + "</div>"
    body = _masthead(show_back=True) + '<div class="detail">' + left + right + "</div>"
    return page(f"sift — alert #{alert['id']}", body)
