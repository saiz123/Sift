"""
Storage for sift — a single SQLite file, standard library only.

Three tables:
  alerts        every alert we've scored, with its receipt and (later) the
                analyst's verdict.
  rule_stats    per-rule tally of how often a rule turned out to be a real
                threat vs a false alarm. This is what lets sift get smarter.
  enrich_cache  cached AbuseIPDB / VirusTotal lookups so we don't re-query the
                same IP or hash and burn through rate limits.
"""

import contextlib
import json
import sqlite3
import datetime as dt

import config


def connect():
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


@contextlib.contextmanager
def _db():
    """Open a connection, manage the transaction, and guarantee close."""
    conn = connect()
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def init_db():
    with _db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                received_at     TEXT NOT NULL,
                rule_id         TEXT,
                rule_desc       TEXT,
                rule_level      INTEGER,
                src_ip          TEXT,
                src_user        TEXT,
                target          TEXT,
                file_hash       TEXT,
                score           INTEGER NOT NULL,
                verdict         TEXT NOT NULL,
                receipt_json    TEXT NOT NULL,
                raw_json        TEXT NOT NULL,
                analyst_verdict TEXT,
                decided_at      TEXT
            );

            CREATE TABLE IF NOT EXISTS rule_stats (
                rule_id   TEXT PRIMARY KEY,
                total     INTEGER NOT NULL DEFAULT 0,
                fp        INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS rule_target_stats (
                rule_id   TEXT NOT NULL,
                target    TEXT NOT NULL,
                total     INTEGER NOT NULL DEFAULT 0,
                fp        INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (rule_id, target)
            );

            CREATE TABLE IF NOT EXISTS enrich_cache (
                cache_key TEXT PRIMARY KEY,
                value_json TEXT NOT NULL,
                cached_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_alerts_received ON alerts(received_at);
            CREATE INDEX IF NOT EXISTS idx_alerts_dedup    ON alerts(rule_id, src_ip);
            """
        )
        cols = {row["name"] for row in conn.execute("PRAGMA table_info(alerts)").fetchall()}
        if "snoozed_until" not in cols:
            conn.execute("ALTER TABLE alerts ADD COLUMN snoozed_until TEXT")
        if "source" not in cols:
            conn.execute("ALTER TABLE alerts ADD COLUMN source TEXT")


def _now():
    return dt.datetime.now().isoformat(timespec="seconds")


# --- alerts ---------------------------------------------------------------

def insert_alert(alert, score, verdict, receipt):
    with _db() as conn:
        cur = conn.execute(
            """
            INSERT INTO alerts (received_at, source, rule_id, rule_desc, rule_level,
                                src_ip, src_user, target, file_hash,
                                score, verdict, receipt_json, raw_json)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                _now(),
                alert.get("source"),
                alert.get("rule_id"),
                alert.get("rule_desc"),
                alert.get("rule_level"),
                alert.get("src_ip"),
                alert.get("src_user"),
                alert.get("target"),
                alert.get("file_hash"),
                score,
                verdict,
                json.dumps(receipt),
                json.dumps(alert.get("raw", {})),
            ),
        )
        return cur.lastrowid


def get_alert(alert_id):
    with _db() as conn:
        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        return dict(row) if row else None


def _alert_filters(verdict_filter, q, snoozed, min_age_hours):
    """WHERE clauses + params shared by list_alerts and list_alert_ids."""
    clauses = []
    params = []
    now = _now()
    if snoozed:
        clauses.append("snoozed_until IS NOT NULL AND snoozed_until > ?")
        params.append(now)
    else:
        clauses.append("(snoozed_until IS NULL OR snoozed_until <= ?)")
        params.append(now)
    if verdict_filter:
        clauses.append("verdict = ?")
        params.append(verdict_filter)
    if q:
        clauses.append(
            "(rule_id LIKE ? OR rule_desc LIKE ? OR target LIKE ?"
            " OR src_ip LIKE ? OR src_user LIKE ?)"
        )
        like = f"%{q}%"
        params.extend([like] * 5)
    if min_age_hours is not None:
        cutoff = (dt.datetime.now() - dt.timedelta(hours=min_age_hours)).isoformat(timespec="seconds")
        clauses.append("received_at <= ?")
        params.append(cutoff)
    return clauses, params


def list_alerts(verdict_filter=None, q=None, snoozed=False, min_age_hours=None, limit=200):
    clauses, params = _alert_filters(verdict_filter, q, snoozed, min_age_hours)
    query = "SELECT * FROM alerts WHERE " + " AND ".join(clauses) + " ORDER BY id DESC LIMIT ?"
    with _db() as conn:
        return [dict(r) for r in conn.execute(query, params + [limit]).fetchall()]


def list_alert_ids(verdict_filter=None, q=None, snoozed=False, min_age_hours=None, limit=200):
    """Ordered alert ids for the same filter as list_alerts — used for prev/next navigation."""
    clauses, params = _alert_filters(verdict_filter, q, snoozed, min_age_hours)
    query = "SELECT id FROM alerts WHERE " + " AND ".join(clauses) + " ORDER BY id DESC LIMIT ?"
    with _db() as conn:
        return [r["id"] for r in conn.execute(query, params + [limit]).fetchall()]


def verdict_counts():
    """Counts for the chips — excludes alerts currently snoozed out of the queue."""
    now = _now()
    with _db() as conn:
        rows = conn.execute(
            "SELECT verdict, COUNT(*) AS n FROM alerts"
            " WHERE snoozed_until IS NULL OR snoozed_until <= ?"
            " GROUP BY verdict",
            (now,),
        ).fetchall()
    counts = {"ESCALATE": 0, "REVIEW": 0, "JUNK": 0}
    for r in rows:
        counts[r["verdict"]] = r["n"]
    return counts


# --- snooze -----------------------------------------------------------------

def snoozed_count():
    now = _now()
    with _db() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM alerts WHERE snoozed_until IS NOT NULL AND snoozed_until > ?",
            (now,),
        ).fetchone()
    return row["n"]


def snooze_alert(alert_id, until_iso):
    with _db() as conn:
        cur = conn.execute(
            "UPDATE alerts SET snoozed_until = ? WHERE id = ?", (until_iso, alert_id)
        )
        return cur.rowcount > 0


def unsnooze_alert(alert_id):
    with _db() as conn:
        cur = conn.execute(
            "UPDATE alerts SET snoozed_until = NULL WHERE id = ?", (alert_id,)
        )
        return cur.rowcount > 0


def count_recent_duplicates(rule_id, src_ip, window_hours):
    """How many prior alerts share this rule + source within the window."""
    if not rule_id or not src_ip:
        return 0
    cutoff = (
        dt.datetime.now() - dt.timedelta(hours=window_hours)
    ).isoformat(timespec="seconds")
    with _db() as conn:
        row = conn.execute(
            """
            SELECT COUNT(*) AS n FROM alerts
            WHERE rule_id = ? AND src_ip = ? AND received_at >= ?
            """,
            (rule_id, src_ip, cutoff),
        ).fetchone()
    return row["n"]


def recent_distinct_source_ips(src_user, window_hours):
    """
    Distinct source IPs this user has alerted from within the last
    window_hours — feeds the velocity (impossible-travel) signal.
    """
    if not src_user:
        return set()
    cutoff = (
        dt.datetime.now() - dt.timedelta(hours=window_hours)
    ).isoformat(timespec="seconds")
    with _db() as conn:
        rows = conn.execute(
            """
            SELECT DISTINCT src_ip FROM alerts
            WHERE src_user = ? AND received_at >= ? AND src_ip IS NOT NULL
            """,
            (src_user, cutoff),
        ).fetchall()
    return {r["src_ip"] for r in rows}


def user_source_history(src_user, src_ip):
    """
    How many prior alerts mention this user, and has this user + source IP
    combination been seen before? Used by the "unfamiliar source" signal.
    """
    if not src_user:
        return {"total": 0, "seen_this_ip": False}
    with _db() as conn:
        total = conn.execute(
            "SELECT COUNT(*) AS n FROM alerts WHERE src_user = ?", (src_user,)
        ).fetchone()["n"]
        seen_this_ip = False
        if src_ip:
            seen_this_ip = conn.execute(
                "SELECT COUNT(*) AS n FROM alerts WHERE src_user = ? AND src_ip = ?",
                (src_user, src_ip),
            ).fetchone()["n"] > 0
    return {"total": total, "seen_this_ip": seen_this_ip}


# --- the learning loop ----------------------------------------------------

def _adjust_stats(conn, table, where_sql, where_params, previous, analyst_verdict):
    """
    Undo the previous decision's contribution to (total, fp), if any, then
    apply the new one. Shared by the global and per-asset rule track records.
    """
    if previous == "true_positive":
        conn.execute(f"UPDATE {table} SET total = total - 1 WHERE {where_sql}", where_params)
    elif previous == "false_positive":
        conn.execute(f"UPDATE {table} SET total = total - 1, fp = fp - 1 WHERE {where_sql}", where_params)

    if analyst_verdict == "true_positive":
        conn.execute(f"UPDATE {table} SET total = total + 1 WHERE {where_sql}", where_params)
    else:
        conn.execute(f"UPDATE {table} SET total = total + 1, fp = fp + 1 WHERE {where_sql}", where_params)


def record_feedback(alert_id, analyst_verdict):
    """
    Save the analyst's call ('true_positive' or 'false_positive') and update
    the rule's running track record, both globally and for this rule on this
    asset. Re-deciding an alert adjusts the tally correctly instead of
    double-counting.
    """
    if analyst_verdict not in ("true_positive", "false_positive"):
        raise ValueError(f"analyst_verdict must be 'true_positive' or 'false_positive', got {analyst_verdict!r}")

    # BEGIN IMMEDIATE so the read-then-write on rule_stats can't race with
    # another concurrent feedback submission — writers wait (busy_timeout)
    # rather than failing with SQLITE_BUSY.
    with contextlib.closing(connect()) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute(
                "SELECT rule_id, target, analyst_verdict FROM alerts WHERE id = ?", (alert_id,)
            ).fetchone()
            if row is None:
                conn.rollback()
                return False
            rule_id = row["rule_id"]
            target = row["target"]
            previous = row["analyst_verdict"]

            conn.execute(
                "UPDATE alerts SET analyst_verdict = ?, decided_at = ? WHERE id = ?",
                (analyst_verdict, _now(), alert_id),
            )

            if rule_id:
                conn.execute(
                    "INSERT OR IGNORE INTO rule_stats (rule_id, total, fp) VALUES (?,0,0)",
                    (rule_id,),
                )
                _adjust_stats(conn, "rule_stats", "rule_id = ?", (rule_id,), previous, analyst_verdict)

                if target:
                    conn.execute(
                        "INSERT OR IGNORE INTO rule_target_stats (rule_id, target, total, fp) VALUES (?,?,0,0)",
                        (rule_id, target),
                    )
                    _adjust_stats(
                        conn, "rule_target_stats", "rule_id = ? AND target = ?",
                        (rule_id, target), previous, analyst_verdict,
                    )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    return True


def get_rule_stats(rule_id):
    if not rule_id:
        return None
    with _db() as conn:
        row = conn.execute(
            "SELECT total, fp FROM rule_stats WHERE rule_id = ?", (rule_id,)
        ).fetchone()
    return dict(row) if row else None


def get_rule_target_stats(rule_id, target):
    """Per-asset track record for this rule — feeds per-asset noisy-rule tuning."""
    if not rule_id or not target:
        return None
    with _db() as conn:
        row = conn.execute(
            "SELECT total, fp FROM rule_target_stats WHERE rule_id = ? AND target = ?",
            (rule_id, target),
        ).fetchone()
    return dict(row) if row else None


def rule_activity_stats(rule_id, window_hours):
    """
    How many times this rule has fired recently vs. over its whole lifetime —
    feeds the rule-drift signal (a normally-quiet rule suddenly firing a lot).
    """
    if not rule_id:
        return None
    cutoff = (
        dt.datetime.now() - dt.timedelta(hours=window_hours)
    ).isoformat(timespec="seconds")
    with _db() as conn:
        row = conn.execute(
            """
            SELECT COUNT(*) AS total, MIN(received_at) AS first_seen,
                   SUM(CASE WHEN received_at >= ? THEN 1 ELSE 0 END) AS recent
            FROM alerts WHERE rule_id = ?
            """,
            (cutoff, rule_id),
        ).fetchone()
    if row["total"] == 0:
        return None
    return {"total": row["total"], "first_seen": row["first_seen"], "recent": row["recent"]}


# --- case correlation ------------------------------------------------------

_VERDICT_RANK = {"ESCALATE": 0, "REVIEW": 1, "JUNK": 2}
_RANK_VERDICT = {v: k for k, v in _VERDICT_RANK.items()}
_VERDICT_RANK_SQL = "CASE verdict WHEN 'ESCALATE' THEN 0 WHEN 'REVIEW' THEN 1 ELSE 2 END"

_CASE_DIMENSIONS = (("user", "src_user"), ("ip", "src_ip"), ("target", "target"))


def list_cases(window_hours, min_alerts):
    """
    Group alerts that share a src_user, src_ip, or target within the last
    window_hours into "cases" — bursts of related activity worth triaging
    together. Returns a list of dicts: {dimension, value, count, latest,
    rollup_verdict, escalate_n, review_n, junk_n}, most severe and most
    recent first.
    """
    cutoff = (dt.datetime.now() - dt.timedelta(hours=window_hours)).isoformat(timespec="seconds")
    cases = []
    with _db() as conn:
        for dimension, column in _CASE_DIMENSIONS:
            rows = conn.execute(
                f"""
                SELECT {column} AS value, COUNT(*) AS count, MAX(received_at) AS latest,
                       MIN({_VERDICT_RANK_SQL}) AS rank,
                       SUM(verdict = 'ESCALATE') AS escalate_n,
                       SUM(verdict = 'REVIEW') AS review_n,
                       SUM(verdict = 'JUNK') AS junk_n
                FROM alerts
                WHERE {column} IS NOT NULL AND {column} != '' AND received_at >= ?
                GROUP BY {column}
                HAVING COUNT(*) >= ?
                """,
                (cutoff, min_alerts),
            ).fetchall()
            for row in rows:
                cases.append({
                    "dimension": dimension,
                    "value": row["value"],
                    "count": row["count"],
                    "latest": row["latest"],
                    "rollup_verdict": _RANK_VERDICT[row["rank"]],
                    "escalate_n": row["escalate_n"],
                    "review_n": row["review_n"],
                    "junk_n": row["junk_n"],
                })
    cases.sort(key=lambda c: c["latest"], reverse=True)
    cases.sort(key=lambda c: _VERDICT_RANK[c["rollup_verdict"]])
    return cases


def list_case_alerts(dimension, value, window_hours):
    """
    All alerts for one (dimension, value) case within window_hours, newest
    first. dimension is one of "user"/"ip"/"target", mapping to
    src_user/src_ip/target. Snoozed and already-decided alerts are included
    intentionally — a case is the recent history of related activity, not
    just the open queue.
    """
    column = {"user": "src_user", "ip": "src_ip", "target": "target"}.get(dimension)
    if column is None:
        return []
    cutoff = (dt.datetime.now() - dt.timedelta(hours=window_hours)).isoformat(timespec="seconds")
    with _db() as conn:
        rows = conn.execute(
            f"SELECT * FROM alerts WHERE {column} = ? AND received_at >= ? ORDER BY id DESC",
            (value, cutoff),
        ).fetchall()
    return [dict(r) for r in rows]


# --- enrichment cache -----------------------------------------------------

def cache_get(key, max_age_hours=None):
    with _db() as conn:
        if max_age_hours is not None:
            cutoff = (dt.datetime.now() - dt.timedelta(hours=max_age_hours)).isoformat(timespec="seconds")
            row = conn.execute(
                "SELECT value_json FROM enrich_cache WHERE cache_key = ? AND cached_at >= ?",
                (key, cutoff),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT value_json FROM enrich_cache WHERE cache_key = ?", (key,)
            ).fetchone()
    return json.loads(row["value_json"]) if row else None


def update_alert_score(alert_id, score, verdict, receipt):
    """Update score/verdict/receipt after background enrichment re-scores the alert."""
    with _db() as conn:
        conn.execute(
            "UPDATE alerts SET score = ?, verdict = ?, receipt_json = ? WHERE id = ?",
            (score, verdict, json.dumps(receipt), alert_id),
        )


def cache_set(key, value):
    with _db() as conn:
        conn.execute(
            """
            INSERT INTO enrich_cache (cache_key, value_json, cached_at)
            VALUES (?,?,?)
            ON CONFLICT(cache_key) DO UPDATE SET value_json = excluded.value_json,
                                                 cached_at  = excluded.cached_at
            """,
            (key, json.dumps(value), _now()),
        )
