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

import json
import sqlite3
import datetime as dt

import config


def connect():
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    with connect() as conn:
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


def _now():
    return dt.datetime.now().isoformat(timespec="seconds")


# --- alerts ---------------------------------------------------------------

def insert_alert(alert, score, verdict, receipt):
    with connect() as conn:
        cur = conn.execute(
            """
            INSERT INTO alerts (received_at, rule_id, rule_desc, rule_level,
                                src_ip, src_user, target, file_hash,
                                score, verdict, receipt_json, raw_json)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                _now(),
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
    with connect() as conn:
        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        return dict(row) if row else None


def list_alerts(verdict_filter=None, q=None, snoozed=False, min_age_hours=None, limit=200):
    query = "SELECT * FROM alerts"
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
    query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    with connect() as conn:
        return [dict(r) for r in conn.execute(query, params).fetchall()]


def verdict_counts():
    """Counts for the chips — excludes alerts currently snoozed out of the queue."""
    now = _now()
    with connect() as conn:
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
    with connect() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM alerts WHERE snoozed_until IS NOT NULL AND snoozed_until > ?",
            (now,),
        ).fetchone()
    return row["n"]


def snooze_alert(alert_id, until_iso):
    with connect() as conn:
        cur = conn.execute(
            "UPDATE alerts SET snoozed_until = ? WHERE id = ?", (until_iso, alert_id)
        )
        return cur.rowcount > 0


def unsnooze_alert(alert_id):
    with connect() as conn:
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
    with connect() as conn:
        row = conn.execute(
            """
            SELECT COUNT(*) AS n FROM alerts
            WHERE rule_id = ? AND src_ip = ? AND received_at >= ?
            """,
            (rule_id, src_ip, cutoff),
        ).fetchone()
    return row["n"]


def user_source_history(src_user, src_ip):
    """
    How many prior alerts mention this user, and has this user + source IP
    combination been seen before? Used by the "unfamiliar source" signal.
    """
    if not src_user:
        return {"total": 0, "seen_this_ip": False}
    with connect() as conn:
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

def record_feedback(alert_id, analyst_verdict):
    """
    Save the analyst's call ('true_positive' or 'false_positive') and update
    the rule's running track record. Re-deciding an alert adjusts the tally
    correctly instead of double-counting.
    """
    assert analyst_verdict in ("true_positive", "false_positive")
    with connect() as conn:
        row = conn.execute(
            "SELECT rule_id, analyst_verdict FROM alerts WHERE id = ?", (alert_id,)
        ).fetchone()
        if row is None:
            return False
        rule_id = row["rule_id"]
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
            # Undo the previous decision's contribution, if any.
            if previous == "true_positive":
                conn.execute(
                    "UPDATE rule_stats SET total = total - 1 WHERE rule_id = ?",
                    (rule_id,),
                )
            elif previous == "false_positive":
                conn.execute(
                    "UPDATE rule_stats SET total = total - 1, fp = fp - 1 WHERE rule_id = ?",
                    (rule_id,),
                )
            # Apply the new decision.
            if analyst_verdict == "true_positive":
                conn.execute(
                    "UPDATE rule_stats SET total = total + 1 WHERE rule_id = ?",
                    (rule_id,),
                )
            else:
                conn.execute(
                    "UPDATE rule_stats SET total = total + 1, fp = fp + 1 WHERE rule_id = ?",
                    (rule_id,),
                )
    return True


def get_rule_stats(rule_id):
    if not rule_id:
        return None
    with connect() as conn:
        row = conn.execute(
            "SELECT total, fp FROM rule_stats WHERE rule_id = ?", (rule_id,)
        ).fetchone()
    return dict(row) if row else None


# --- enrichment cache -----------------------------------------------------

def cache_get(key):
    with connect() as conn:
        row = conn.execute(
            "SELECT value_json FROM enrich_cache WHERE cache_key = ?", (key,)
        ).fetchone()
    return json.loads(row["value_json"]) if row else None


def cache_set(key, value):
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO enrich_cache (cache_key, value_json, cached_at)
            VALUES (?,?,?)
            ON CONFLICT(cache_key) DO UPDATE SET value_json = excluded.value_json,
                                                 cached_at  = excluded.cached_at
            """,
            (key, json.dumps(value), _now()),
        )
