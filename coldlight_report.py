#!/usr/bin/env python3
"""
Reporting layer for the ColdLight awareness-test framework.

SQLite-backed storage with de-duplication (by run_id), a safe-list "excluded"
flag, metric computation, CSV export, retention purging, and ingest of the local
JSONL logs the payload writes -- so you can get numbers from collected USB sticks
even without running the collector server.

Pure stdlib (sqlite3, csv, json). Used by the CLI (`coldlight report` / `coldlight
purge`) and the collector.
"""

from __future__ import annotations

import csv
import json
import sqlite3
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

HIT_FIELDS = [
    "run_id", "engagement_id", "timestamp_utc", "received_utc",
    "hostname", "username", "os", "ran_from",
]
EXPORT_FIELDS = HIT_FIELDS + ["excluded", "vector"]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS hits (
    run_id         TEXT PRIMARY KEY,
    engagement_id  TEXT,
    timestamp_utc  TEXT,
    received_utc   TEXT,
    hostname       TEXT,
    username       TEXT,
    os             TEXT,
    ran_from       TEXT,
    excluded       INTEGER NOT NULL DEFAULT 0,
    vector         TEXT NOT NULL DEFAULT 'usb'
);
"""


def connect(db_path: str | Path) -> sqlite3.Connection:
    """Open the DB (creating/migrating the schema). check_same_thread=False so a
    threaded server can share one connection behind its own lock."""
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.execute(_SCHEMA)
    # Migrate older DBs that predate the `excluded` column.
    cols = {r[1] for r in conn.execute("PRAGMA table_info(hits)")}
    if "excluded" not in cols:
        conn.execute("ALTER TABLE hits ADD COLUMN excluded INTEGER NOT NULL DEFAULT 0")
    if "vector" not in cols:
        conn.execute("ALTER TABLE hits ADD COLUMN vector TEXT NOT NULL DEFAULT 'usb'")
    conn.commit()
    return conn


def _clip(value, limit: int = 256) -> str:
    """Coerce to a bounded string -- never trust record contents blindly."""
    if value is None:
        return ""
    return str(value)[:limit]


def insert_hit(conn: sqlite3.Connection, record: dict, excluded: bool = False,
               vector: str = "usb") -> bool:
    """Insert one hit, de-duplicated by run_id. Returns True if it was new."""
    run_id = _clip(record.get("run_id"), 64)
    if not run_id:
        return False
    cur = conn.execute(
        "INSERT OR IGNORE INTO hits "
        "(run_id, engagement_id, timestamp_utc, received_utc, hostname, "
        " username, os, ran_from, excluded, vector) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (
            run_id,
            _clip(record.get("engagement_id")),
            _clip(record.get("timestamp_utc"), 64),
            _clip(record.get("received_utc"), 64),
            _clip(record.get("hostname")),
            _clip(record.get("username")),
            _clip(record.get("os")),
            _clip(record.get("ran_from"), 512),
            1 if excluded else 0,
            _clip(vector, 16) or "usb",
        ),
    )
    conn.commit()
    return cur.rowcount > 0


def ingest_jsonl(conn: sqlite3.Connection, path: str | Path) -> tuple[int, int]:
    """Load a payload JSONL log into the DB. Returns (new_rows, lines_seen)."""
    new = seen = 0
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue
        seen += 1
        rec.setdefault("received_utc", rec.get("timestamp_utc", ""))
        if insert_hit(conn, rec):
            new += 1
    return new, seen


def _rows(conn: sqlite3.Connection) -> list[dict]:
    cols = ", ".join(EXPORT_FIELDS)
    # `cols` is the EXPORT_FIELDS constant (fixed column names), never user
    # input; SQLite cannot parameterise identifiers.
    rows = conn.execute(f"SELECT {cols} FROM hits")  # nosec
    return [dict(zip(EXPORT_FIELDS, r)) for r in rows]


def all_hits(conn: sqlite3.Connection) -> list[dict]:
    """Every stored hit, as dicts. Used by exports and the purple-team layer."""
    return _rows(conn)


def compute_stats(conn: sqlite3.Connection) -> dict:
    """Aggregate metrics. Safe-listed (excluded) hits are reported separately and
    left out of the headline counts."""
    all_rows = _rows(conn)
    rows = [r for r in all_rows if not r["excluded"]]
    excluded_runs = len(all_rows) - len(rows)

    hosts = {r["hostname"] for r in rows if r["hostname"]}
    users = {r["username"] for r in rows if r["username"]}
    by_vector = Counter((r["vector"] or "usb") for r in rows)

    by_day: Counter[str] = Counter()
    per_eng: dict[str, dict] = {}
    for r in rows:
        ts = r["timestamp_utc"] or r["received_utc"] or ""
        eng = r["engagement_id"] or "(none)"
        slot = per_eng.setdefault(
            eng, {"count": 0, "hosts": set(), "first": None, "last": None}
        )
        slot["count"] += 1
        if r["hostname"]:
            slot["hosts"].add(r["hostname"])
        if ts:
            by_day[ts[:10]] += 1
            if slot["first"] is None or ts < slot["first"]:
                slot["first"] = ts
            if slot["last"] is None or ts > slot["last"]:
                slot["last"] = ts

    per_eng_out = {
        k: {
            "count": v["count"],
            "unique_hosts": len(v["hosts"]),
            "first_run": v["first"],
            "last_run": v["last"],
        }
        for k, v in sorted(per_eng.items())
    }
    return {
        "total_runs": len(rows),
        "unique_hosts": len(hosts),
        "unique_users": len(users),
        "excluded_runs": excluded_runs,
        "by_vector": dict(by_vector),
        "by_day": dict(sorted(by_day.items())),
        "per_engagement": per_eng_out,
    }


def export_csv(conn: sqlite3.Connection, path: str | Path) -> int:
    """Write every hit (including the excluded flag) to CSV. Returns row count."""
    rows = _rows(conn)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=EXPORT_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def purge(conn: sqlite3.Connection, *, older_than_days: int | None = None,
          before: str | None = None, engagement: str | None = None,
          dry_run: bool = False) -> int:
    """Delete hits matching a retention criterion. Returns the count removed (or,
    with dry_run, the count that *would* be removed). Requires >=1 criterion."""
    clauses: list[str] = []
    params: list[str] = []
    if older_than_days is not None:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=older_than_days)).isoformat()
        clauses.append("received_utc < ?")
        params.append(cutoff)
    if before:
        clauses.append("received_utc < ?")
        params.append(before)
    if engagement:
        clauses.append("engagement_id = ?")
        params.append(engagement)
    if not clauses:
        raise ValueError("purge requires at least one criterion")

    # `where` is built only from the fixed clause literals above; every
    # caller-supplied value is bound through `params`, never interpolated.
    where = " AND ".join(clauses)
    count = conn.execute(f"SELECT COUNT(*) FROM hits WHERE {where}", params).fetchone()[0]  # nosec
    if not dry_run:
        conn.execute(f"DELETE FROM hits WHERE {where}", params)  # nosec
        conn.commit()
    return count


def text_summary(stats: dict) -> str:
    lines = [
        "ColdLight awareness-test report",
        "=" * 40,
        f"Total runs    : {stats['total_runs']}",
        f"Unique hosts  : {stats['unique_hosts']}",
        f"Unique users  : {stats['unique_users']}",
        f"Excluded      : {stats.get('excluded_runs', 0)} (safe-listed)",
        "",
        "Per engagement:",
    ]
    if not stats["per_engagement"]:
        lines.append("  (no data yet)")
    for eng, s in stats["per_engagement"].items():
        lines.append(
            f"  - {eng}: {s['count']} runs, {s['unique_hosts']} hosts, "
            f"first {s['first_run']}, last {s['last_run']}"
        )
    if stats["by_day"]:
        lines += ["", "Runs by day:"]
        peak = max(stats["by_day"].values())
        for day, n in stats["by_day"].items():
            bar = "#" * max(1, round(20 * n / peak))
            lines.append(f"  {day}  {bar} {n}")
    return "\n".join(lines)
