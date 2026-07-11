"""
db.py — SQLite storage for the scam-site detector.

Doubles as (a) a growing catalogue of checked/known scam sites, and (b) a short-term
cache so repeat checks of the same domain are instant and don't re-hammer the target.
Stdlib sqlite3 only — no extra dependency.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

DB_PATH = Path(__file__).with_name("scans.db")
_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    domain          TEXT NOT NULL,
    url             TEXT NOT NULL,
    scanned_at      TEXT NOT NULL,     -- ISO-8601 UTC
    score           INTEGER NOT NULL,
    level           TEXT NOT NULL,
    registered      TEXT,
    expires         TEXT,
    age_days        INTEGER,
    host_org        TEXT,
    host_country    TEXT,
    summary         TEXT,
    result_json     TEXT NOT NULL      -- full analyze.quick_scan() dict
);
CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain);
CREATE INDEX IF NOT EXISTS idx_scans_scanned_at ON scans(scanned_at);
"""


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with _lock, _connect() as conn:
        conn.executescript(SCHEMA)


def save_scan(result: Dict) -> int:
    """Persist an analyze.quick_scan() result. Returns the new row id."""
    a = result.get("assessment", {})
    f = a.get("facts", {})
    with _lock, _connect() as conn:
        cur = conn.execute(
            """INSERT INTO scans
               (domain, url, scanned_at, score, level, registered, expires,
                age_days, host_org, host_country, summary, result_json)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                result.get("domain") or "",
                result.get("url") or "",
                result.get("scanned_at") or datetime.now(timezone.utc).isoformat(),
                int(a.get("score", 0)),
                a.get("level", "Low"),
                f.get("registered"),
                f.get("expires"),
                f.get("age_days"),
                f.get("host_org"),
                f.get("host_country"),
                a.get("summary"),
                json.dumps(result, ensure_ascii=False),
            ),
        )
        return cur.lastrowid


def get_cached(domain: str, max_age_seconds: int = 1800) -> Optional[Dict]:
    """Return the most recent stored result for a domain if it is still fresh."""
    with _lock, _connect() as conn:
        row = conn.execute(
            "SELECT * FROM scans WHERE domain = ? ORDER BY id DESC LIMIT 1",
            (domain,),
        ).fetchone()
    if not row:
        return None
    scanned = row["scanned_at"]
    try:
        dt = datetime.fromisoformat(scanned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - dt).total_seconds()
    except ValueError:
        return None
    if age > max_age_seconds:
        return None
    data = json.loads(row["result_json"])
    data["_cached"] = True
    data["_row_id"] = row["id"]
    return data


def get_latest_for_domain(domain: str) -> Optional[Dict]:
    """Most recent stored result for a domain regardless of age (for /site/<domain>)."""
    with _lock, _connect() as conn:
        row = conn.execute(
            "SELECT * FROM scans WHERE domain = ? ORDER BY id DESC LIMIT 1",
            (domain,),
        ).fetchone()
    if not row:
        return None
    data = json.loads(row["result_json"])
    data["_row_id"] = row["id"]
    return data


def recent_scans(limit: int = 20) -> List[Dict]:
    """Distinct domains, most recently checked first (for the catalogue / homepage)."""
    with _lock, _connect() as conn:
        rows = conn.execute(
            """SELECT domain, url, scanned_at, score, level, registered, expires,
                      host_country, summary
               FROM scans
               WHERE id IN (SELECT MAX(id) FROM scans GROUP BY domain)
               ORDER BY id DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def high_risk_scans(limit: int = 50) -> List[Dict]:
    """Highest-risk distinct domains (for the 'known scams' view)."""
    with _lock, _connect() as conn:
        rows = conn.execute(
            """SELECT domain, url, scanned_at, score, level, registered, expires,
                      host_country, summary
               FROM scans
               WHERE id IN (SELECT MAX(id) FROM scans GROUP BY domain)
               ORDER BY score DESC, id DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]
