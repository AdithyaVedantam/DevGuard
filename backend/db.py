"""SQLite database using plain SQL (Python's built-in sqlite3 - nothing to install).
The file devguard.db is created automatically in the project folder on first start.

projects      one row per project
scans         one row per scan (a snapshot with summary numbers)
dependencies  every package found in a scan
findings      "package X in scan Y has vulnerability Z"
"""
import os
import sqlite3
from contextlib import closing
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    source_type TEXT NOT NULL,            -- upload | github | demo
    repo_url TEXT,
    branch TEXT,
    manifest_text TEXT,                   -- the package.json text (data only)
    lock_text TEXT,                       -- the package-lock.json text
    created_at TEXT NOT NULL,
    UNIQUE (name, source_type)
);
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    status TEXT NOT NULL,                 -- running | completed | partial | failed
    mode TEXT NOT NULL DEFAULT 'lockfile',-- lockfile | manifest-ranges
    created_at TEXT NOT NULL,
    total_dependencies INTEGER DEFAULT 0,
    direct_count INTEGER DEFAULT 0,
    transitive_count INTEGER DEFAULT 0,
    vulnerable_dependencies INTEGER DEFAULT 0,
    total_findings INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    unknown_count INTEGER DEFAULT 0,
    fixable_findings INTEGER DEFAULT 0,
    lookups_failed INTEGER DEFAULT 0,
    risk_index INTEGER DEFAULT 0,
    risk_level TEXT DEFAULT 'none',
    warnings TEXT DEFAULT '[]',           -- JSON list
    errors TEXT DEFAULT '[]'              -- JSON list
);
CREATE TABLE IF NOT EXISTS dependencies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    dep_type TEXT NOT NULL,               -- direct | transitive
    env TEXT NOT NULL,                    -- production | development
    depth INTEGER,
    path TEXT DEFAULT '[]',               -- JSON list: ["my-app","express","qs"]
    lookup_ok INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    dependency_id INTEGER NOT NULL REFERENCES dependencies(id) ON DELETE CASCADE,
    osv_id TEXT NOT NULL,
    summary TEXT, details TEXT,
    severity TEXT NOT NULL,               -- critical | high | medium | low | unknown
    cvss REAL, cvss_vector TEXT,
    fixed_version TEXT,
    affected_ranges TEXT DEFAULT '[]',    -- JSON list of readable ranges, e.g. "from 0 until 1.2.6"
    risk REAL DEFAULT 0,
    refs TEXT DEFAULT '[]', aliases TEXT DEFAULT '[]',
    published TEXT, modified TEXT
);
CREATE INDEX IF NOT EXISTS ix_scans_project ON scans(project_id);
CREATE INDEX IF NOT EXISTS ix_deps_scan ON dependencies(scan_id);
CREATE INDEX IF NOT EXISTS ix_findings_scan ON findings(scan_id, severity);
CREATE INDEX IF NOT EXISTS ix_findings_dep ON findings(dependency_id);
"""


def db_path():
    return os.environ.get("DEVGUARD_DB") or str(Path(__file__).resolve().parent.parent / "devguard.db")


def get_conn():
    conn = sqlite3.connect(db_path())
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    with closing(get_conn()) as conn:
        conn.executescript(SCHEMA)
        conn.commit()


def query(sql, params=(), one=False):
    """Run a SELECT. Returns a list of dicts (or one dict / None when one=True)."""
    with closing(get_conn()) as conn:
        rows = [dict(r) for r in conn.execute(sql, params)]
    return (rows[0] if rows else None) if one else rows


def execute(sql, params=()):
    """Run an INSERT/UPDATE/DELETE and return the new row id."""
    with closing(get_conn()) as conn:
        cur = conn.execute(sql, params)
        conn.commit()
        return cur.lastrowid
