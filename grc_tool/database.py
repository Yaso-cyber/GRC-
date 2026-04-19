"""
Database layer for the GRC Tool.
Uses SQLite3 (standard library) for all data persistence.
"""

import sqlite3
import os
import json
from datetime import datetime
from pathlib import Path


DEFAULT_DB_PATH = os.path.expanduser("~/.grc_tool/grc.db")


def get_db_path() -> str:
    """Return the configured database path, creating the directory if needed."""
    db_path = os.environ.get("GRC_DB_PATH", DEFAULT_DB_PATH)
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    return db_path


class Database:
    """SQLite database manager for the GRC Tool."""

    def __init__(self, db_path: str | None = None):
        self.db_path = db_path or get_db_path()
        self._conn: sqlite3.Connection | None = None

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def connect(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA foreign_keys = ON")
            self._conn.execute("PRAGMA journal_mode = WAL")
        return self._conn

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *_):
        self.close()

    # ------------------------------------------------------------------
    # Schema initialisation
    # ------------------------------------------------------------------

    def initialize(self):
        """Create all tables if they do not exist."""
        conn = self.connect()
        with conn:
            conn.executescript("""
                -- ── Risks ──────────────────────────────────────────────────────
                CREATE TABLE IF NOT EXISTS risks (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    title           TEXT    NOT NULL,
                    description     TEXT,
                    category        TEXT    NOT NULL DEFAULT 'Operational',
                    likelihood      INTEGER NOT NULL DEFAULT 3 CHECK (likelihood BETWEEN 1 AND 5),
                    impact          INTEGER NOT NULL DEFAULT 3 CHECK (impact     BETWEEN 1 AND 5),
                    risk_score      INTEGER GENERATED ALWAYS AS (likelihood * impact) STORED,
                    risk_level      TEXT    NOT NULL DEFAULT 'Medium',
                    owner           TEXT,
                    status          TEXT    NOT NULL DEFAULT 'Open'
                                        CHECK (status IN ('Open','In Progress','Mitigated','Accepted','Closed')),
                    treatment       TEXT    NOT NULL DEFAULT 'Mitigate'
                                        CHECK (treatment IN ('Mitigate','Accept','Transfer','Avoid')),
                    due_date        TEXT,
                    tags            TEXT    DEFAULT '[]',
                    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
                    updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
                );

                -- ── Controls ───────────────────────────────────────────────────
                CREATE TABLE IF NOT EXISTS controls (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    control_id      TEXT    NOT NULL UNIQUE,
                    framework       TEXT    NOT NULL,
                    domain          TEXT    NOT NULL,
                    title           TEXT    NOT NULL,
                    description     TEXT,
                    guidance        TEXT,
                    implementation  TEXT,
                    status          TEXT    NOT NULL DEFAULT 'Not Implemented'
                                        CHECK (status IN ('Not Implemented','Planned','Partially Implemented',
                                                          'Implemented','Not Applicable')),
                    evidence        TEXT,
                    owner           TEXT,
                    last_reviewed   TEXT,
                    tags            TEXT    DEFAULT '[]',
                    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
                    updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
                );

                -- ── Risk ↔ Control mapping ────────────────────────────────────
                CREATE TABLE IF NOT EXISTS risk_controls (
                    risk_id         INTEGER NOT NULL REFERENCES risks(id)    ON DELETE CASCADE,
                    control_id      INTEGER NOT NULL REFERENCES controls(id) ON DELETE CASCADE,
                    PRIMARY KEY (risk_id, control_id)
                );

                -- ── Compliance Assessments ─────────────────────────────────────
                CREATE TABLE IF NOT EXISTS assessments (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    name            TEXT    NOT NULL,
                    framework       TEXT    NOT NULL,
                    scope           TEXT,
                    assessor        TEXT,
                    status          TEXT    NOT NULL DEFAULT 'Draft'
                                        CHECK (status IN ('Draft','In Progress','Completed','Archived')),
                    score           REAL,
                    findings        TEXT    DEFAULT '[]',
                    recommendations TEXT    DEFAULT '[]',
                    start_date      TEXT,
                    end_date        TEXT,
                    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
                    updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
                );

                -- ── Policies ───────────────────────────────────────────────────
                CREATE TABLE IF NOT EXISTS policies (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    title           TEXT    NOT NULL,
                    policy_id       TEXT    NOT NULL UNIQUE,
                    version         TEXT    NOT NULL DEFAULT '1.0',
                    category        TEXT    NOT NULL,
                    content         TEXT,
                    owner           TEXT,
                    approver        TEXT,
                    status          TEXT    NOT NULL DEFAULT 'Draft'
                                        CHECK (status IN ('Draft','Under Review','Approved','Deprecated')),
                    effective_date  TEXT,
                    review_date     TEXT,
                    tags            TEXT    DEFAULT '[]',
                    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
                    updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
                );

                -- ── Audit Log ──────────────────────────────────────────────────
                CREATE TABLE IF NOT EXISTS audit_log (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp       TEXT    NOT NULL DEFAULT (datetime('now')),
                    actor           TEXT    NOT NULL DEFAULT 'system',
                    action          TEXT    NOT NULL,
                    entity_type     TEXT    NOT NULL,
                    entity_id       TEXT,
                    details         TEXT    DEFAULT '{}'
                );

                -- ── Indexes ────────────────────────────────────────────────────
                CREATE INDEX IF NOT EXISTS idx_risks_status    ON risks(status);
                CREATE INDEX IF NOT EXISTS idx_risks_level     ON risks(risk_level);
                CREATE INDEX IF NOT EXISTS idx_controls_fw     ON controls(framework);
                CREATE INDEX IF NOT EXISTS idx_controls_status ON controls(status);
                CREATE INDEX IF NOT EXISTS idx_assessments_fw  ON assessments(framework);
                CREATE INDEX IF NOT EXISTS idx_audit_entity    ON audit_log(entity_type, entity_id);
            """)

    # ------------------------------------------------------------------
    # Generic helpers
    # ------------------------------------------------------------------

    def execute(self, sql: str, params=()) -> sqlite3.Cursor:
        return self.connect().execute(sql, params)

    def executemany(self, sql: str, params_seq) -> sqlite3.Cursor:
        return self.connect().executemany(sql, params_seq)

    def commit(self):
        if self._conn:
            self._conn.commit()

    def fetchall(self, sql: str, params=()) -> list[sqlite3.Row]:
        return self.execute(sql, params).fetchall()

    def fetchone(self, sql: str, params=()) -> sqlite3.Row | None:
        return self.execute(sql, params).fetchone()

    def log_action(self, action: str, entity_type: str,
                   entity_id: str | None = None,
                   details: dict | None = None,
                   actor: str = "system"):
        """Write a record to the audit_log table."""
        self.execute(
            """INSERT INTO audit_log (actor, action, entity_type, entity_id, details)
               VALUES (?, ?, ?, ?, ?)""",
            (actor, action, entity_type, str(entity_id) if entity_id else None,
             json.dumps(details or {}))
        )
        self.commit()
