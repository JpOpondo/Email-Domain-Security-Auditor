"""
logger.py
Local SQLite logging for the Email Domain Security Auditor.
CNS 3104 | John Paul Opondo (193309)

Tables:
  Audit_Session    — one row per domain audit session
  Protocol_Record  — one row per protocol (SPF/DKIM/DMARC/MX) per session
"""

import json
import sqlite3
import time
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "audit_log.db"


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    with _connect() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS Audit_Session (
                session_id         INTEGER PRIMARY KEY AUTOINCREMENT,
                target_domain       TEXT    NOT NULL,
                timestamp           INTEGER NOT NULL,
                overall_risk_score  TEXT    NOT NULL,
                report_json         TEXT
            );

            CREATE TABLE IF NOT EXISTS Protocol_Record (
                record_id            INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id            INTEGER NOT NULL
                                      REFERENCES Audit_Session(session_id)
                                      ON DELETE CASCADE,
                protocol_type         TEXT    NOT NULL,
                raw_dns_value         TEXT,
                risk_rating           TEXT    NOT NULL,
                remediation_guidance  TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_session_domain    ON Audit_Session(target_domain);
            CREATE INDEX IF NOT EXISTS idx_session_timestamp ON Audit_Session(timestamp);
        """)


def log_audit(report: dict) -> int:
    init_db()

    target_domain      = report["domain"]
    overall_risk_score = report["overall_risk"]
    timestamp           = int(time.time())

    with _connect() as conn:
        cur = conn.execute(
            """
            INSERT INTO Audit_Session (target_domain, timestamp, overall_risk_score, report_json)
            VALUES (?, ?, ?, ?)
            """,
            (target_domain, timestamp, overall_risk_score, json.dumps(report)),
        )
        session_id = cur.lastrowid

        for protocol in ("spf", "dkim", "dmarc", "mx"):
            rec = report.get(protocol, {})

            raw_dns_value = rec.get("record")
            if raw_dns_value is None and protocol == "dkim":
                for sel_data in rec.get("selectors", {}).values():
                    if sel_data.get("record"):
                        raw_dns_value = sel_data["record"]
                        break

            conn.execute(
                """
                INSERT INTO Protocol_Record
                    (session_id, protocol_type, raw_dns_value, risk_rating, remediation_guidance)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    protocol.upper(),
                    raw_dns_value,
                    rec.get("risk", "Unknown"),
                    json.dumps(rec.get("remediation", [])),
                ),
            )

    return session_id


def get_recent_audits(limit: int = 20) -> list[dict]:
    init_db()
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT session_id, target_domain, timestamp, overall_risk_score
            FROM   Audit_Session
            ORDER  BY timestamp DESC
            LIMIT  ?
            """,
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_audit_by_id(session_id: int) -> dict | None:
    init_db()
    with _connect() as conn:
        row = conn.execute(
            "SELECT report_json FROM Audit_Session WHERE session_id = ?", (session_id,)
        ).fetchone()
    if row is None or row["report_json"] is None:
        return None
    return json.loads(row["report_json"])


def get_audits_for_domain(domain: str) -> list[dict]:
    init_db()
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT session_id, target_domain, timestamp, overall_risk_score
            FROM   Audit_Session
            WHERE  target_domain = ?
            ORDER  BY timestamp DESC
            """,
            (domain.strip().lower(),),
        ).fetchall()
    return [dict(r) for r in rows]