"""SQLite persistence for tasks, messages, and cached findings."""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator


SCHEMA = """
CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    status TEXT NOT NULL,
    target TEXT,
    source_type TEXT,
    source_url TEXT,
    source_branch TEXT,
    source_commit TEXT,
    source_path TEXT,
    instruction TEXT,
    scan_mode TEXT,
    max_budget REAL,
    workspace TEXT NOT NULL,
    run_name TEXT,
    pid INTEGER,
    exit_code INTEGER,
    parent_task_id TEXT,
    action TEXT,
    error TEXT,
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL,
    delivered INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY(task_id) REFERENCES tasks(id)
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT,
    confidence TEXT,
    description TEXT,
    asset TEXT,
    location_json TEXT,
    evidence TEXT,
    poc TEXT,
    impact TEXT,
    recommendation TEXT,
    cwe TEXT,
    cvss REAL,
    raw_json TEXT,
    created_at TEXT NOT NULL,
    PRIMARY KEY (id, task_id),
    FOREIGN KEY(task_id) REFERENCES tasks(id)
);

CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
CREATE INDEX IF NOT EXISTS idx_tasks_created ON tasks(created_at);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_messages_task ON messages(task_id);
"""


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class Database:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.RLock()
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            conn = sqlite3.connect(self.path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    def insert_task(self, task: dict[str, Any]) -> dict[str, Any]:
        cols = ", ".join(task.keys())
        placeholders = ", ".join("?" for _ in task)
        with self.connect() as conn:
            conn.execute(
                f"INSERT INTO tasks ({cols}) VALUES ({placeholders})",
                tuple(task.values()),
            )
        return self.get_task(task["id"])  # type: ignore[return-value]

    def update_task(self, task_id: str, **fields: Any) -> dict[str, Any] | None:
        if not fields:
            return self.get_task(task_id)
        fields = {**fields, "updated_at": utc_now()}
        assignments = ", ".join(f"{key} = ?" for key in fields)
        with self.connect() as conn:
            conn.execute(
                f"UPDATE tasks SET {assignments} WHERE id = ?",
                (*fields.values(), task_id),
            )
        return self.get_task(task_id)

    def get_task(self, task_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        return dict(row) if row else None

    def list_tasks(
        self,
        *,
        status: str | None = None,
        task_type: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if status:
            clauses.append("status = ?")
            params.append(status)
        if task_type:
            clauses.append("type = ?")
            params.append(task_type)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.extend([limit, offset])
        with self.connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM tasks {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
                params,
            ).fetchall()
        return [dict(row) for row in rows]

    def count_by_status(self, status: str) -> int:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS c FROM tasks WHERE status = ?",
                (status,),
            ).fetchone()
        return int(row["c"] if row else 0)

    def claim_next_queued(self) -> dict[str, Any] | None:
        """Atomically move one queued task to starting."""
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM tasks WHERE status = 'queued' ORDER BY created_at ASC LIMIT 1"
            ).fetchone()
            if not row:
                return None
            now = utc_now()
            conn.execute(
                "UPDATE tasks SET status = 'starting', started_at = ?, updated_at = ? "
                "WHERE id = ? AND status = 'queued'",
                (now, now, row["id"]),
            )
            updated = conn.execute("SELECT * FROM tasks WHERE id = ?", (row["id"],)).fetchone()
        return dict(updated) if updated else None

    def add_message(self, task_id: str, role: str, content: str) -> dict[str, Any]:
        now = utc_now()
        with self.connect() as conn:
            cur = conn.execute(
                "INSERT INTO messages (task_id, role, content, created_at, delivered) "
                "VALUES (?, ?, ?, ?, 0)",
                (task_id, role, content, now),
            )
            row = conn.execute(
                "SELECT * FROM messages WHERE id = ?",
                (cur.lastrowid,),
            ).fetchone()
        return dict(row)

    def list_messages(self, task_id: str) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM messages WHERE task_id = ? ORDER BY id ASC",
                (task_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def replace_findings(self, task_id: str, findings: list[dict[str, Any]]) -> None:
        now = utc_now()
        with self.connect() as conn:
            conn.execute("DELETE FROM findings WHERE task_id = ?", (task_id,))
            for finding in findings:
                conn.execute(
                    """
                    INSERT INTO findings (
                        id, task_id, title, severity, confidence, description, asset,
                        location_json, evidence, poc, impact, recommendation, cwe, cvss,
                        raw_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        finding["id"],
                        task_id,
                        finding.get("title") or "Untitled",
                        finding.get("severity"),
                        finding.get("confidence"),
                        finding.get("description"),
                        finding.get("asset"),
                        json.dumps(finding.get("location") or {}, ensure_ascii=False),
                        finding.get("evidence"),
                        finding.get("poc"),
                        finding.get("impact"),
                        finding.get("recommendation"),
                        finding.get("cwe"),
                        finding.get("cvss"),
                        json.dumps(finding.get("raw") or finding, ensure_ascii=False, default=str),
                        finding.get("created_at") or now,
                    ),
                )

    def list_findings(
        self,
        *,
        task_id: str,
        severity: str | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = ["task_id = ?"]
        params: list[Any] = [task_id]
        if severity:
            clauses.append("severity = ?")
            params.append(severity.lower())
        where = "WHERE " + " AND ".join(clauses)
        params.extend([limit, offset])
        with self.connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM findings {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
                params,
            ).fetchall()
        results: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            try:
                item["location"] = json.loads(item.pop("location_json") or "{}")
            except json.JSONDecodeError:
                item["location"] = {}
            item.pop("raw_json", None)
            results.append(item)
        return results
