"""Compliance audit logging - stores metadata without original PII."""
import aiosqlite
import json
import time
from typing import Optional, List, Dict, Any
from pathlib import Path
from dataclasses import dataclass

from config.settings import settings


@dataclass
class AuditEntry:
    timestamp: float
    session_id: str
    request_path: str
    entity_count: int
    entity_types: Dict[str, int]
    tokens: List[Dict[str, Any]]  # Contains token, type, confidence, length (not original!)
    response_status: int
    processing_time_ms: float


class AuditLog:
    """SQLite-based audit log for compliance tracking."""

    def __init__(self, db_path: str = None):
        self.db_path = db_path or settings.audit_db_path
        self._initialized = False

    async def initialize(self):
        """Create tables if they don't exist."""
        if self._initialized:
            return

        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    session_id TEXT NOT NULL,
                    request_path TEXT,
                    entity_count INTEGER,
                    entity_types TEXT,
                    tokens TEXT,
                    response_status INTEGER,
                    processing_time_ms REAL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)

            await db.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_timestamp
                ON audit_log(timestamp)
            """)

            await db.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_session
                ON audit_log(session_id)
            """)

            await db.commit()

        self._initialized = True

    async def log(self, entry: AuditEntry):
        """Log an audit entry."""
        if not settings.enable_audit_log:
            return

        await self.initialize()

        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO audit_log
                (timestamp, session_id, request_path, entity_count,
                 entity_types, tokens, response_status, processing_time_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.timestamp,
                    entry.session_id,
                    entry.request_path,
                    entry.entity_count,
                    json.dumps(entry.entity_types),
                    json.dumps(entry.tokens),
                    entry.response_status,
                    entry.processing_time_ms,
                )
            )
            await db.commit()

    async def query(
        self,
        start_time: Optional[float] = None,
        end_time: Optional[float] = None,
        session_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Query audit log entries."""
        await self.initialize()

        query = "SELECT * FROM audit_log WHERE 1=1"
        params = []

        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time)

        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time)

        if session_id:
            query += " AND session_id = ?"
            params.append(session_id)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(query, params)
            rows = await cursor.fetchall()

            return [
                {
                    "id": row["id"],
                    "timestamp": row["timestamp"],
                    "session_id": row["session_id"],
                    "request_path": row["request_path"],
                    "entity_count": row["entity_count"],
                    "entity_types": json.loads(row["entity_types"]),
                    "tokens": json.loads(row["tokens"]),
                    "response_status": row["response_status"],
                    "processing_time_ms": row["processing_time_ms"],
                }
                for row in rows
            ]

    async def get_stats(
        self,
        start_time: Optional[float] = None,
        end_time: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Get aggregate statistics."""
        await self.initialize()

        query = """
            SELECT
                COUNT(*) as total_requests,
                SUM(entity_count) as total_entities,
                AVG(entity_count) as avg_entities_per_request,
                AVG(processing_time_ms) as avg_processing_time_ms
            FROM audit_log
            WHERE 1=1
        """
        params = []

        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time)

        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time)

        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(query, params)
            row = await cursor.fetchone()

            return {
                "total_requests": row["total_requests"] or 0,
                "total_entities": row["total_entities"] or 0,
                "avg_entities_per_request": row["avg_entities_per_request"] or 0,
                "avg_processing_time_ms": row["avg_processing_time_ms"] or 0,
            }


# Singleton instance
_audit_log: Optional[AuditLog] = None


def get_audit_log() -> AuditLog:
    global _audit_log
    if _audit_log is None:
        _audit_log = AuditLog()
    return _audit_log
