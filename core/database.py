"""
ClaudioSec - Database Layer
SQLite-based event storage with async support
"""

import aiosqlite
import sqlite3
import json
import os
from datetime import datetime
from typing import Optional, List, Dict, Any
from loguru import logger

DB_PATH = os.getenv("DB_PATH", "data/claudiosec.db")


def get_db_path() -> str:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    return DB_PATH


def init_db():
    """Initialize database synchronously (for startup)"""
    db_path = get_db_path()
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    # Security events table
    c.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL CHECK(severity IN ('low', 'medium', 'high', 'critical')),
            source_module TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            raw_data TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            username TEXT,
            file_path TEXT,
            process_name TEXT,
            ai_analyzed INTEGER DEFAULT 0,
            ai_analysis TEXT,
            resolved INTEGER DEFAULT 0,
            resolved_at TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)

    # AI incident reports table
    c.execute("""
        CREATE TABLE IF NOT EXISTS incident_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            threat_summary TEXT NOT NULL,
            affected_assets TEXT,
            attack_vector TEXT,
            indicators TEXT,
            remediation_steps TEXT NOT NULL,
            raw_events TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)

    # File integrity baseline table
    c.execute("""
        CREATE TABLE IF NOT EXISTS file_hashes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT UNIQUE NOT NULL,
            hash_sha256 TEXT NOT NULL,
            file_size INTEGER,
            last_modified TEXT,
            baseline_set_at TEXT DEFAULT (datetime('now')),
            last_checked_at TEXT
        )
    """)

    # Auth events table
    c.execute("""
        CREATE TABLE IF NOT EXISTS auth_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            username TEXT,
            source_ip TEXT,
            success INTEGER,
            details TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)

    # Known threat IPs table
    c.execute("""
        CREATE TABLE IF NOT EXISTS threat_intel (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE NOT NULL,
            threat_type TEXT,
            confidence_score INTEGER,
            source TEXT,
            added_at TEXT DEFAULT (datetime('now'))
        )
    """)

    # System stats table
    c.execute("""
        CREATE TABLE IF NOT EXISTS system_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            cpu_percent REAL,
            memory_percent REAL,
            disk_percent REAL,
            network_bytes_sent INTEGER,
            network_bytes_recv INTEGER,
            active_connections INTEGER
        )
    """)

    conn.commit()
    conn.close()
    logger.info(f"Database initialized at {db_path}")


async def get_db():
    """Async database connection context manager"""
    return await aiosqlite.connect(get_db_path())


async def insert_event(
    event_type: str,
    severity: str,
    source_module: str,
    title: str,
    description: str,
    raw_data: Optional[Dict] = None,
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    username: Optional[str] = None,
    file_path: Optional[str] = None,
    process_name: Optional[str] = None,
) -> int:
    """Insert a security event into the database"""
    async with aiosqlite.connect(get_db_path()) as db:
        cursor = await db.execute(
            """
            INSERT INTO events (
                timestamp, event_type, severity, source_module, title, description,
                raw_data, source_ip, destination_ip, username, file_path, process_name
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.utcnow().isoformat(),
                event_type,
                severity,
                source_module,
                title,
                description,
                json.dumps(raw_data) if raw_data else None,
                source_ip,
                destination_ip,
                username,
                file_path,
                process_name,
            ),
        )
        await db.commit()
        event_id = cursor.lastrowid
        logger.debug(f"[DB] Event inserted: id={event_id} type={event_type} severity={severity}")
        return event_id


async def get_events(
    limit: int = 100,
    offset: int = 0,
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
    source_module: Optional[str] = None,
    resolved: Optional[bool] = None,
) -> List[Dict]:
    """Retrieve events with optional filters"""
    query = "SELECT * FROM events WHERE 1=1"
    params = []

    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if event_type:
        query += " AND event_type = ?"
        params.append(event_type)
    if source_module:
        query += " AND source_module = ?"
        params.append(source_module)
    if resolved is not None:
        query += " AND resolved = ?"
        params.append(1 if resolved else 0)

    query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    async with aiosqlite.connect(get_db_path()) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(query, params) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]


async def get_event_stats() -> Dict[str, Any]:
    """Get event statistics for dashboard"""
    async with aiosqlite.connect(get_db_path()) as db:
        stats = {}

        # Total events
        async with db.execute("SELECT COUNT(*) FROM events") as c:
            stats["total_events"] = (await c.fetchone())[0]

        # By severity
        async with db.execute(
            "SELECT severity, COUNT(*) FROM events GROUP BY severity"
        ) as c:
            rows = await c.fetchall()
            stats["by_severity"] = {row[0]: row[1] for row in rows}

        # Unresolved
        async with db.execute(
            "SELECT COUNT(*) FROM events WHERE resolved = 0"
        ) as c:
            stats["unresolved"] = (await c.fetchone())[0]

        # Last 24h
        async with db.execute(
            "SELECT COUNT(*) FROM events WHERE timestamp > datetime('now', '-1 day')"
        ) as c:
            stats["last_24h"] = (await c.fetchone())[0]

        # Critical unresolved
        async with db.execute(
            "SELECT COUNT(*) FROM events WHERE severity = 'critical' AND resolved = 0"
        ) as c:
            stats["critical_unresolved"] = (await c.fetchone())[0]

        # Recent events (last 10)
        async with db.execute(
            "SELECT * FROM events ORDER BY timestamp DESC LIMIT 10"
        ) as c:
            db.row_factory = aiosqlite.Row
            rows = await c.fetchall()
            stats["recent"] = [dict(r) for r in rows] if rows else []

        return stats


async def mark_event_resolved(event_id: int):
    """Mark an event as resolved"""
    async with aiosqlite.connect(get_db_path()) as db:
        await db.execute(
            "UPDATE events SET resolved = 1, resolved_at = ? WHERE id = ?",
            (datetime.utcnow().isoformat(), event_id),
        )
        await db.commit()


async def save_ai_analysis(event_id: int, analysis: str):
    """Save Claude's analysis for an event"""
    async with aiosqlite.connect(get_db_path()) as db:
        await db.execute(
            "UPDATE events SET ai_analyzed = 1, ai_analysis = ? WHERE id = ?",
            (analysis, event_id),
        )
        await db.commit()


async def save_incident_report(report: Dict) -> int:
    """Save a full incident report"""
    async with aiosqlite.connect(get_db_path()) as db:
        cursor = await db.execute(
            """
            INSERT INTO incident_reports (
                timestamp, title, severity, threat_summary, affected_assets,
                attack_vector, indicators, remediation_steps, raw_events
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.utcnow().isoformat(),
                report.get("title", "Incident Report"),
                report.get("severity", "medium"),
                report.get("threat_summary", ""),
                json.dumps(report.get("affected_assets", [])),
                report.get("attack_vector", ""),
                json.dumps(report.get("indicators", [])),
                report.get("remediation_steps", ""),
                json.dumps(report.get("raw_events", [])),
            ),
        )
        await db.commit()
        return cursor.lastrowid


async def get_incident_reports(limit: int = 20) -> List[Dict]:
    """Get incident reports"""
    async with aiosqlite.connect(get_db_path()) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM incident_reports ORDER BY timestamp DESC LIMIT ?", (limit,)
        ) as cursor:
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]


async def upsert_file_hash(file_path: str, hash_sha256: str, file_size: int, last_modified: str):
    """Insert or update file hash baseline"""
    async with aiosqlite.connect(get_db_path()) as db:
        await db.execute(
            """
            INSERT INTO file_hashes (file_path, hash_sha256, file_size, last_modified, last_checked_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(file_path) DO UPDATE SET
                hash_sha256 = excluded.hash_sha256,
                file_size = excluded.file_size,
                last_modified = excluded.last_modified,
                last_checked_at = excluded.last_checked_at
            """,
            (file_path, hash_sha256, file_size, last_modified, datetime.utcnow().isoformat()),
        )
        await db.commit()


async def get_file_hash(file_path: str) -> Optional[Dict]:
    """Get stored hash for a file"""
    async with aiosqlite.connect(get_db_path()) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM file_hashes WHERE file_path = ?", (file_path,)
        ) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None


async def add_threat_ip(ip: str, threat_type: str, confidence: int, source: str):
    """Add IP to threat intel"""
    async with aiosqlite.connect(get_db_path()) as db:
        await db.execute(
            """
            INSERT OR REPLACE INTO threat_intel (ip_address, threat_type, confidence_score, source)
            VALUES (?, ?, ?, ?)
            """,
            (ip, threat_type, confidence, source),
        )
        await db.commit()


async def is_threat_ip(ip: str) -> Optional[Dict]:
    """Check if an IP is in the threat intel database"""
    async with aiosqlite.connect(get_db_path()) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM threat_intel WHERE ip_address = ?", (ip,)
        ) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None