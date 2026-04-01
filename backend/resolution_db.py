"""
Aegis ReWrite — Resolution Database
SQLite persistence for finding resolution states (FIXED, IGNORED, OPEN).
Cross-platform. No external dependencies.
"""
import os
import sqlite3
import hashlib
from datetime import datetime


DB_DIR = os.path.join(os.path.dirname(__file__), 'data')
RESOLUTION_DB = os.path.join(DB_DIR, 'resolutions.db')


def _init_db():
    """Initialize the resolution database."""
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(RESOLUTION_DB)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS finding_resolutions (
            finding_hash TEXT PRIMARY KEY,
            project_path TEXT,
            file_path TEXT,
            category TEXT,
            title TEXT,
            status TEXT DEFAULT 'OPEN',
            resolved_at TEXT,
            created_at TEXT,
            updated_at TEXT
        )
    ''')
    conn.commit()
    conn.close()


def finding_hash(project_path, finding):
    """Deterministic hash from immutable finding properties."""
    raw = f"{project_path}|{finding.get('file','')}|{finding.get('line','')}|{finding.get('category','')}|{finding.get('title','')}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def get_resolution(fhash):
    """Get the resolution status for a finding hash."""
    conn = sqlite3.connect(RESOLUTION_DB)
    row = conn.execute(
        'SELECT status FROM finding_resolutions WHERE finding_hash = ?',
        (fhash,)
    ).fetchone()
    conn.close()
    return row[0] if row else 'OPEN'


def set_resolution(fhash, project_path, finding, status):
    """Set or update resolution status."""
    now = datetime.now().isoformat()
    conn = sqlite3.connect(RESOLUTION_DB)
    conn.execute('''
        INSERT INTO finding_resolutions (finding_hash, project_path, file_path, category, title, status, resolved_at, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(finding_hash) DO UPDATE SET
            status = excluded.status,
            resolved_at = excluded.resolved_at,
            updated_at = excluded.updated_at
    ''', (
        fhash, project_path,
        finding.get('file', ''), finding.get('category', ''), finding.get('title', ''),
        status,
        now if status in ('FIXED', 'IGNORED') else None,
        now, now
    ))
    conn.commit()
    conn.close()


def get_resolutions(project_path):
    """Get all resolutions for a project."""
    conn = sqlite3.connect(RESOLUTION_DB)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        'SELECT * FROM finding_resolutions WHERE project_path = ? ORDER BY updated_at DESC',
        (project_path,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# Initialize on import
_init_db()
