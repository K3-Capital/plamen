"""
Database module for Solodit vulnerability storage and search.
Uses SQLite with FTS5 for full-text search.
"""

import aiosqlite
import json
from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, asdict
from datetime import datetime

# Database path
DB_PATH = Path(__file__).parent.parent / "data" / "solodit.db"


@dataclass
class Finding:
    """Represents a Solodit vulnerability finding."""
    id: str
    title: str
    severity: str  # Critical, High, Medium, Low, Info
    category: str  # reentrancy, oracle, access-control, etc.
    protocol: str
    protocol_type: str  # DEX, Lending, Vault, Bridge, etc.
    description: str
    impact: str
    code_snippet: Optional[str]
    recommendation: str
    audit_firm: str
    audit_date: str
    url: str
    tags: List[str]
    created_at: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


async def init_database():
    """Initialize the database schema."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    
    async with aiosqlite.connect(DB_PATH) as db:
        # Main findings table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                protocol TEXT,
                protocol_type TEXT,
                description TEXT,
                impact TEXT,
                code_snippet TEXT,
                recommendation TEXT,
                audit_firm TEXT,
                audit_date TEXT,
                url TEXT,
                tags TEXT,  -- JSON array
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Full-text search virtual table
        await db.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS findings_fts USING fts5(
                id,
                title,
                description,
                impact,
                code_snippet,
                recommendation,
                category,
                tags,
                content='findings',
                content_rowid='rowid'
            )
        """)
        
        # Triggers to keep FTS in sync
        await db.execute("""
            CREATE TRIGGER IF NOT EXISTS findings_ai AFTER INSERT ON findings BEGIN
                INSERT INTO findings_fts(rowid, id, title, description, impact, 
                    code_snippet, recommendation, category, tags)
                VALUES (new.rowid, new.id, new.title, new.description, new.impact,
                    new.code_snippet, new.recommendation, new.category, new.tags);
            END
        """)
        
        await db.execute("""
            CREATE TRIGGER IF NOT EXISTS findings_ad AFTER DELETE ON findings BEGIN
                INSERT INTO findings_fts(findings_fts, rowid, id, title, description, 
                    impact, code_snippet, recommendation, category, tags)
                VALUES ('delete', old.rowid, old.id, old.title, old.description, 
                    old.impact, old.code_snippet, old.recommendation, old.category, old.tags);
            END
        """)
        
        await db.execute("""
            CREATE TRIGGER IF NOT EXISTS findings_au AFTER UPDATE ON findings BEGIN
                INSERT INTO findings_fts(findings_fts, rowid, id, title, description,
                    impact, code_snippet, recommendation, category, tags)
                VALUES ('delete', old.rowid, old.id, old.title, old.description,
                    old.impact, old.code_snippet, old.recommendation, old.category, old.tags);
                INSERT INTO findings_fts(rowid, id, title, description, impact,
                    code_snippet, recommendation, category, tags)
                VALUES (new.rowid, new.id, new.title, new.description, new.impact,
                    new.code_snippet, new.recommendation, new.category, new.tags);
            END
        """)
        
        # Indexes for common queries
        await db.execute("CREATE INDEX IF NOT EXISTS idx_severity ON findings(severity)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_category ON findings(category)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_protocol_type ON findings(protocol_type)")
        
        # Metadata table for tracking scrape status
        await db.execute("""
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)
        
        await db.commit()


async def insert_finding(finding: Finding) -> bool:
    """Insert or update a finding in the database."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT OR REPLACE INTO findings 
            (id, title, severity, category, protocol, protocol_type, description,
             impact, code_snippet, recommendation, audit_firm, audit_date, url, tags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            finding.id, finding.title, finding.severity, finding.category,
            finding.protocol, finding.protocol_type, finding.description,
            finding.impact, finding.code_snippet, finding.recommendation,
            finding.audit_firm, finding.audit_date, finding.url,
            json.dumps(finding.tags)
        ))
        await db.commit()
        return True


async def search_findings(
    query: str,
    limit: int = 10,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    protocol_type: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Full-text search across findings.
    
    Args:
        query: Search query (supports FTS5 syntax)
        limit: Maximum results to return
        severity: Filter by severity (Critical, High, Medium, Low)
        category: Filter by vulnerability category
        protocol_type: Filter by protocol type
    
    Returns:
        List of matching findings
    """
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        
        # Build WHERE clause for filters
        filters = []
        params = []
        
        if severity:
            filters.append("f.severity = ?")
            params.append(severity)
        if category:
            filters.append("f.category LIKE ?")
            params.append(f"%{category}%")
        if protocol_type:
            filters.append("f.protocol_type LIKE ?")
            params.append(f"%{protocol_type}%")
        
        filter_clause = " AND ".join(filters) if filters else "1=1"
        
        # FTS5 search with filters
        sql = f"""
            SELECT f.*, 
                   bm25(findings_fts) as relevance
            FROM findings f
            JOIN findings_fts fts ON f.id = fts.id
            WHERE findings_fts MATCH ? AND {filter_clause}
            ORDER BY relevance
            LIMIT ?
        """
        
        params = [query] + params + [limit]
        
        cursor = await db.execute(sql, params)
        rows = await cursor.fetchall()
        
        results = []
        for row in rows:
            result = dict(row)
            result['tags'] = json.loads(result.get('tags', '[]'))
            results.append(result)
        
        return results


async def search_by_category(
    category: str,
    limit: int = 10,
    severity: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Search findings by vulnerability category."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        
        sql = """
            SELECT * FROM findings 
            WHERE category LIKE ?
        """
        params = [f"%{category}%"]
        
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        
        sql += " ORDER BY CASE severity "
        sql += "WHEN 'Critical' THEN 1 "
        sql += "WHEN 'High' THEN 2 "
        sql += "WHEN 'Medium' THEN 3 "
        sql += "WHEN 'Low' THEN 4 "
        sql += "ELSE 5 END "
        sql += "LIMIT ?"
        params.append(limit)
        
        cursor = await db.execute(sql, params)
        rows = await cursor.fetchall()
        
        results = []
        for row in rows:
            result = dict(row)
            result['tags'] = json.loads(result.get('tags', '[]'))
            results.append(result)
        
        return results


async def get_finding_by_id(finding_id: str) -> Optional[Dict[str, Any]]:
    """Get a single finding by ID."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        
        cursor = await db.execute(
            "SELECT * FROM findings WHERE id = ?",
            (finding_id,)
        )
        row = await cursor.fetchone()
        
        if row:
            result = dict(row)
            result['tags'] = json.loads(result.get('tags', '[]'))
            return result
        return None


async def get_statistics() -> Dict[str, Any]:
    """Get database statistics."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        
        # Total count
        cursor = await db.execute("SELECT COUNT(*) as total FROM findings")
        total = (await cursor.fetchone())['total']
        
        # By severity
        cursor = await db.execute("""
            SELECT severity, COUNT(*) as count 
            FROM findings 
            GROUP BY severity 
            ORDER BY CASE severity 
                WHEN 'Critical' THEN 1 
                WHEN 'High' THEN 2 
                WHEN 'Medium' THEN 3 
                WHEN 'Low' THEN 4 
                ELSE 5 END
        """)
        by_severity = {row['severity']: row['count'] for row in await cursor.fetchall()}
        
        # By category (top 10)
        cursor = await db.execute("""
            SELECT category, COUNT(*) as count 
            FROM findings 
            GROUP BY category 
            ORDER BY count DESC 
            LIMIT 10
        """)
        by_category = {row['category']: row['count'] for row in await cursor.fetchall()}
        
        # Last update
        cursor = await db.execute(
            "SELECT value FROM metadata WHERE key = 'last_scrape'"
        )
        row = await cursor.fetchone()
        last_update = row['value'] if row else "Never"
        
        return {
            "total_findings": total,
            "by_severity": by_severity,
            "top_categories": by_category,
            "last_update": last_update
        }


async def list_categories() -> List[Dict[str, int]]:
    """List all vulnerability categories with counts."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        
        cursor = await db.execute("""
            SELECT category, COUNT(*) as count 
            FROM findings 
            GROUP BY category 
            ORDER BY count DESC
        """)
        
        return [{"category": row['category'], "count": row['count']} 
                for row in await cursor.fetchall()]


async def set_metadata(key: str, value: str):
    """Set a metadata value."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            (key, value)
        )
        await db.commit()
