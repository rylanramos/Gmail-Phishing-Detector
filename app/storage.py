import json
import sqlite3
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parent.parent
DB_DIR = BASE_DIR / "data"
DB_FILE = DB_DIR / "phishing_detector.db"


def get_connection():
    DB_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def _migration_001_baseline(conn):
    """Create the baseline tables. Safe to run against a pre-existing
    database created by earlier versions of this app: CREATE TABLE IF NOT
    EXISTS and column-presence checks make this idempotent."""

    conn.execute("""
        CREATE TABLE IF NOT EXISTS email_analysis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            gmail_message_id TEXT UNIQUE
        )
    """)

    existing_columns = {
        row["name"]
        for row in conn.execute("PRAGMA table_info(email_analysis)").fetchall()
    }

    required_columns = {
        "subject": "TEXT",
        "sender": "TEXT",
        "sender_domain": "TEXT",
        "score": "INTEGER",
        "verdict": "TEXT",
        "reasons": "TEXT",
        "raw_features": "TEXT",
        "snippet": "TEXT",
        "analyzed_at": "TEXT",
    }

    for column, col_type in required_columns.items():
        if column not in existing_columns:
            conn.execute(
                f"ALTER TABLE email_analysis ADD COLUMN {column} {col_type}"
            )

    conn.execute("""
        CREATE TABLE IF NOT EXISTS domain_history (
            domain TEXT PRIMARY KEY,
            first_seen TEXT,
            last_seen TEXT,
            suspicious_count INTEGER DEFAULT 0
        )
    """)


# Ordered, numbered migrations. Each migration is applied at most once per
# database, tracked via the schema_version table below. To evolve the schema
# in the future (rename/drop a column, add an index, backfill data, etc.),
# add a new `_migration_NNN_description(conn)` function here and append it
# to this list - never edit an already-shipped migration. This lets existing
# databases upgrade in place instead of requiring the .db file to be deleted.
MIGRATIONS = [
    _migration_001_baseline,
]


def _get_schema_version(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER NOT NULL
        )
    """)

    row = conn.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
    if row is None:
        conn.execute("INSERT INTO schema_version (version) VALUES (0)")
        return 0

    return row["version"]


def _set_schema_version(conn, version):
    conn.execute("DELETE FROM schema_version")
    conn.execute("INSERT INTO schema_version (version) VALUES (?)", (version,))


def init_db():
    with get_connection() as conn:
        current_version = _get_schema_version(conn)

        for version, migration in enumerate(MIGRATIONS, start=1):
            if version > current_version:
                migration(conn)
                _set_schema_version(conn, version)

        conn.commit()

def message_exists(message_id):
    with get_connection() as conn:
        cur = conn.execute(
            "SELECT 1 FROM email_analysis WHERE gmail_message_id=?",
            (message_id,)
        )
        return cur.fetchone() is not None


def update_domain_history(domain, verdict):
    if not domain:
        return

    now = datetime.utcnow().isoformat()
    suspicious_increment = 1 if verdict in {"suspicious", "likely phishing"} else 0

    with get_connection() as conn:
        cur = conn.execute(
            "SELECT domain, suspicious_count FROM domain_history WHERE domain=?",
            (domain,)
        )
        row = cur.fetchone()

        if row:
            conn.execute("""
                UPDATE domain_history
                SET last_seen=?,
                    suspicious_count=suspicious_count + ?
                WHERE domain=?
            """, (now, suspicious_increment, domain))
        else:
            conn.execute("""
                INSERT INTO domain_history (
                    domain,
                    first_seen,
                    last_seen,
                    suspicious_count
                ) VALUES (?, ?, ?, ?)
            """, (domain, now, now, suspicious_increment))

        conn.commit()


def save_result(parsed_email, features, result):
    now = datetime.utcnow().isoformat()

    features_to_store = dict(features)

    with get_connection() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO email_analysis (
                gmail_message_id,
                subject,
                sender,
                sender_domain,
                score,
                verdict,
                reasons,
                raw_features,
                snippet,
                analyzed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            parsed_email["message_id"],
            parsed_email["subject"],
            parsed_email["from"],
            features["sender_domain"],
            result["score"],
            result["verdict"],
            json.dumps(result["reasons"]),
            json.dumps(features_to_store),
            parsed_email.get("snippet", ""),
            now,
        ))
        conn.commit()

    update_domain_history(features["sender_domain"], result["verdict"])


def get_recent_results(limit=100):
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT *
            FROM email_analysis
            ORDER BY analyzed_at DESC
            LIMIT ?
        """, (limit,)).fetchall()

    results = []
    for row in rows:
        item = dict(row)
        item["reasons"] = json.loads(item["reasons"]) if item["reasons"] else []
        item["raw_features"] = json.loads(item["raw_features"]) if item["raw_features"] else {}
        results.append(item)

    return results


def get_results_by_verdict(verdict, limit=100):
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT *
            FROM email_analysis
            WHERE verdict=?
            ORDER BY analyzed_at DESC
            LIMIT ?
        """, (verdict, limit)).fetchall()

    results = []
    for row in rows:
        item = dict(row)
        item["reasons"] = json.loads(item["reasons"]) if item["reasons"] else []
        item["raw_features"] = json.loads(item["raw_features"]) if item["raw_features"] else {}
        results.append(item)

    return results


def get_summary_stats():
    with get_connection() as conn:
        total = conn.execute("SELECT COUNT(*) FROM email_analysis").fetchone()[0]
        safe = conn.execute("SELECT COUNT(*) FROM email_analysis WHERE verdict='safe'").fetchone()[0]
        suspicious = conn.execute("SELECT COUNT(*) FROM email_analysis WHERE verdict='suspicious'").fetchone()[0]
        phishing = conn.execute("SELECT COUNT(*) FROM email_analysis WHERE verdict='likely phishing'").fetchone()[0]

    return {
        "total": total,
        "safe": safe,
        "suspicious": suspicious,
        "likely_phishing": phishing
    }


def get_top_suspicious_domains(limit=10):
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT domain, suspicious_count, last_seen
            FROM domain_history
            WHERE suspicious_count > 0
            ORDER BY suspicious_count DESC, last_seen DESC
            LIMIT ?
        """, (limit,)).fetchall()

    return [dict(row) for row in rows]