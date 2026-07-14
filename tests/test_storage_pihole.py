"""Tests for the Pi-hole correlation migration and persistence in app.storage.

Each test runs against a fresh temporary SQLite database (storage.DB_FILE is
monkeypatched) so the developer's real data/phishing_detector.db is untouched.
"""

from datetime import datetime, timedelta

import pytest

from app import storage


@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    db_dir = tmp_path / "data"
    monkeypatch.setattr(storage, "DB_DIR", db_dir)
    monkeypatch.setattr(storage, "DB_FILE", db_dir / "test.db")
    storage.init_db()
    return storage.DB_FILE


def _save_email(message_id, sender_domain, verdict, score, all_urls=None, analyzed_at=None):
    """Directly insert an email_analysis row with realistic shape (mirrors
    what app.storage.save_result actually writes), so tests exercise the real
    read path (get_flagged_emails_since) against real column/JSON shapes."""
    import json

    now = analyzed_at or datetime.utcnow().isoformat()
    raw_features = {"sender_domain": sender_domain, "all_urls": all_urls or []}

    with storage.get_connection() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO email_analysis (
                gmail_message_id, subject, sender, sender_domain,
                score, verdict, reasons, raw_features, snippet, analyzed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            message_id, "Test subject", f"Sender <x@{sender_domain}>", sender_domain,
            score, verdict, json.dumps([]), json.dumps(raw_features), "snippet", now,
        ))
        conn.commit()


def _hit(domain="evil-example.com", source="sender", message_id="msg-1",
         query_id=1, **overrides):
    base = {
        "domain": domain,
        "domain_source": source,
        "gmail_message_id": message_id,
        "email_verdict": "likely phishing",
        "email_score": 80,
        "email_subject": "Urgent: verify your account",
        "pihole_query_id": query_id,
        "pihole_query_time": 1751900000.0,
        "pihole_client_ip": "192.168.2.10",
        "pihole_client_name": "main-pc",
        "pihole_query_status": "FORWARDED",
    }
    base.update(overrides)
    return base


class TestMigration:
    def test_schema_version_advances_past_pihole_migration(self, temp_db):
        # Tied to len(MIGRATIONS) rather than a hardcoded number, so this
        # doesn't need editing every time a later, unrelated migration is
        # added. What matters here is that migration 003 is included.
        with storage.get_connection() as conn:
            version = conn.execute("SELECT version FROM schema_version").fetchone()[0]
        assert version == len(storage.MIGRATIONS)
        assert version >= 3

    def test_table_and_indexes_exist(self, temp_db):
        with storage.get_connection() as conn:
            row = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='pihole_correlations'"
            ).fetchone()
            assert row is not None
            indexes = {
                r["name"] for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='pihole_correlations'"
                ).fetchall()
            }
            assert "idx_pihole_correlations_dedup" in indexes
            assert "idx_pihole_correlations_domain" in indexes

    def test_migration_is_idempotent(self, temp_db):
        storage.init_db()
        storage.init_db()
        with storage.get_connection() as conn:
            version = conn.execute("SELECT version FROM schema_version").fetchone()[0]
        assert version == len(storage.MIGRATIONS)


class TestGetFlaggedEmailsSince:
    def test_only_suspicious_and_phishing_returned(self, temp_db):
        _save_email("safe-1", "example.com", "safe", 0)
        _save_email("susp-1", "sketchy.example", "suspicious", 35)
        _save_email("phish-1", "evil-example.com", "likely phishing", 80)

        cutoff = (datetime.utcnow() - timedelta(days=7)).isoformat()
        flagged = storage.get_flagged_emails_since(cutoff)

        ids = {e["gmail_message_id"] for e in flagged}
        assert ids == {"susp-1", "phish-1"}

    def test_respects_cutoff(self, temp_db):
        old = (datetime.utcnow() - timedelta(days=30)).isoformat()
        recent = datetime.utcnow().isoformat()
        _save_email("old-phish", "evil-example.com", "likely phishing", 80, analyzed_at=old)
        _save_email("recent-phish", "evil-example.com", "likely phishing", 80, analyzed_at=recent)

        cutoff = (datetime.utcnow() - timedelta(days=7)).isoformat()
        flagged = storage.get_flagged_emails_since(cutoff)

        ids = {e["gmail_message_id"] for e in flagged}
        assert ids == {"recent-phish"}

    def test_raw_features_decoded(self, temp_db):
        _save_email("phish-1", "evil-example.com", "likely phishing", 80,
                    all_urls=["https://evil-example.com/verify"])

        cutoff = (datetime.utcnow() - timedelta(days=7)).isoformat()
        flagged = storage.get_flagged_emails_since(cutoff)

        assert flagged[0]["raw_features"]["all_urls"] == ["https://evil-example.com/verify"]

    def test_empty_when_nothing_flagged(self, temp_db):
        _save_email("safe-1", "example.com", "safe", 0)

        cutoff = (datetime.utcnow() - timedelta(days=7)).isoformat()
        assert storage.get_flagged_emails_since(cutoff) == []


class TestSavePiholeCorrelation:
    def test_hit_saved_and_queryable(self, temp_db):
        storage.save_pihole_correlation(_hit())

        rows = storage.get_recent_pihole_correlations()
        assert len(rows) == 1
        assert rows[0]["domain"] == "evil-example.com"
        assert rows[0]["domain_source"] == "sender"
        assert rows[0]["gmail_message_id"] == "msg-1"
        assert rows[0]["pihole_query_id"] == 1
        assert rows[0]["pihole_client_ip"] == "192.168.2.10"

    def test_duplicate_hit_is_ignored_not_duplicated(self, temp_db):
        storage.save_pihole_correlation(_hit())
        storage.save_pihole_correlation(_hit())  # exact same domain/message/query id

        assert len(storage.get_recent_pihole_correlations()) == 1

    def test_same_query_from_two_different_emails_both_recorded(self, temp_db):
        # Two distinct phishing emails both referencing the same domain, and
        # Pi-hole logged one matching DNS query: both source emails should be
        # preserved as separate provenance rows against that one query.
        storage.save_pihole_correlation(_hit(message_id="msg-1", query_id=1))
        storage.save_pihole_correlation(_hit(message_id="msg-2", query_id=1))

        rows = storage.get_recent_pihole_correlations()
        assert len(rows) == 2
        assert {r["gmail_message_id"] for r in rows} == {"msg-1", "msg-2"}

    def test_same_domain_different_queries_both_recorded(self, temp_db):
        storage.save_pihole_correlation(_hit(query_id=1))
        storage.save_pihole_correlation(_hit(query_id=2))

        assert len(storage.get_recent_pihole_correlations()) == 2

    def test_link_source_hit(self, temp_db):
        storage.save_pihole_correlation(_hit(source="link"))

        rows = storage.get_recent_pihole_correlations()
        assert rows[0]["domain_source"] == "link"
