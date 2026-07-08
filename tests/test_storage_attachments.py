"""Tests for the attachment-findings migration and persistence in app.storage.

Each test runs against a fresh temporary SQLite database (storage.DB_FILE is
monkeypatched) so the developer's real data/phishing_detector.db is untouched.
"""

import pytest

from app import storage


@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    db_dir = tmp_path / "data"
    monkeypatch.setattr(storage, "DB_DIR", db_dir)
    monkeypatch.setattr(storage, "DB_FILE", db_dir / "test.db")
    storage.init_db()
    return storage.DB_FILE


def _parsed(message_id="msg-1"):
    return {
        "message_id": message_id,
        "subject": "Invoice attached",
        "from": '"AP" <ap@vendor-example.com>',
        "snippet": "see attached",
    }


def _features():
    return {"sender_domain": "vendor-example.com"}


def _result():
    return {"score": 80, "verdict": "likely phishing", "reasons": ["macro"]}


def _finding(**overrides):
    base = {
        "filename": "invoice.docm",
        "detected_type": "docx",
        "claimed_extension": "docm",
        "extension_mismatch": False,
        "has_macros": True,
        "macro_autoexec_triggers": ["AutoOpen"],
        "macro_shell_calls": ["Shell"],
        "macro_obfuscation": False,
        "macro_obfuscation_details": [],
        "macro_urls": [],
        "macro_ips": [],
        "has_embedded_objects": False,
        "sha256": "abc123",
        "virustotal": {"available": True, "status": "malicious",
                       "malicious": 40, "total": 70},
    }
    base.update(overrides)
    return base


class TestMigration:
    def test_schema_version_advances_to_two(self, temp_db):
        with storage.get_connection() as conn:
            version = conn.execute("SELECT version FROM schema_version").fetchone()[0]
        assert version == 2

    def test_attachment_table_exists(self, temp_db):
        with storage.get_connection() as conn:
            row = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='attachment_findings'"
            ).fetchone()
        assert row is not None

    def test_migration_is_idempotent(self, temp_db):
        # Running init_db again must not error or duplicate anything.
        storage.init_db()
        storage.init_db()
        with storage.get_connection() as conn:
            version = conn.execute("SELECT version FROM schema_version").fetchone()[0]
        assert version == 2


class TestPersistence:
    def test_findings_saved_and_queryable_per_email(self, temp_db):
        storage.save_result(_parsed(), _features(), _result(), [_finding()])

        rows = storage.get_attachments_for_message("msg-1")
        assert len(rows) == 1
        row = rows[0]
        assert row["filename"] == "invoice.docm"
        assert row["detected_type"] == "docx"
        assert row["has_macros"] == 1
        assert row["sha256"] == "abc123"
        assert row["vt_status"] == "malicious"
        assert row["vt_malicious"] == 40
        assert row["vt_total"] == 70

    def test_macro_triggers_roundtrip_as_dict(self, temp_db):
        storage.save_result(_parsed(), _features(), _result(), [_finding()])
        row = storage.get_attachments_for_message("msg-1")[0]
        assert row["macro_triggers"]["autoexec"] == ["AutoOpen"]
        assert row["macro_triggers"]["shell"] == ["Shell"]

    def test_extension_mismatch_flag_stored_as_int(self, temp_db):
        storage.save_result(
            _parsed(), _features(), _result(),
            [_finding(extension_mismatch=True, has_macros=False)],
        )
        row = storage.get_attachments_for_message("msg-1")[0]
        assert row["extension_mismatch"] == 1

    def test_no_attachments_saves_email_only(self, temp_db):
        storage.save_result(_parsed(), _features(), _result(), None)
        assert storage.get_attachments_for_message("msg-1") == []
        assert storage.message_exists("msg-1")

    def test_missing_virustotal_recorded_unavailable(self, temp_db):
        storage.save_result(
            _parsed(), _features(), _result(),
            [_finding(virustotal=None)],
        )
        row = storage.get_attachments_for_message("msg-1")[0]
        assert row["vt_available"] == 0
        assert row["vt_status"] is None

    def test_rescan_replaces_prior_attachment_rows(self, temp_db):
        storage.save_result(_parsed(), _features(), _result(),
                            [_finding(filename="first.docm")])
        # Re-scan the same message with a different attachment set.
        storage.save_result(_parsed(), _features(), _result(),
                            [_finding(filename="second.docm")])

        rows = storage.get_attachments_for_message("msg-1")
        assert len(rows) == 1
        assert rows[0]["filename"] == "second.docm"

    def test_multiple_attachments_preserve_order(self, temp_db):
        storage.save_result(
            _parsed(), _features(), _result(),
            [_finding(filename="a.docm"), _finding(filename="b.docm")],
        )
        rows = storage.get_attachments_for_message("msg-1")
        assert [r["filename"] for r in rows] == ["a.docm", "b.docm"]
