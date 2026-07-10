"""End-to-end tests for scanner.run_scan itself (not score_email in isolation).

These drive the real live scanning path that app/main.py and the systemd timer
run: Gmail fetch -> parse_message -> build_features -> analyze_attachments ->
score_email -> save_result. A fake Gmail service (no network/OAuth) delivers a
message whose attachment is a real, statically-extractable AutoOpen+Shell macro
document, and the test asserts run_scan both returns and PERSISTS the correct
'likely phishing' verdict plus the attachment finding.

VirusTotal is stubbed to a disabled client so the test never touches the
network, and storage is redirected to a temp SQLite DB so the developer's real
database is untouched.
"""

import base64
import sys
from pathlib import Path

import pytest

# scanner.py uses bare intra-package imports (e.g. `from gmail_client import ...`),
# so app/ must be on sys.path to import it - matching how it runs in production.
APP_DIR = Path(__file__).resolve().parents[1] / "app"
sys.path.insert(0, str(APP_DIR))

import scanner        # noqa: E402  (import after sys.path tweak)
import storage        # noqa: E402  (same storage module scanner's functions use)

from fixtures import attachments as fx  # noqa: E402


def _b64url(raw):
    """Gmail delivers attachment bytes as base64url without padding."""
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


class _Exec:
    def __init__(self, value):
        self._value = value

    def execute(self):
        return self._value


class _FakeMessages:
    def __init__(self, message, attachment_store):
        self._message = message
        self._attachment_store = attachment_store

    def list(self, userId, maxResults=None, q=None):
        return _Exec({"messages": [{"id": self._message["id"]}]})

    def get(self, userId, id, format):
        return _Exec(self._message)

    def attachments(self):
        store = self._attachment_store

        class _Att:
            def get(self, userId, messageId, id):
                return _Exec({"data": _b64url(store[id])})

        return _Att()


class FakeGmailService:
    """Minimal stand-in for the googleapiclient Gmail service."""

    def __init__(self, message, attachment_store):
        self._messages = _FakeMessages(message, attachment_store)

    def users(self):
        return self

    def messages(self):
        return self._messages


class DisabledVTClient:
    """VirusTotal client stub: never touches the network."""

    def __init__(self, *args, **kwargs):
        pass

    @property
    def enabled(self):
        return False

    def lookup_hash(self, sha256):
        return {"available": False, "status": "unavailable",
                "reason": "test", "malicious": None, "total": None}


def _message_with_attachment(filename, content, *, from_="Billing <billing@vendor-example.com>",
                             subject="Invoice", body="Please see the attached invoice."):
    return {
        "id": "scan-msg-1",
        "threadId": "scan-thread-1",
        "snippet": body[:80],
        "internalDate": "1751724862000",
        "payload": {
            "mimeType": "multipart/mixed",
            "headers": [
                {"name": "From", "value": from_},
                {"name": "Subject", "value": subject},
            ],
            "parts": [
                {"mimeType": "text/plain", "body": {"data": _b64url(body.encode())}},
                {
                    "mimeType": "application/vnd.ms-word.document.macroEnabled.12",
                    "filename": filename,
                    "body": {"attachmentId": "att1", "size": len(content)},
                },
            ],
        },
    }, {"att1": content}


@pytest.fixture
def temp_env(tmp_path, monkeypatch):
    """Redirect storage to a temp DB and stub the network-facing collaborators."""
    db_dir = tmp_path / "data"
    monkeypatch.setattr(storage, "DB_DIR", db_dir)
    monkeypatch.setattr(storage, "DB_FILE", db_dir / "scanner-test.db")
    monkeypatch.setattr(scanner, "VirusTotalClient", DisabledVTClient)
    return tmp_path


def _run_with_message(monkeypatch, message, attachment_store):
    service = FakeGmailService(message, attachment_store)
    monkeypatch.setattr(scanner, "get_gmail_service", lambda: service)
    return scanner.run_scan(max_results=1, query="test")


class _MultiQueryFakeMessages:
    """Fake messages() resource that returns different id lists depending on
    whether the query string contains 'in:spam', mirroring Gmail's real
    behaviour of excluding Spam/Trash from messages.list unless explicitly
    asked for. Message bodies for every id must be present in `catalog`."""

    def __init__(self, catalog, inbox_ids, spam_ids):
        self._catalog = catalog
        self._inbox_ids = inbox_ids
        self._spam_ids = spam_ids

    def list(self, userId, maxResults=None, q=None):
        ids = self._spam_ids if "in:spam" in (q or "") else self._inbox_ids
        return _Exec({"messages": [{"id": i} for i in ids]})

    def get(self, userId, id, format):
        return _Exec(self._catalog[id]["message"])

    def attachments(self):
        catalog = self._catalog

        class _Att:
            def get(self, userId, messageId, id):
                return _Exec({"data": _b64url(catalog[messageId]["attachments"][id])})

        return _Att()


class MultiQueryFakeGmailService:
    def __init__(self, catalog, inbox_ids, spam_ids):
        self._messages = _MultiQueryFakeMessages(catalog, inbox_ids, spam_ids)

    def users(self):
        return self

    def messages(self):
        return self._messages


def _plain_message(message_id, *, from_="Newsletter <news@example.com>", subject="Hello", body="Hi there"):
    return {
        "id": message_id,
        "threadId": message_id,
        "snippet": body[:80],
        "internalDate": "1751724862000",
        "payload": {
            "mimeType": "text/plain",
            "headers": [
                {"name": "From", "value": from_},
                {"name": "Subject", "value": subject},
            ],
            "body": {"data": _b64url(body.encode())},
        },
    }


class TestRunScanSpamCoverage:
    """Gmail's messages.list excludes Spam/Trash by default regardless of
    query terms, so malicious attachments landing straight in Spam would
    otherwise never reach the pipeline at all. run_scan must run an explicit
    'in:spam' pass and merge it in (deduped) unless include_spam=False."""

    def test_spam_messages_are_included_by_default(self, temp_env, monkeypatch):
        spam_message, spam_store = _message_with_attachment(
            "invoice.docm", fx.make_docm_with_macro(fx.AUTOOPEN_SHELL_MACRO)
        )
        spam_message["id"] = "spam-msg-1"
        inbox_message = _plain_message("inbox-msg-1")

        catalog = {
            "inbox-msg-1": {"message": inbox_message, "attachments": {}},
            "spam-msg-1": {"message": spam_message, "attachments": spam_store},
        }
        service = MultiQueryFakeGmailService(
            catalog, inbox_ids=["inbox-msg-1"], spam_ids=["spam-msg-1"]
        )
        monkeypatch.setattr(scanner, "get_gmail_service", lambda: service)

        result = scanner.run_scan(max_results=10, query="test")

        assert result["found"] == 2
        assert result["analyzed"] == 2
        processed_ids = {r["subject"] for r in result["results"]}
        assert processed_ids == {"Hello", "Invoice"}

        stored_ids = {row["gmail_message_id"] for row in storage.get_recent_results()}
        assert stored_ids == {"inbox-msg-1", "spam-msg-1"}

        # The spam message's malicious macro was actually analyzed, not just listed.
        spam_row = next(r for r in storage.get_recent_results() if r["gmail_message_id"] == "spam-msg-1")
        assert spam_row["verdict"] == "likely phishing"

    def test_include_spam_false_skips_the_spam_pass_entirely(self, temp_env, monkeypatch):
        spam_message, spam_store = _message_with_attachment(
            "invoice.docm", fx.make_docm_with_macro(fx.AUTOOPEN_SHELL_MACRO)
        )
        spam_message["id"] = "spam-msg-1"
        inbox_message = _plain_message("inbox-msg-1")

        catalog = {
            "inbox-msg-1": {"message": inbox_message, "attachments": {}},
            "spam-msg-1": {"message": spam_message, "attachments": spam_store},
        }
        service = MultiQueryFakeGmailService(
            catalog, inbox_ids=["inbox-msg-1"], spam_ids=["spam-msg-1"]
        )
        monkeypatch.setattr(scanner, "get_gmail_service", lambda: service)

        result = scanner.run_scan(max_results=10, query="test", include_spam=False)

        assert result["found"] == 1
        assert result["analyzed"] == 1
        assert storage.get_recent_results()[0]["gmail_message_id"] == "inbox-msg-1"

    def test_overlap_between_inbox_and_spam_results_is_deduped(self, temp_env, monkeypatch):
        # Simulates the FakeMessages-style stub used elsewhere in this file,
        # where the plain and spam-inclusive queries happen to return the same
        # id: it must be processed exactly once, not twice.
        message, store = _message_with_attachment("report.docx", fx.make_clean_docx())
        catalog = {"scan-msg-1": {"message": message, "attachments": store}}
        service = MultiQueryFakeGmailService(
            catalog, inbox_ids=["scan-msg-1"], spam_ids=["scan-msg-1"]
        )
        monkeypatch.setattr(scanner, "get_gmail_service", lambda: service)

        result = scanner.run_scan(max_results=10, query="test")

        assert result["found"] == 1
        assert result["analyzed"] == 1
        assert len(storage.get_recent_results()) == 1


class TestRunScanAttachmentPipeline:
    def test_malicious_attachment_yields_and_persists_likely_phishing(self, temp_env, monkeypatch):
        message, store = _message_with_attachment(
            "invoice.docm", fx.make_docm_with_macro(fx.AUTOOPEN_SHELL_MACRO)
        )

        result = _run_with_message(monkeypatch, message, store)

        # run_scan processed exactly this message with no errors.
        assert result["analyzed"] == 1
        assert result["errors"] == []

        # The verdict returned by run_scan reflects the attachment (body is
        # benign; the AutoOpen+Shell macro drives the score to 80).
        item = result["results"][0]
        assert item["verdict"] == "likely phishing"
        assert item["score"] == 80
        assert item["attachments"][0]["has_macros"] is True

        # And it was actually PERSISTED with that verdict (this is the part that
        # only run_scan -> save_result exercises, not score_email in isolation).
        stored = storage.get_recent_results()
        assert len(stored) == 1
        assert stored[0]["gmail_message_id"] == "scan-msg-1"
        assert stored[0]["verdict"] == "likely phishing"

        # The per-attachment finding is queryable per-email with its triggers.
        atts = storage.get_attachments_for_message("scan-msg-1")
        assert len(atts) == 1
        assert atts[0]["has_macros"] == 1
        assert atts[0]["filename"] == "invoice.docm"
        assert "AutoOpen" in atts[0]["macro_triggers"]["autoexec"]
        assert atts[0]["macro_triggers"]["shell"]

    def test_clean_attachment_stays_safe(self, temp_env, monkeypatch):
        message, store = _message_with_attachment("report.docx", fx.make_clean_docx())

        result = _run_with_message(monkeypatch, message, store)

        assert result["analyzed"] == 1
        assert result["errors"] == []
        item = result["results"][0]
        assert item["verdict"] == "safe"
        assert item["attachments"][0]["has_macros"] is False
        assert storage.get_recent_results()[0]["verdict"] == "safe"

    def test_already_scanned_message_is_skipped(self, temp_env, monkeypatch):
        message, store = _message_with_attachment(
            "invoice.docm", fx.make_docm_with_macro(fx.AUTOOPEN_SHELL_MACRO)
        )
        _run_with_message(monkeypatch, message, store)
        # Second run over the same message id must skip (idempotent), not
        # re-analyze or duplicate rows.
        result = _run_with_message(monkeypatch, message, store)
        assert result["analyzed"] == 0
        assert result["skipped"] == 1
        assert len(storage.get_attachments_for_message("scan-msg-1")) == 1
