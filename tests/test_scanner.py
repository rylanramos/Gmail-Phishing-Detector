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
