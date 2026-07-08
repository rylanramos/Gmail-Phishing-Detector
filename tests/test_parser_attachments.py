"""Tests for the attachment-extraction path added to app.parser.

The parser previously discarded every non-text/html MIME part; these tests
cover the new extract_attachments / fetch_attachment_content / parse_message
attachment handling using a fake Gmail service (no network).
"""

import base64

import pytest

from app import parser


def _b64url(raw):
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


class FakeAttachmentsResource:
    def __init__(self, store):
        self._store = store

    def get(self, userId, messageId, id):
        data = self._store[id]

        class _Exec:
            def execute(_self):
                return {"data": _b64url(data)}

        return _Exec()


class FakeMessagesResource:
    def __init__(self, message, attachment_store):
        self._message = message
        self._attachments = FakeAttachmentsResource(attachment_store)

    def get(self, userId, id, format):
        message = self._message

        class _Exec:
            def execute(_self):
                return message

        return _Exec()

    def attachments(self):
        return self._attachments


class FakeService:
    def __init__(self, message, attachment_store=None):
        self._messages = FakeMessagesResource(message, attachment_store or {})

    def users(self):
        return self

    def messages(self):
        return self._messages


class TestExtractAttachments:
    def test_finds_attachment_parts_by_filename(self):
        payload = {
            "mimeType": "multipart/mixed",
            "parts": [
                {"mimeType": "text/plain", "body": {"data": _b64url(b"hi")}},
                {"mimeType": "application/pdf", "filename": "invoice.pdf",
                 "body": {"attachmentId": "att1", "size": 1234}},
            ],
        }
        result = parser.extract_attachments(payload)
        assert len(result) == 1
        assert result[0]["filename"] == "invoice.pdf"
        assert result[0]["attachment_id"] == "att1"

    def test_recurses_into_nested_parts(self):
        payload = {
            "parts": [
                {"parts": [
                    {"filename": "deep.docx", "mimeType": "application/octet-stream",
                     "body": {"attachmentId": "x"}},
                ]},
            ],
        }
        result = parser.extract_attachments(payload)
        assert [a["filename"] for a in result] == ["deep.docx"]

    def test_ignores_parts_without_filename(self):
        payload = {"mimeType": "text/html", "body": {"data": _b64url(b"<p>x</p>")}}
        assert parser.extract_attachments(payload) == []


class TestDecodeAttachmentData:
    def test_decodes_binary_with_missing_padding(self):
        raw = b"\xD0\xCF\x11\xE0binarydata"
        assert parser.decode_attachment_data(_b64url(raw)) == raw

    def test_empty_returns_empty_bytes(self):
        assert parser.decode_attachment_data("") == b""

    def test_invalid_returns_empty_bytes(self):
        assert parser.decode_attachment_data("!!!not base64!!!") == b""


class TestFetchAttachmentContent:
    def test_inline_data_used_directly(self):
        service = FakeService({"id": "m1", "payload": {}})
        att = {"inline_data": _b64url(b"inline-bytes"), "attachment_id": None}
        assert parser.fetch_attachment_content(service, "m1", att) == b"inline-bytes"

    def test_attachment_id_fetched(self):
        service = FakeService({"id": "m1", "payload": {}},
                              attachment_store={"att1": b"fetched-bytes"})
        att = {"inline_data": None, "attachment_id": "att1"}
        assert parser.fetch_attachment_content(service, "m1", att) == b"fetched-bytes"


class TestParseMessageAttachments:
    def test_parse_message_includes_resolved_attachments(self):
        raw = b"%PDF-1.5 fake pdf bytes"
        message = {
            "id": "m1",
            "threadId": "t1",
            "snippet": "see attached",
            "internalDate": "1751724862000",
            "payload": {
                "mimeType": "multipart/mixed",
                "headers": [
                    {"name": "From", "value": "sender@example.com"},
                    {"name": "Subject", "value": "Invoice"},
                ],
                "parts": [
                    {"mimeType": "text/plain", "body": {"data": _b64url(b"body")}},
                    {"mimeType": "application/pdf", "filename": "invoice.pdf",
                     "body": {"attachmentId": "att1", "size": len(raw)}},
                ],
            },
        }
        service = FakeService(message, attachment_store={"att1": raw})

        parsed = parser.parse_message(service, "m1")

        assert len(parsed["attachments"]) == 1
        att = parsed["attachments"][0]
        assert att["filename"] == "invoice.pdf"
        assert att["content"] == raw

    def test_message_without_attachments_has_empty_list(self):
        message = {
            "id": "m2",
            "threadId": "t2",
            "snippet": "",
            "payload": {
                "mimeType": "text/plain",
                "headers": [{"name": "From", "value": "a@b.com"}],
                "body": {"data": _b64url(b"hello")},
            },
        }
        service = FakeService(message)
        parsed = parser.parse_message(service, "m2")
        assert parsed["attachments"] == []
