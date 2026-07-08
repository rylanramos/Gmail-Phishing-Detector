"""Unit tests for app.attachments: static file-type detection, extension
mismatch, SHA-256, VBA macro indicator extraction (via real olevba parsing of
synthetic OLE/OOXML fixtures), embedded-object detection, and graceful
degradation. No attachment is ever executed or opened in an interpreter.
"""

import hashlib

import pytest

from app import attachments
from fixtures import attachments as fx


# ---------------------------------------------------------------------------
# File-type detection (magic bytes, independent of filename)
# ---------------------------------------------------------------------------

class TestDetectFileType:
    def test_ole_signature(self):
        assert attachments.detect_file_type(fx.make_ole_with_vba(fx.BENIGN_MACRO)) == "ole"

    def test_ooxml_docx(self):
        assert attachments.detect_file_type(fx.make_clean_docx()) == "docx"

    def test_executable(self):
        assert attachments.detect_file_type(fx.make_fake_executable()) == "exe"

    def test_png(self):
        assert attachments.detect_file_type(fx.make_png_bytes()) == "png"

    def test_pdf(self):
        assert attachments.detect_file_type(fx.make_pdf_bytes()) == "pdf"

    def test_empty_is_none(self):
        assert attachments.detect_file_type(b"") is None

    def test_unrecognized_is_none(self):
        assert attachments.detect_file_type(b"just some plain text bytes") is None


class TestClaimedExtension:
    @pytest.mark.parametrize("name, ext", [
        ("invoice.PDF", "pdf"),
        ("archive.tar.gz", "gz"),
        ("report.docx", "docx"),
        ("noext", ""),
        ("", ""),
    ])
    def test_extension_parsing(self, name, ext):
        assert attachments.claimed_extension(name) == ext


class TestExtensionMismatch:
    def test_executable_named_pdf_is_mismatch(self):
        assert attachments.extension_mismatch("Invoice_2026.pdf", "exe") is True

    def test_image_named_pdf_is_mismatch(self):
        assert attachments.extension_mismatch("photo.pdf", "png") is True

    def test_matching_docx_is_not_mismatch(self):
        assert attachments.extension_mismatch("report.docx", "docx") is False

    def test_ole_named_doc_is_not_mismatch(self):
        # A legacy .doc is an OLE file: same 'office' family, no mismatch.
        assert attachments.extension_mismatch("legacy.doc", "ole") is False

    def test_docm_detected_as_docx_is_not_mismatch(self):
        # filetype reports macro-enabled OOXML as 'docx'; both are 'office'.
        assert attachments.extension_mismatch("macro.docm", "docx") is False

    def test_unknown_detected_type_never_mismatch(self):
        assert attachments.extension_mismatch("thing.pdf", None) is False

    def test_zip_ambiguity_never_mismatch(self):
        # A real .docx *is* a zip; a 'zip' detection must not false-positive.
        assert attachments.extension_mismatch("report.docx", "zip") is False


class TestSha256:
    def test_matches_hashlib(self):
        content = b"attachment bytes"
        assert attachments.compute_sha256(content) == hashlib.sha256(content).hexdigest()

    def test_empty(self):
        assert attachments.compute_sha256(b"") == hashlib.sha256(b"").hexdigest()


# ---------------------------------------------------------------------------
# VBA macro indicator analysis (on source strings)
# ---------------------------------------------------------------------------

class TestAnalyzeVbaCode:
    def test_autoopen_and_shell_detected(self):
        result = attachments.analyze_vba_code(fx.AUTOOPEN_SHELL_MACRO)
        assert "AutoOpen" in result["autoexec_triggers"]
        assert "Shell" in result["shell_calls"]
        assert "WScript.Shell" in result["shell_calls"]
        assert "CreateObject" in result["shell_calls"]

    def test_benign_macro_has_no_risky_calls(self):
        result = attachments.analyze_vba_code(fx.BENIGN_MACRO)
        assert result["autoexec_triggers"] == []
        assert result["shell_calls"] == []
        assert result["obfuscation"] is False

    def test_obfuscation_indicators_detected(self):
        result = attachments.analyze_vba_code(fx.OBFUSCATED_MACRO)
        assert result["obfuscation"] is True
        assert result["obfuscation_details"]  # non-empty

    def test_embedded_url_and_ip_extracted(self):
        result = attachments.analyze_vba_code(fx.OBFUSCATED_MACRO)
        assert "http://203.0.113.55/payload" in result["urls"]
        assert "203.0.113.55" in result["ips"]

    def test_keyword_matching_is_case_insensitive(self):
        result = attachments.analyze_vba_code("sub autoopen()\n  shell \"x\"\nend sub")
        assert result["autoexec_triggers"] == ["AutoOpen"]
        assert result["shell_calls"] == ["Shell"]

    def test_empty_code(self):
        result = attachments.analyze_vba_code("")
        assert result["autoexec_triggers"] == []
        assert result["shell_calls"] == []
        assert result["urls"] == []


# ---------------------------------------------------------------------------
# Office macro extraction via real olevba static parsing
# ---------------------------------------------------------------------------

class TestExtractOfficeMacros:
    def test_clean_docx_has_no_macros(self):
        result = attachments.extract_office_macros(fx.make_clean_docx(), "clean.docx")
        assert result["has_macros"] is False
        assert result["error"] is None

    def test_benign_docm_macro_extracted(self):
        result = attachments.extract_office_macros(
            fx.make_docm_with_macro(fx.BENIGN_MACRO), "quarterly.docm"
        )
        assert result["has_macros"] is True
        assert "FormatCells" in result["code"]

    def test_risky_ole_macro_extracted(self):
        result = attachments.extract_office_macros(
            fx.make_ole_with_vba(fx.AUTOOPEN_SHELL_MACRO), "notes.doc"
        )
        assert result["has_macros"] is True
        assert "AutoOpen" in result["code"]
        assert "Shell" in result["code"]

    def test_corrupt_office_bytes_degrade(self):
        # Looks office-ish by name but the bytes are garbage: no crash.
        result = attachments.extract_office_macros(b"PK\x03\x04garbage", "broken.docx")
        assert result["has_macros"] is False


class TestEmbeddedObjects:
    def test_docx_with_embedded_object_detected(self):
        content = fx.make_docx_with_embedded_object()
        assert attachments.detect_embedded_objects(content, "docx") is True

    def test_clean_docx_has_no_embedded_objects(self):
        assert attachments.detect_embedded_objects(fx.make_clean_docx(), "docx") is False


# ---------------------------------------------------------------------------
# Full per-attachment orchestration
# ---------------------------------------------------------------------------

class TestAnalyzeAttachment:
    def test_clean_docx(self):
        finding = attachments.analyze_attachment(
            fx.attachment("report.docx", fx.make_clean_docx())
        )
        assert finding["detected_type"] == "docx"
        assert finding["has_macros"] is False
        assert finding["extension_mismatch"] is False
        assert finding["sha256"]
        assert finding["virustotal"] is None  # no client supplied

    def test_high_risk_macro_document(self):
        finding = attachments.analyze_attachment(
            fx.attachment("invoice.docm", fx.make_docm_with_macro(fx.AUTOOPEN_SHELL_MACRO))
        )
        assert finding["has_macros"] is True
        assert finding["macro_autoexec_triggers"] == ["AutoOpen"]
        assert "Shell" in finding["macro_shell_calls"]

    def test_extension_mismatch_flagged(self):
        finding = attachments.analyze_attachment(
            fx.attachment("Invoice_2026.pdf", fx.make_fake_executable())
        )
        assert finding["detected_type"] == "exe"
        assert finding["extension_mismatch"] is True
        assert finding["has_macros"] is False

    def test_virustotal_client_consulted(self):
        class StubVT:
            def lookup_hash(self, sha256):
                return {"available": True, "status": "malicious",
                        "malicious": 40, "total": 70}

        finding = attachments.analyze_attachment(
            fx.attachment("report.docx", fx.make_clean_docx()), vt_client=StubVT()
        )
        assert finding["virustotal"]["status"] == "malicious"
        assert finding["virustotal"]["malicious"] == 40

    def test_virustotal_failure_never_crashes(self):
        class BoomVT:
            def lookup_hash(self, sha256):
                raise RuntimeError("network down")

        finding = attachments.analyze_attachment(
            fx.attachment("report.docx", fx.make_clean_docx()), vt_client=BoomVT()
        )
        # Degrades to unavailable rather than propagating.
        assert finding["virustotal"]["available"] is False


class TestAnalyzeAttachments:
    def test_multiple_attachments(self):
        findings = attachments.analyze_attachments([
            fx.attachment("a.docx", fx.make_clean_docx()),
            fx.attachment("b.docm", fx.make_docm_with_macro(fx.AUTOOPEN_SHELL_MACRO)),
        ])
        assert len(findings) == 2
        assert findings[0]["has_macros"] is False
        assert findings[1]["has_macros"] is True

    def test_empty_list(self):
        assert attachments.analyze_attachments([]) == []

    def test_one_bad_attachment_does_not_abort_others(self, monkeypatch):
        # Force analysis of the first attachment to raise; the second must still
        # be analyzed and both must appear in the results.
        original = attachments.analyze_attachment
        calls = {"n": 0}

        def flaky(attachment, vt_client=None):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("kaboom")
            return original(attachment, vt_client=vt_client)

        monkeypatch.setattr(attachments, "analyze_attachment", flaky)
        findings = attachments.analyze_attachments([
            fx.attachment("bad.docx", fx.make_clean_docx()),
            fx.attachment("good.docx", fx.make_clean_docx()),
        ])
        assert len(findings) == 2
        assert findings[0]["analysis_errors"] == ["analysis_error"]
