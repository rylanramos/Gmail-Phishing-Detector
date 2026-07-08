"""Scoring tests for attachment-derived signals: pinned weights, the
structural full-weight convention (never discounted by the bulk-mail
mechanism), VirusTotal dominance, and an end-to-end run through the real
build_features -> analyze_attachments -> score_email pipeline.
"""

import pytest

from app import attachments, features, scorer
from fixtures import emails
from fixtures import attachments as fx


def make_features(**overrides):
    base = {
        "sender_domain": "example.com",
        "reply_to_domain": "",
        "from_replyto_mismatch": 0,
        "sender_uses_free_mail": 0,
        "contains_urgent_language": 0,
        "credential_lure_language": 0,
        "brand_keyword_presence": 0,
        "url_count": 0,
        "ip_url_count": 0,
        "suspicious_subdomain_count": 0,
        "link_text_href_mismatch_count": 0,
        "url_shortener_usage": 0,
        "punycode_domain": 0,
        "has_unsubscribe_header": 0,
        "has_list_id": 0,
        "has_bulk_precedence": 0,
        "newsletter_language": 0,
        "sender_root_matches_links": 0,
        "all_urls": [],
    }
    base.update(overrides)
    return base


def finding(**overrides):
    base = {
        "filename": "attachment.bin",
        "extension_mismatch": False,
        "has_macros": False,
        "macro_autoexec_triggers": [],
        "macro_shell_calls": [],
        "macro_obfuscation": False,
        "macro_urls": [],
        "macro_ips": [],
        "has_embedded_objects": False,
        "virustotal": None,
    }
    base.update(overrides)
    return base


class TestAttachmentWeights:
    def test_no_attachments_unchanged(self):
        assert scorer.score_email(make_features(), None)["score"] == 0
        assert scorer.score_email(make_features(), [])["score"] == 0

    def test_extension_mismatch_weight(self):
        result = scorer.score_email(make_features(), [finding(extension_mismatch=True)])
        assert result["score"] == 25

    def test_macro_presence_weight(self):
        result = scorer.score_email(make_features(), [finding(has_macros=True)])
        assert result["score"] == 25

    def test_macro_autoexec_only(self):
        result = scorer.score_email(
            make_features(),
            [finding(has_macros=True, macro_autoexec_triggers=["AutoOpen"])],
        )
        assert result["score"] == 35  # 25 macro + 10 autoexec

    def test_macro_shell_only(self):
        result = scorer.score_email(
            make_features(),
            [finding(has_macros=True, macro_shell_calls=["Shell"])],
        )
        assert result["score"] == 35  # 25 macro + 10 shell

    def test_autoexec_plus_shell_is_high_severity(self):
        result = scorer.score_email(
            make_features(),
            [finding(has_macros=True,
                     macro_autoexec_triggers=["AutoOpen"],
                     macro_shell_calls=["Shell"])],
        )
        # 25 macro + 10 autoexec + 10 shell + 35 combo = 80
        assert result["score"] == 80
        assert result["verdict"] == "likely phishing"

    def test_obfuscation_and_embedded_iocs_add(self):
        result = scorer.score_email(
            make_features(),
            [finding(has_macros=True, macro_obfuscation=True, macro_ips=["1.2.3.4"])],
        )
        assert result["score"] == 45  # 25 + 10 obf + 10 ioc

    def test_embedded_object_weight(self):
        result = scorer.score_email(make_features(), [finding(has_embedded_objects=True)])
        assert result["score"] == 15

    def test_virustotal_malicious_is_highest_signal(self):
        result = scorer.score_email(
            make_features(),
            [finding(virustotal={"available": True, "status": "malicious",
                                 "malicious": 40, "total": 70})],
        )
        assert result["score"] == 100
        assert result["verdict"] == "likely phishing"

    def test_virustotal_unknown_is_neutral(self):
        result = scorer.score_email(
            make_features(),
            [finding(virustotal={"available": True, "status": "unknown",
                                 "malicious": None, "total": None})],
        )
        assert result["score"] == 0

    def test_virustotal_harmless_is_neutral(self):
        result = scorer.score_email(
            make_features(),
            [finding(virustotal={"available": True, "status": "harmless",
                                 "malicious": 0, "total": 70})],
        )
        assert result["score"] == 0

    def test_virustotal_unavailable_is_neutral(self):
        result = scorer.score_email(
            make_features(),
            [finding(virustotal={"available": False, "status": "unavailable",
                                 "malicious": None, "total": None})],
        )
        assert result["score"] == 0

    def test_signals_sum_across_multiple_attachments(self):
        result = scorer.score_email(
            make_features(),
            [finding(extension_mismatch=True), finding(has_macros=True)],
        )
        assert result["score"] == 50  # 25 + 25


class TestAttachmentReasons:
    def test_reasons_name_the_attachment(self):
        result = scorer.score_email(
            make_features(),
            [finding(filename="invoice.docm", has_macros=True,
                     macro_autoexec_triggers=["AutoOpen"],
                     macro_shell_calls=["Shell"])],
        )
        joined = " ".join(result["reasons"])
        assert "invoice.docm" in joined
        assert "auto-execution" in joined and "shell" in joined

    def test_virustotal_reason_reports_engine_counts(self):
        result = scorer.score_email(
            make_features(),
            [finding(filename="x.bin", virustotal={"available": True,
                     "status": "malicious", "malicious": 40, "total": 70})],
        )
        assert any("40 of 70 engines" in r for r in result["reasons"])


class TestStructuralFullWeightConvention:
    """Attachment malicious indicators are structural: the bulk-mail
    trusted-context discount and newsletter deductions must never reduce them."""

    def test_macro_immune_to_newsletter_framing(self):
        newsletter = make_features(
            has_unsubscribe_header=1, has_list_id=1, has_bulk_precedence=1,
            newsletter_language=1, sender_root_matches_links=1,
        )
        risky = [finding(has_macros=True,
                         macro_autoexec_triggers=["AutoOpen"],
                         macro_shell_calls=["Shell"])]

        bare = scorer.score_email(make_features(), risky)["score"]
        framed = scorer.score_email(newsletter, risky)["score"]

        # Identical: the newsletter deduction floors the body score at 0 first,
        # so it cannot eat into the attachment signal.
        assert bare == framed == 80

    def test_virustotal_hit_survives_newsletter_framing(self):
        newsletter = make_features(
            has_unsubscribe_header=1, has_list_id=1, has_bulk_precedence=1,
            newsletter_language=1, sender_root_matches_links=1,
        )
        vt = [finding(virustotal={"available": True, "status": "malicious",
                                  "malicious": 50, "total": 72})]
        result = scorer.score_email(newsletter, vt)
        assert result["score"] == 100
        assert result["verdict"] == "likely phishing"

    def test_body_and_attachment_signals_combine(self):
        result = scorer.score_email(
            make_features(from_replyto_mismatch=1),
            [finding(has_macros=True,
                     macro_autoexec_triggers=["AutoOpen"],
                     macro_shell_calls=["Shell"])],
        )
        assert result["score"] == 110  # 30 body + 80 attachment

    def test_newsletter_framing_does_not_suppress_weaponized_attachment_end_to_end(self):
        """End-to-end proof of the scoring-ORDER fix through the real
        build_features -> analyze_attachments -> score_email pipeline.

        legit_marketing_newsletter is a fully-formed bulk newsletter that scores
        exactly 0 on its own: its body signals net to zero and it carries the
        maximum newsletter deduction (List-Unsubscribe + List-Id + Precedence:
        bulk + newsletter language + same-domain links = -46 before the floor).

        Attach a real, statically-extractable AutoOpen + Shell macro document
        (worth +80) to that same message. Because attachment signals are added
        only AFTER the email-body score is floored at zero, the -46 newsletter
        deduction cannot bleed into the attachment score:

            body = max(0, 0 - 46) = 0;  0 + 80 = 80  ->  likely phishing

        If the order were reversed (attachment added before the floor), the
        deduction would drag the total to 0 - 46 + 80 = 34 ("suspicious"),
        letting newsletter framing buy down a weaponized attachment. This test
        pins the score at 80 to lock the correct order in place.
        """
        # Control: the newsletter alone is safe/0 through the real pipeline.
        control = scorer.score_email(
            features.build_features(emails.legit_marketing_newsletter()), []
        )
        assert control["score"] == 0
        assert control["verdict"] == "safe"

        # Same newsletter, now carrying a weaponized attachment.
        parsed = emails.legit_marketing_newsletter()
        parsed["attachments"] = [
            fx.attachment(
                "summer-sale-invoice.docm",
                fx.make_docm_with_macro(fx.AUTOOPEN_SHELL_MACRO),
            )
        ]
        feats = features.build_features(parsed)
        att_findings = attachments.analyze_attachments(parsed["attachments"])

        # Sanity-check the fixture really produced the high-risk macro signal.
        assert att_findings[0]["has_macros"] is True
        assert att_findings[0]["macro_autoexec_triggers"] == ["AutoOpen"]
        assert att_findings[0]["macro_shell_calls"]

        result = scorer.score_email(feats, att_findings)

        # 80, not 34: the newsletter deduction did not suppress the attachment.
        assert result["score"] == 80
        assert result["verdict"] == "likely phishing"
        assert any("auto-execution" in r and "shell" in r for r in result["reasons"])


class TestEndToEndPipeline:
    def _run(self, parsed):
        feats = features.build_features(parsed)
        att = attachments.analyze_attachments(parsed.get("attachments", []))
        return scorer.score_email(feats, att)

    def test_clean_attachment_stays_safe(self):
        parsed = fx.parsed_email_with_attachments(
            [fx.attachment("report.docx", fx.make_clean_docx())]
        )
        result = self._run(parsed)
        assert result["verdict"] == "safe"

    def test_high_risk_macro_reaches_likely_phishing(self):
        parsed = fx.parsed_email_with_attachments(
            [fx.attachment("invoice.docm", fx.make_docm_with_macro(fx.AUTOOPEN_SHELL_MACRO))]
        )
        result = self._run(parsed)
        assert result["verdict"] == "likely phishing"
        assert any("auto-execution" in r for r in result["reasons"])

    def test_extension_mismatch_pipeline(self):
        parsed = fx.parsed_email_with_attachments(
            [fx.attachment("Invoice_2026.pdf", fx.make_fake_executable())]
        )
        result = self._run(parsed)
        assert any("does not match" in r for r in result["reasons"])
