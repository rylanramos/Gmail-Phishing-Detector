"""Unit tests for app.scorer.score_email: signal weights, the trusted-context
discount, newsletter deductions, score clamping, and verdict thresholds."""

import pytest

from app import scorer


def make_features(**overrides):
    """A parsed message with no signals at all; override per test."""
    base = {
        "sender_domain": "example.com",
        "reply_to_domain": "",
        "from_replyto_mismatch": 0,
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


class TestIndividualWeights:
    def test_no_signals_scores_zero_safe(self):
        result = scorer.score_email(make_features())
        assert result == {"score": 0, "verdict": "safe", "reasons": []}

    @pytest.mark.parametrize(
        "overrides, expected_score",
        [
            ({"from_replyto_mismatch": 1}, 30),
            ({"ip_url_count": 1}, 35),
            ({"punycode_domain": 1}, 30),
            ({"link_text_href_mismatch_count": 1}, 20),
            ({"suspicious_subdomain_count": 1}, 10),
            ({"url_shortener_usage": 1}, 15),
            ({"credential_lure_language": 1}, 25),
            ({"contains_urgent_language": 1}, 15),
            ({"url_count": 8}, 5),
        ],
        ids=[
            "replyto-mismatch",
            "ip-url",
            "punycode",
            "anchor-mismatch",
            "suspicious-subdomain",
            "shortener",
            "credential-lure",
            "urgent-language",
            "many-links",
        ],
    )
    def test_single_signal_weight(self, overrides, expected_score):
        result = scorer.score_email(make_features(**overrides))
        assert result["score"] == expected_score

    def test_brand_keyword_alone_scores_nothing(self):
        result = scorer.score_email(make_features(brand_keyword_presence=1))
        assert result["score"] == 0

    def test_brand_plus_credential_lure_bonus(self):
        result = scorer.score_email(
            make_features(brand_keyword_presence=1, credential_lure_language=1)
        )
        assert result["score"] == 45  # 25 lure + 20 brand-combo bonus
        assert "Brand language combined with credential lure detected" in result["reasons"]


class TestTrustedContextDiscount:
    """Language signals collapse in a trusted context; structural ones don't.

    Bulk headers each also carry a newsletter deduction, so the discounted
    variants pair the language signal with a fixed structural signal
    (punycode, +30) to keep scores positive and comparable.
    """

    def test_credential_lure_discounted_by_bulk_header(self):
        untrusted = scorer.score_email(
            make_features(punycode_domain=1, credential_lure_language=1)
        )
        trusted = scorer.score_email(
            make_features(punycode_domain=1, credential_lure_language=1, has_list_id=1)
        )
        assert untrusted["score"] == 55  # 30 + 25
        assert trusted["score"] == 27  # 30 + 5 - 8
        assert "Credential or account-verification language detected" not in trusted["reasons"]

    def test_urgent_language_discounted_by_bulk_precedence(self):
        untrusted = scorer.score_email(
            make_features(punycode_domain=1, contains_urgent_language=1)
        )
        trusted = scorer.score_email(
            make_features(punycode_domain=1, contains_urgent_language=1, has_bulk_precedence=1)
        )
        assert untrusted["score"] == 45  # 30 + 15
        assert trusted["score"] == 27  # 30 + 3 - 6
        assert "Urgent or account-pressure language detected" not in trusted["reasons"]

    def test_shortener_discounted_by_same_domain_links(self):
        untrusted = scorer.score_email(
            make_features(punycode_domain=1, url_shortener_usage=1)
        )
        trusted = scorer.score_email(
            make_features(punycode_domain=1, url_shortener_usage=1, sender_root_matches_links=1)
        )
        assert untrusted["score"] == 45  # 30 + 15
        assert trusted["score"] == 23  # 30 + 5 - 12
        assert "URL shortener detected" not in trusted["reasons"]

    def test_brand_combo_bonus_suppressed_in_trusted_context(self):
        result = scorer.score_email(
            make_features(
                punycode_domain=1,
                brand_keyword_presence=1,
                credential_lure_language=1,
                has_list_id=1,
            )
        )
        assert result["score"] == 27  # 30 + 5 - 8, no +20 combo
        assert "Brand language combined with credential lure detected" not in result["reasons"]

    def test_many_links_signal_skipped_for_bulk_mail(self):
        bulk = scorer.score_email(
            make_features(punycode_domain=1, url_count=12, has_list_id=1)
        )
        assert bulk["score"] == 22  # 30 - 8, no +5 for link count
        assert "Large number of links in message" not in bulk["reasons"]

    @pytest.mark.parametrize(
        "overrides",
        [
            {"from_replyto_mismatch": 1},
            {"ip_url_count": 1},
            {"punycode_domain": 1},
            {"link_text_href_mismatch_count": 1},
        ],
        ids=["replyto-mismatch", "ip-url", "punycode", "anchor-mismatch"],
    )
    def test_structural_signals_never_discounted(self, overrides):
        untrusted = scorer.score_email(make_features(**overrides))
        trusted = scorer.score_email(make_features(**overrides, has_list_id=1))
        # Same full weight, minus only the flat List-Id deduction (8).
        assert trusted["score"] == untrusted["score"] - 8


class TestNewsletterDeductions:
    @pytest.mark.parametrize(
        "overrides, deduction",
        [
            ({"has_unsubscribe_header": 1}, 10),
            ({"has_list_id": 1}, 8),
            ({"has_bulk_precedence": 1}, 6),
            ({"newsletter_language": 1}, 10),
            ({"sender_root_matches_links": 1}, 12),
        ],
        ids=["unsubscribe", "list-id", "precedence", "newsletter-language", "same-domain-links"],
    )
    def test_each_deduction_amount(self, overrides, deduction):
        # Anchor on a structural +30 so the deduction is observable.
        result = scorer.score_email(make_features(punycode_domain=1, **overrides))
        assert result["score"] == 30 - deduction
        assert "Legitimate mailing-list or newsletter indicators detected" in result["reasons"]

    def test_score_clamped_at_zero(self):
        result = scorer.score_email(
            make_features(
                has_unsubscribe_header=1,
                has_list_id=1,
                has_bulk_precedence=1,
                newsletter_language=1,
                sender_root_matches_links=1,
            )
        )
        assert result["score"] == 0
        assert result["verdict"] == "safe"


class TestVerdictThresholds:
    @pytest.mark.parametrize(
        "overrides, expected_score, expected_verdict",
        [
            # Below 30: safe
            ({"link_text_href_mismatch_count": 1}, 20, "safe"),
            ({"credential_lure_language": 1}, 25, "safe"),
            # Exactly 30: suspicious
            ({"from_replyto_mismatch": 1}, 30, "suspicious"),
            # Just below 60: still suspicious
            ({"ip_url_count": 1, "link_text_href_mismatch_count": 1}, 55, "suspicious"),
            # Exactly 60: likely phishing
            ({"ip_url_count": 1, "credential_lure_language": 1}, 60, "likely phishing"),
            # Far above 60
            (
                {
                    "from_replyto_mismatch": 1,
                    "ip_url_count": 1,
                    "punycode_domain": 1,
                    "credential_lure_language": 1,
                },
                120,
                "likely phishing",
            ),
        ],
        ids=["safe-20", "safe-25", "suspicious-30", "suspicious-55", "phishing-60", "phishing-120"],
    )
    def test_threshold_boundaries(self, overrides, expected_score, expected_verdict):
        result = scorer.score_email(make_features(**overrides))
        assert result["score"] == expected_score
        assert result["verdict"] == expected_verdict


class TestFraudulentBulkHeaders:
    def test_fake_unsubscribe_cannot_buy_down_structural_signals(self):
        """A phisher adding List-Unsubscribe gets the language discount and a
        -10 deduction, but structural signals keep the verdict at likely
        phishing."""
        result = scorer.score_email(
            make_features(
                from_replyto_mismatch=1,
                punycode_domain=1,
                link_text_href_mismatch_count=1,
                credential_lure_language=1,
                contains_urgent_language=1,
                has_unsubscribe_header=1,
            )
        )
        assert result["score"] == 78  # 30 + 30 + 20 + 5 + 3 - 10
        assert result["verdict"] == "likely phishing"
        for reason in [
            "From and Reply-To domains do not match",
            "Punycode domain detected",
            "Displayed domain text does not match destination domain",
        ]:
            assert reason in result["reasons"]
