"""End-to-end scoring tests: every fixture is run through the real
build_features -> score_email pipeline and checked against the exact score
and verdict it should receive.

The exact scores double as documentation of how each scenario decomposes
into signal weights; see the fixture docstrings in fixtures/emails.py for
the arithmetic.
"""

import pytest

from app import features, scorer
from fixtures import emails


def run_pipeline(parsed_email):
    return scorer.score_email(features.build_features(parsed_email))


@pytest.mark.parametrize(
    "fixture, expected_score, expected_verdict",
    [
        # --- Single phishing signals in isolation ---
        (emails.phishing_reply_to_mismatch_only, 30, "suspicious"),
        (emails.phishing_punycode_link_only, 30, "suspicious"),
        (emails.phishing_punycode_subdomain, 30, "suspicious"),
        (emails.phishing_ip_url_only, 35, "suspicious"),
        # A single anchor/href mismatch (20) or undiscounted credential lure
        # (25) sits below the suspicious threshold by design: one weak-to-mid
        # signal alone is not enough to flag a message.
        (emails.phishing_anchor_text_mismatch_only, 20, "safe"),
        (emails.phishing_credential_lure_no_bulk, 25, "safe"),
        # --- Phishing signal combinations ---
        (emails.phishing_lure_urgent_brand, 60, "likely phishing"),
        (emails.phishing_fake_unsubscribe, 78, "likely phishing"),
        (emails.phishing_multi_signal, 160, "likely phishing"),
        # --- Legitimate mail ---
        (emails.legit_bulk_with_lure_language, 0, "safe"),
        (emails.legit_marketing_newsletter, 0, "safe"),
        (emails.legit_transactional_receipt, 0, "safe"),
        (emails.legit_shipping_notification, 0, "safe"),
        (emails.legit_personal_email, 0, "safe"),
        (emails.legit_security_newsletter, 0, "safe"),
        # --- Threshold boundary probes ---
        (emails.boundary_shortener_plus_urgent, 30, "suspicious"),
        (emails.boundary_ip_plus_credential_lure, 60, "likely phishing"),
        (emails.boundary_ip_plus_anchor_mismatch, 55, "suspicious"),
    ],
    ids=lambda value: value.__name__ if callable(value) else None,
)
def test_fixture_scores_and_verdicts(fixture, expected_score, expected_verdict):
    result = run_pipeline(fixture())
    assert result["score"] == expected_score
    assert result["verdict"] == expected_verdict


class TestBulkDiscountMechanism:
    def test_identical_lure_copy_diverges_on_context(self):
        """The same lure-heavy copy must be likely phishing from a lookalike
        sender and safe from the brand's real bulk infrastructure."""
        phish = run_pipeline(emails.phishing_lure_urgent_brand())
        legit = run_pipeline(emails.legit_bulk_with_lure_language())

        assert phish["verdict"] == "likely phishing"
        assert legit["verdict"] == "safe"

    def test_fake_unsubscribe_header_does_not_rescue_phish(self):
        """Gaming the discount with a fraudulent List-Unsubscribe header must
        not suppress full-weight structural signals."""
        result = run_pipeline(emails.phishing_fake_unsubscribe())

        assert result["verdict"] == "likely phishing"
        assert result["score"] >= 60
        for reason in [
            "From and Reply-To domains do not match",
            "Punycode domain detected",
            "Displayed domain text does not match destination domain",
        ]:
            assert reason in result["reasons"]

    def test_historical_isc2_false_positive_stays_fixed(self):
        """A security-topic newsletter with brand keywords and 'security
        alert' wording — the original false-positive bug — must stay safe."""
        result = run_pipeline(emails.legit_security_newsletter())

        assert result["score"] == 0
        assert result["verdict"] == "safe"


class TestReasons:
    def test_multi_signal_phish_reports_every_fired_signal(self):
        result = run_pipeline(emails.phishing_multi_signal())

        assert set(result["reasons"]) == {
            "From and Reply-To domains do not match",
            "One or more URLs use a raw IP address",
            "Displayed domain text does not match destination domain",
            "URL shortener detected",
            "Credential or account-verification language detected",
            "Urgent or account-pressure language detected",
            "Brand language combined with credential lure detected",
        }

    def test_clean_personal_email_reports_no_reasons(self):
        result = run_pipeline(emails.legit_personal_email())
        assert result["reasons"] == []
