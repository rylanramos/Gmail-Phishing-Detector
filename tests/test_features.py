"""Unit tests for app.features: individual signal extractors and the
build_features() pipeline over realistic parsed-email fixtures."""

import pytest

from app import features
from fixtures import emails


class TestGetDomainFromEmailHeader:
    def test_display_name_form(self):
        header = '"Meridian Support" <support@meridiancu-notices.com>'
        assert features.get_domain_from_email_header(header) == "meridiancu-notices.com"

    def test_bare_address(self):
        assert features.get_domain_from_email_header("alice@example.com") == "example.com"

    def test_subdomain_preserved(self):
        assert features.get_domain_from_email_header("x@mail.news.example.com") == "mail.news.example.com"

    def test_uppercase_is_lowered(self):
        assert features.get_domain_from_email_header("Bob@EXAMPLE.COM") == "example.com"

    @pytest.mark.parametrize("value", ["", None, "no address here"])
    def test_missing_or_invalid(self, value):
        assert features.get_domain_from_email_header(value) == ""


class TestGetRegisteredDomain:
    def test_collapses_subdomains(self):
        assert features.get_registered_domain("www.paypal.com") == "paypal.com"

    def test_multi_part_suffix(self):
        assert features.get_registered_domain("mail.example.co.uk") == "example.co.uk"

    def test_plain_domain_unchanged(self):
        assert features.get_registered_domain("example.com") == "example.com"

    def test_empty(self):
        assert features.get_registered_domain("") == ""


class TestGetDomainFromUrl:
    def test_hostname_extracted_and_lowered(self):
        assert features.get_domain_from_url("https://Secure.Example.COM/a/b?c=1") == "secure.example.com"

    def test_no_hostname(self):
        assert features.get_domain_from_url("not a url") == ""


class TestUrlUsesIp:
    def test_http_ip(self):
        assert features.url_uses_ip("http://185.220.101.44/invoices")

    def test_https_ip(self):
        assert features.url_uses_ip("https://203.0.113.88/portal")

    def test_normal_domain(self):
        assert not features.url_uses_ip("https://example.com/185.220.101.44")

    def test_empty(self):
        assert not features.url_uses_ip("")


class TestExcessiveSubdomains:
    def test_deep_subdomain_chain(self):
        assert features.excessive_subdomains("login.secure.account.example.com")

    def test_normal_www_host(self):
        assert not features.excessive_subdomains("www.example.com")

    def test_ipv4_hostname_is_not_a_subdomain_chain(self):
        # Regression: an IPv4 literal has exactly three dots and used to be
        # double-counted on top of the dedicated IP-URL signal.
        assert not features.excessive_subdomains("185.220.101.44")

    def test_empty(self):
        assert not features.excessive_subdomains("")


class TestLinkTextHrefMismatch:
    def test_mismatching_domains_counted(self):
        anchors = [{"text": "canadapost.ca", "href": "http://parcel-redelivery-portal.com/track"}]
        assert features.link_text_href_mismatch(anchors) == 1

    def test_matching_bare_domain(self):
        anchors = [{"text": "paypal.com", "href": "https://paypal.com/signin"}]
        assert features.link_text_href_mismatch(anchors) == 0

    def test_matching_www_prefixed_text(self):
        # Regression: "www.paypal.com" used to be extracted as "www.paypal",
        # which never equals the href's registered domain, so legitimate
        # domain-shaped anchor text was flagged as a mismatch.
        anchors = [{"text": "www.paypal.com", "href": "https://www.paypal.com/signin"}]
        assert features.link_text_href_mismatch(anchors) == 0

    def test_domain_inside_sentence(self):
        anchors = [{"text": "Visit chase.com for details", "href": "http://chase-secure-center.com/login"}]
        assert features.link_text_href_mismatch(anchors) == 1

    def test_non_domain_text_ignored(self):
        anchors = [{"text": "Click here", "href": "http://anything-at-all.com/x"}]
        assert features.link_text_href_mismatch(anchors) == 0

    def test_non_http_href_ignored(self):
        anchors = [{"text": "support@example.com", "href": "mailto:support@example.com"}]
        assert features.link_text_href_mismatch(anchors) == 0

    def test_empty_text_ignored(self):
        anchors = [{"text": "", "href": "http://example.com"}]
        assert features.link_text_href_mismatch(anchors) == 0

    def test_multiple_mismatches_accumulate(self):
        anchors = [
            {"text": "interac.ca", "href": "http://91.203.67.44/claim"},
            {"text": "www.isc2.org", "href": "https://xn--isc-1na2b.com/verify"},
            {"text": "Track order", "href": "https://example.com/track"},
        ]
        assert features.link_text_href_mismatch(anchors) == 2


class TestHasShortener:
    def test_known_shortener(self):
        assert features.has_shortener(["https://bit.ly/3fastclaim"])

    def test_shortener_with_www(self):
        assert features.has_shortener(["https://www.tinyurl.com/abc"])

    def test_normal_urls(self):
        assert not features.has_shortener(["https://example.com/a", "https://example.org/b"])

    def test_empty(self):
        assert not features.has_shortener([])


class TestHasPunycode:
    def test_punycode_registered_domain(self):
        assert features.has_punycode(["xn--pypal-4ve.com"])

    def test_punycode_subdomain(self):
        assert features.has_punycode(["xn--pypal-4ve.session-review.net"])

    def test_plain_domains(self):
        assert not features.has_punycode(["example.com", "mail.example.org"])

    def test_empty_and_none_entries(self):
        assert not features.has_punycode(["", None])


class TestContainsAnyPhrase:
    def test_case_insensitive(self):
        assert features.contains_any_phrase("URGENT ACTION REQUIRED today", features.URGENT_PHRASES)

    def test_absent(self):
        assert not features.contains_any_phrase("see you at lunch", features.URGENT_PHRASES)

    def test_none_text(self):
        assert not features.contains_any_phrase(None, features.URGENT_PHRASES)


class TestContainsBrandKeywords:
    def test_brand_present(self):
        assert features.contains_brand_keywords("Your PayPal profile was flagged")

    def test_no_brand(self):
        assert not features.contains_brand_keywords("Your order has shipped")


class TestSenderMatchesLinkDomains:
    def test_subdomain_sender_matches_root_links(self):
        assert features.sender_matches_link_domains("news.brightwave.io", ["brightwave.io"])

    def test_unrelated_domains(self):
        assert not features.sender_matches_link_domains("paypal-account-review.com", ["paypal-account-review.net"])

    def test_empty_sender(self):
        assert not features.sender_matches_link_domains("", ["example.com"])


class TestBuildFeatures:
    def test_multi_signal_phish(self):
        built = features.build_features(emails.phishing_multi_signal())

        assert built["sender_domain"] == "interac-transfers-alerts.com"
        assert built["reply_to_domain"] == "fast-deposit-refunds.ru"
        assert built["from_replyto_mismatch"] == 1
        assert built["ip_url_count"] == 2  # plain-text URL + anchor href
        assert built["url_shortener_usage"] == 1
        assert built["link_text_href_mismatch_count"] == 1
        assert built["credential_lure_language"] == 1
        assert built["contains_urgent_language"] == 1
        assert built["brand_keyword_presence"] == 1
        assert built["punycode_domain"] == 0
        assert built["suspicious_subdomain_count"] == 0  # IPs must not count
        assert built["has_unsubscribe_header"] == 0
        assert built["sender_root_matches_links"] == 0
        assert built["url_count"] == 3

    def test_marketing_newsletter(self):
        built = features.build_features(emails.legit_marketing_newsletter())

        assert built["sender_domain"] == "news.brightwave.io"
        assert built["has_unsubscribe_header"] == 1
        assert built["has_list_id"] == 1
        assert built["has_bulk_precedence"] == 1
        assert built["newsletter_language"] == 1
        assert built["sender_root_matches_links"] == 1
        assert built["contains_urgent_language"] == 1  # "act now" marketing copy
        assert built["credential_lure_language"] == 0
        assert built["from_replyto_mismatch"] == 0
        assert built["link_text_href_mismatch_count"] == 0
        assert built["ip_url_count"] == 0
        assert built["punycode_domain"] == 0
        assert built["url_count"] >= 8

    def test_personal_email(self):
        built = features.build_features(emails.legit_personal_email())

        assert built["sender_uses_free_mail"] == 1
        assert built["url_count"] == 0
        assert built["contains_urgent_language"] == 0
        assert built["credential_lure_language"] == 0
        assert built["brand_keyword_presence"] == 0

    def test_punycode_detected_in_subdomain(self):
        # Regression: detection must look at full hostnames, not just
        # registered domains, or subdomain homographs slip through.
        built = features.build_features(emails.phishing_punycode_subdomain())
        assert built["punycode_domain"] == 1

    def test_fake_unsubscribe_keeps_structural_signals(self):
        built = features.build_features(emails.phishing_fake_unsubscribe())

        assert built["has_unsubscribe_header"] == 1
        assert built["from_replyto_mismatch"] == 1
        assert built["punycode_domain"] == 1
        assert built["link_text_href_mismatch_count"] == 1
