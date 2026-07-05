import re
from urllib.parse import urlparse
import tldextract

URGENT_PHRASES = [
    "verify your account",
    "account suspended",
    "urgent action required",
    "password expires",
    "confirm your identity",
    "unusual sign-in",
    "payment failed",
    "verify now",
    "act now",
    "immediate action required",
    "security alert",
]

# Deliberately narrow: generic terms like "sign in", "log in", or "payment
# method" show up constantly in legitimate transactional/marketing email and
# were a major source of false positives. Keep only phrasing that is
# specifically about proving identity or recovering account access under
# pressure.
CREDENTIAL_LURE_PHRASES = [
    "reset your password",
    "password reset required",
    "confirm your password",
    "verify your identity",
    "validate your account",
    "suspended account",
    "secure your account immediately",
    "confirm your account details",
]

NEWSLETTER_HINTS = [
    "unsubscribe",
    "view in browser",
    "manage preferences",
    "email preferences",
    "article",
    "read more",
    "top stories",
    "newsletter",
    "insights",
    "weekly update",
    "monthly update",
]

FREE_MAIL_DOMAINS = {
    "gmail.com",
    "yahoo.com",
    "hotmail.com",
    "outlook.com",
}

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "buff.ly",
    "is.gd",
    "rb.gy",
}


def get_domain_from_email_header(header_value):
    if not header_value:
        return ""

    match = re.search(r'[\w\.-]+@([\w\.-]+\.\w+)', header_value)
    if match:
        return match.group(1).lower()

    return ""


def get_registered_domain(value):
    if not value:
        return ""

    ext = tldextract.extract(value)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower()

    return value.lower()


def get_domain_from_url(url):
    try:
        hostname = urlparse(url).hostname or ""
        return hostname.lower()
    except Exception:
        return ""


def contains_any_phrase(text, phrases):
    lower_text = (text or "").lower()
    return any(phrase in lower_text for phrase in phrases)


def url_uses_ip(url):
    return bool(re.search(r"https?://\d{1,3}(\.\d{1,3}){3}", url or ""))


def excessive_subdomains(domain):
    if not domain:
        return False
    return domain.count(".") >= 3


def link_text_href_mismatch(anchors):
    mismatches = 0

    for anchor in anchors:
        text = (anchor.get("text") or "").strip().lower()
        href = (anchor.get("href") or "").strip().lower()

        if not text or not href.startswith("http"):
            continue

        text_domain_match = re.search(r'([a-z0-9-]+\.[a-z]{2,})', text)
        if not text_domain_match:
            continue

        text_domain = get_registered_domain(text_domain_match.group(1))
        href_domain = get_registered_domain(get_domain_from_url(href))

        if text_domain and href_domain and text_domain != href_domain:
            mismatches += 1

    return mismatches


def has_shortener(urls):
    for url in urls:
        domain = get_registered_domain(get_domain_from_url(url))
        if domain in SHORTENERS:
            return True
    return False


def has_punycode(domains):
    return any("xn--" in (domain or "") for domain in domains)


def contains_brand_keywords(text):
    keywords = [
        "microsoft",
        "google",
        "apple",
        "amazon",
        "paypal",
        "bank",
        "etransfer",
        "interac",
        "outlook",
        "office365",
        "dropbox",
        "docusign",
        "isc2",
    ]
    lower_text = (text or "").lower()
    return any(keyword in lower_text for keyword in keywords)


def sender_matches_link_domains(sender_domain, registered_domains):
    if not sender_domain:
        return False

    sender_root = get_registered_domain(sender_domain)
    if not sender_root:
        return False

    return sender_root in set(registered_domains)


def build_features(parsed_email):
    sender_domain = get_domain_from_email_header(parsed_email.get("from", ""))
    reply_to_domain = get_domain_from_email_header(parsed_email.get("reply_to", ""))

    all_urls = parsed_email.get("text_urls", []) + parsed_email.get("html_urls", [])
    all_domains = [get_domain_from_url(url) for url in all_urls if url]
    registered_domains = [get_registered_domain(domain) for domain in all_domains if domain]

    content = " ".join([
        parsed_email.get("subject", ""),
        parsed_email.get("snippet", ""),
        parsed_email.get("plain_text", ""),
        parsed_email.get("html_text", ""),
    ])

    has_unsubscribe_header = int(bool(parsed_email.get("list_unsubscribe", "")))
    has_list_id = int(bool(parsed_email.get("list_id", "")))
    has_bulk_precedence = int("bulk" in (parsed_email.get("precedence", "") or "").lower())
    newsletter_language = int(contains_any_phrase(content, NEWSLETTER_HINTS))
    urgent_language = int(contains_any_phrase(content, URGENT_PHRASES))
    credential_lure = int(contains_any_phrase(content, CREDENTIAL_LURE_PHRASES))

    sender_root_matches_links = int(sender_matches_link_domains(sender_domain, registered_domains))

    suspicious_subdomain_count = 0
    for domain in all_domains:
        root = get_registered_domain(domain)
        if excessive_subdomains(domain) and root != get_registered_domain(sender_domain):
            suspicious_subdomain_count += 1

    true_mismatch_count = link_text_href_mismatch(parsed_email.get("anchors", []))

    return {
        "sender_domain": sender_domain,
        "reply_to_domain": reply_to_domain,
        "from_replyto_mismatch": int(
            bool(sender_domain and reply_to_domain and get_registered_domain(sender_domain) != get_registered_domain(reply_to_domain))
        ),
        "sender_uses_free_mail": int(get_registered_domain(sender_domain) in FREE_MAIL_DOMAINS),
        "contains_urgent_language": urgent_language,
        "credential_lure_language": credential_lure,
        "brand_keyword_presence": int(contains_brand_keywords(content)),
        "url_count": len(all_urls),
        "ip_url_count": sum(1 for url in all_urls if url_uses_ip(url)),
        "suspicious_subdomain_count": suspicious_subdomain_count,
        "link_text_href_mismatch_count": true_mismatch_count,
        "url_shortener_usage": int(has_shortener(all_urls)),
        "punycode_domain": int(has_punycode(registered_domains)),
        "has_unsubscribe_header": has_unsubscribe_header,
        "has_list_id": has_list_id,
        "has_bulk_precedence": has_bulk_precedence,
        "newsletter_language": newsletter_language,
        "sender_root_matches_links": sender_root_matches_links,
        "all_urls": all_urls,
    }