"""Synthetic parsed-email fixtures for the scoring test suite.

Each fixture returns a dict with the exact shape produced by
app.parser.parse_message for a real Gmail message: realistic From / Reply-To /
Subject / List-* headers plus raw plain-text and HTML bodies. URLs and anchors
are derived from those bodies using the real parser functions
(extract_urls_from_text / extract_urls_from_html), so every fixture exercises
the same extraction path the production pipeline uses.

Fixtures are grouped into three families:
  * phishing_*    — known-bad patterns, individually and in combination
  * legit_*       — known-good marketing, transactional, and personal mail
  * boundary_*    — messages engineered to land on or near the
                    safe/suspicious/likely-phishing score thresholds
"""

from app import parser


def build_parsed_email(
    *,
    from_,
    subject,
    reply_to="",
    plain_text="",
    html="",
    list_unsubscribe="",
    list_id="",
    precedence="",
):
    plain_text = plain_text.strip()
    html = html.strip()
    html_urls, anchors = parser.extract_urls_from_html(html)

    return {
        "message_id": "18f9a2c4e7b31d05",
        "thread_id": "18f9a2c4e7b31d05",
        "snippet": (plain_text or html)[:100],
        "internal_date": "1751724862000",
        "from": from_,
        "reply_to": reply_to,
        "return_path": from_,
        "subject": subject,
        "date": "Sun, 05 Jul 2026 09:14:22 -0400",
        "list_unsubscribe": list_unsubscribe,
        "list_id": list_id,
        "precedence": precedence,
        "plain_text": plain_text,
        "html_text": html,
        "text_urls": parser.extract_urls_from_text(plain_text),
        "html_urls": html_urls,
        "anchors": anchors,
    }


# ---------------------------------------------------------------------------
# Phishing patterns — single structural or language signals in isolation
# ---------------------------------------------------------------------------

def phishing_reply_to_mismatch_only():
    """From/Reply-To registered-domain mismatch and nothing else (+30)."""
    return build_parsed_email(
        from_='"Meridian Credit Union Support" <support@meridiancu-notices.com>',
        reply_to="Account Recovery <recovery-desk@mailbox-fastreply.net>",
        subject="Re: Card inquiry",
        plain_text=(
            "Hello,\n\n"
            "We received your message about your card. Please reply to this "
            "email and our team will follow up within two business days.\n\n"
            "Reference number: 58201"
        ),
    )


def phishing_punycode_link_only():
    """Punycode (IDN homograph) registered domain in the only link (+30)."""
    return build_parsed_email(
        from_='"Membership Services" <renewals@membership-notices.com>',
        subject="Membership renewal notice",
        html=(
            "<p>Hello,</p>"
            "<p>Your annual membership is due for renewal on July 31.</p>"
            '<p><a href="https://xn--membershp-hib.com/renew/8842">'
            "Renew membership</a></p>"
        ),
    )


def phishing_punycode_subdomain():
    """Punycode hidden in a subdomain of an otherwise plain registered domain.

    Regression fixture: punycode detection must inspect full hostnames, not
    just registered domains, or xn--pypal-4ve.session-review.net reduces to
    session-review.net and the homograph goes unnoticed.
    """
    return build_parsed_email(
        from_='"Document Center" <notices@docs-review-center.net>',
        subject="Document shared with you",
        html=(
            "<p>A secure document has been shared with you.</p>"
            '<p><a href="https://xn--pypal-4ve.session-review.net/view/44012">'
            "View document</a></p>"
        ),
    )


def phishing_ip_url_only():
    """Raw IPv4-literal URL and nothing else (+35).

    Regression fixture: the IPv4 hostname's three dots must not also trip the
    excessive-subdomain signal.
    """
    return build_parsed_email(
        from_='"Arctic Net Billing" <billing@arcticnet-billing.com>',
        subject="Your July invoice is ready",
        plain_text=(
            "Your latest invoice is ready.\n\n"
            "Download a copy here: http://185.220.101.44/invoices/9917/download\n\n"
            "Thank you for choosing Arctic Net."
        ),
    )


def phishing_anchor_text_mismatch_only():
    """Anchor text displays one domain, href points at another (+20)."""
    return build_parsed_email(
        from_='"Courier Express" <status@courier-express-updates.com>',
        subject="Delivery attempt unsuccessful",
        html=(
            "<p>Your parcel could not be delivered.</p>"
            '<p><a href="http://parcel-redelivery-portal.com/track/7781">'
            "canadapost.ca</a></p>"
        ),
    )


def phishing_credential_lure_no_bulk():
    """Credential-lure language with no bulk-mail context and an off-domain
    link — the language signal at full (undiscounted) weight (+25)."""
    return build_parsed_email(
        from_='"Account Services" <support@account-services-desk.com>',
        subject="Action needed on your account",
        plain_text=(
            "We could not verify your identity during a recent review.\n\n"
            "Please reset your password using the secure link below within "
            "24 hours.\n\n"
            "https://secure-reset-portal.net/session/awx8172"
        ),
    )


# ---------------------------------------------------------------------------
# The bulk-mail discount, from both sides: identical lure-heavy copy sent by
# a lookalike domain (phishing) and by the real brand's bulk infrastructure
# (legitimate). Only the surrounding context differs.
# ---------------------------------------------------------------------------

_LURE_SUBJECT = "Urgent action required: verify your identity"


def _lure_body(link):
    return (
        "Your PayPal profile was flagged after an unrecognized charge "
        "attempt. Verify your identity to restore full access:\n\n"
        f"{link}"
    )


def phishing_lure_urgent_brand():
    """Credential lure + urgent language + brand impersonation, no bulk
    headers, link domain unrelated to the sender (25 + 15 + 20 = 60)."""
    return build_parsed_email(
        from_='"PayPal Security" <alerts@paypal-account-review.com>',
        subject=_LURE_SUBJECT,
        plain_text=_lure_body("http://paypal-account-review.net/verify/session"),
    )


def legit_bulk_with_lure_language():
    """The same copy sent from the brand's real domain with proper bulk-mail
    headers and a same-domain link — the discount must drive this to safe."""
    return build_parsed_email(
        from_='"PayPal" <service@paypal.com>',
        subject=_LURE_SUBJECT,
        plain_text=_lure_body("https://www.paypal.com/security/review-activity"),
        list_unsubscribe="<mailto:unsubscribe@mail.paypal.com>",
        list_id="PayPal Account Notifications <account.paypal.com>",
    )


# ---------------------------------------------------------------------------
# Phishing patterns — combinations
# ---------------------------------------------------------------------------

def phishing_fake_unsubscribe():
    """Phish that fraudulently adds a List-Unsubscribe header to game the
    bulk-mail discount. The language signals are discounted, but the
    structural signals (Reply-To mismatch, punycode link, anchor/href
    mismatch) carry full weight and must still push it well past the
    likely-phishing threshold (30 + 30 + 20 + 5 + 3 - 10 = 78)."""
    return build_parsed_email(
        from_='"ISC2 Member Services" <renewals@isc2-membership-center.com>',
        reply_to="billing-desk@refund-processing.top",
        subject="Certification hold notice",
        list_unsubscribe="<mailto:optout@isc2-membership-center.com>",
        html=(
            "<p>Your ISC2 certification will be suspended unless we verify "
            "your identity within 24 hours. Immediate action required.</p>"
            '<p><a href="https://xn--isc-1na2b.com/member/verify">'
            "www.isc2.org</a></p>"
        ),
    )


def phishing_multi_signal():
    """Realistic e-transfer phish combining nearly every signal: Reply-To
    mismatch, IP-literal URL, shortener, anchor/href mismatch, credential
    lure, urgency, and brand impersonation (30+35+20+15+25+15+20 = 160)."""
    return build_parsed_email(
        from_='"Interac e-Transfer" <notify@interac-transfers-alerts.com>',
        reply_to="claims@fast-deposit-refunds.ru",
        subject="You have a pending deposit of $482.00",
        plain_text=(
            "A deposit of $482.00 could not be completed because your "
            "payment failed.\n\n"
            "Confirm your account details to claim the transfer:\n"
            "http://91.203.67.44/interac/claim\n\n"
            "Or use our quick link: https://bit.ly/3fastclaim"
        ),
        html=(
            "<p>A deposit of $482.00 is waiting for you.</p>"
            '<p><a href="http://91.203.67.44/interac/claim">interac.ca</a></p>'
        ),
    )


# ---------------------------------------------------------------------------
# Legitimate patterns
# ---------------------------------------------------------------------------

def legit_marketing_newsletter():
    """Bulk marketing newsletter: List-Unsubscribe, List-Id, Precedence:
    bulk, many same-domain links, and marketing copy that includes urgent
    wording ("act now"). Must score safe/0."""
    return build_parsed_email(
        from_='"Brightwave" <hello@news.brightwave.io>',
        subject="Your backyard, upgraded: the Brightwave summer edit",
        list_unsubscribe=(
            "<mailto:unsubscribe@brightwave.io>, "
            "<https://news.brightwave.io/unsubscribe/abc123>"
        ),
        list_id="Brightwave Weekly <weekly.news.brightwave.io>",
        precedence="bulk",
        html=(
            '<p><a href="https://news.brightwave.io/campaigns/summer/view">'
            "View in browser</a></p>"
            "<h1>The summer edit is here</h1>"
            "<p>Three ideas to refresh your outdoor space this month.</p>"
            '<p>Deck refresh on a budget — <a href="https://www.brightwave.io/blog/deck-refresh">Read more</a></p>'
            '<p>Patio lighting that lasts — <a href="https://www.brightwave.io/blog/patio-lighting">Read more</a></p>'
            '<p>Prepping raised beds — <a href="https://www.brightwave.io/blog/garden-prep">Read more</a></p>'
            '<p><a href="https://www.brightwave.io/sale">Act now — the summer '
            "sale ends Friday</a></p>"
            '<p><a href="https://www.brightwave.io/preferences">Manage preferences</a> | '
            '<a href="https://www.brightwave.io/unsubscribe">Unsubscribe</a> | '
            '<a href="https://www.brightwave.io">www.brightwave.io</a></p>'
        ),
    )


def legit_transactional_receipt():
    """Order receipt: no bulk headers, but every link points back to the
    sender's own domain. Must score safe/0."""
    return build_parsed_email(
        from_='"Lumen Market" <orders@lumenmarket.com>',
        subject="Your Lumen Market order #84712",
        plain_text=(
            "Thanks for shopping with us!\n\n"
            "Your order #84712 has been received.\n"
            "  1x Ceramic pour-over set ....... $34.00\n"
            "  1x Filter pack (40) ............. $8.90\n"
            "  Total ......................... $42.90\n\n"
            "View your receipt: https://lumenmarket.com/orders/84712/receipt\n"
            "Questions? Visit https://lumenmarket.com/help"
        ),
    )


def legit_shipping_notification():
    """Shipping notification whose anchor text is the sender's own bare
    domain ("www.lumenmarket.com") linking to that same domain.

    Regression fixture: domain-shaped anchor text with a www. prefix must not
    be reported as an anchor/href mismatch when it matches the destination.
    """
    return build_parsed_email(
        from_='"Lumen Market Shipping" <shipping@lumenmarket.com>',
        subject="Order #84712 has shipped",
        html=(
            "<p>Good news — your order #84712 has shipped.</p>"
            '<p><a href="https://www.lumenmarket.com/orders/84712/tracking">'
            "Track your package</a></p>"
            "<p>Or start from our homepage: "
            '<a href="https://www.lumenmarket.com">www.lumenmarket.com</a></p>'
        ),
    )


def legit_personal_email():
    """Personal correspondence from a free-mail address: no links, no
    phishing indicators of any kind. Must score safe/0."""
    return build_parsed_email(
        from_="Sarah Mitchell <sarah.mitchell.k@gmail.com>",
        subject="Saturday hike?",
        plain_text=(
            "Hey!\n\n"
            "Are we still on for Saturday? I found a trail near the lake "
            "that's supposed to have great views — about 9 km round trip.\n\n"
            "Let me know and I'll drive.\n\n"
            "— Sarah"
        ),
    )


def legit_security_newsletter():
    """Security-industry newsletter (modeled on the real ISC2 false-positive
    bug this project once had): brand keyword, urgent-sounding editorial
    copy ("security alert"), bulk headers, same-domain links. Must score
    safe/0."""
    return build_parsed_email(
        from_='"ISC2 Insights" <insights@email.isc2.org>',
        subject="This week in security: your member insights",
        list_unsubscribe="<https://email.isc2.org/unsubscribe/9917>",
        list_id="ISC2 Insights <insights.email.isc2.org>",
        html=(
            "<p>Top stories for members this week, including a security "
            "alert roundup and phishing defense insights.</p>"
            '<p>Zero trust in practice — <a href="https://www.isc2.org/insights/2026/07/zero-trust">Read more</a></p>'
            '<p>Phishing trends report — <a href="https://www.isc2.org/insights/2026/07/phishing-trends">Read more</a></p>'
            '<p><a href="https://www.isc2.org/certifications">Explore certifications</a></p>'
            '<p><a href="https://email.isc2.org/preferences">Email preferences</a> | '
            '<a href="https://www.isc2.org">www.isc2.org</a></p>'
        ),
    )


# ---------------------------------------------------------------------------
# Boundary probes — engineered to land on or near verdict thresholds
# ---------------------------------------------------------------------------

def boundary_shortener_plus_urgent():
    """Urgent language (+15) plus a shortener with no trusted context (+15):
    exactly 30, the bottom edge of the suspicious band."""
    return build_parsed_email(
        from_="IT Helpdesk <it.helpdesk.notices@gmail.com>",
        subject="Mailbox storage almost full",
        plain_text=(
            "Urgent action required: your mailbox storage is almost full "
            "and incoming messages may bounce.\n\n"
            "Request more space here: https://bit.ly/2mailquota"
        ),
    )


def boundary_ip_plus_credential_lure():
    """IP-literal URL (+35) plus undiscounted credential lure (+25):
    exactly 60, the bottom edge of the likely-phishing band."""
    return build_parsed_email(
        from_='"Payments Desk" <notices@payments-desk-review.com>',
        subject="Validation needed before your next payout",
        plain_text=(
            "We need to validate your account before your next payout can "
            "be released.\n\n"
            "Complete validation here: http://203.0.113.88/portal/validate"
        ),
    )


def boundary_ip_plus_anchor_mismatch():
    """IP-literal URL (+35) plus anchor/href mismatch (+20): 55, just below
    the likely-phishing threshold — must stay suspicious."""
    return build_parsed_email(
        from_='"Storage Team" <alerts@cloud-storage-notices.net>',
        subject="A file was shared with you",
        html=(
            "<p>Your shared file is waiting.</p>"
            '<p><a href="http://198.51.100.23/files/9917">files-portal.net</a></p>'
        ),
    )
