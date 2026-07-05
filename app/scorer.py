def score_email(features):
    score = 0
    reasons = []

    # A message is in a "trusted context" when it carries hard-to-fake bulk
    # mail infrastructure signals (List-Unsubscribe, List-Id, Precedence:
    # bulk) or when its links point back to the sender's own domain. Language
    # like "verify your account" or "act now" is extremely common in
    # legitimate marketing and transactional email, so we discount it heavily
    # in these cases instead of treating every use of urgent wording as a
    # phishing signal.
    is_bulk_mail = bool(
        features["has_unsubscribe_header"]
        or features["has_list_id"]
        or features["has_bulk_precedence"]
    )
    trusted_context = is_bulk_mail or bool(features["sender_root_matches_links"])

    # High-confidence phishing signals (structural, hard for a legitimate
    # sender to trigger by accident)
    if features["from_replyto_mismatch"]:
        score += 30
        reasons.append("From and Reply-To domains do not match")

    if features["ip_url_count"] > 0:
        score += 35
        reasons.append("One or more URLs use a raw IP address")

    if features["punycode_domain"]:
        score += 30
        reasons.append("Punycode domain detected")

    if features["link_text_href_mismatch_count"] > 0:
        score += 20
        reasons.append("Displayed domain text does not match destination domain")

    if features["suspicious_subdomain_count"] > 0:
        score += 10
        reasons.append("Suspicious unrelated deep subdomains detected")

    if features["url_shortener_usage"]:
        if trusted_context:
            score += 5
        else:
            score += 15
            reasons.append("URL shortener detected")

    # Language-based signals (weaker, and heavily discounted in a trusted
    # context since routine marketing/transactional copy reuses this wording)
    if features["credential_lure_language"]:
        if trusted_context:
            score += 5
        else:
            score += 25
            reasons.append("Credential or account-verification language detected")

    if features["contains_urgent_language"]:
        if trusted_context:
            score += 3
        else:
            score += 15
            reasons.append("Urgent or account-pressure language detected")

    if features["brand_keyword_presence"] and features["credential_lure_language"] and not trusted_context:
        score += 20
        reasons.append("Brand language combined with credential lure detected")

    # Weak signal only, and not meaningful for bulk mail which routinely
    # includes many footer/social links
    if features["url_count"] >= 8 and not is_bulk_mail:
        score += 5
        reasons.append("Large number of links in message")

    # Benign newsletter adjustments
    newsletter_score = 0

    if features["has_unsubscribe_header"]:
        newsletter_score += 10

    if features["has_list_id"]:
        newsletter_score += 8

    if features["has_bulk_precedence"]:
        newsletter_score += 6

    if features["newsletter_language"]:
        newsletter_score += 10

    if features["sender_root_matches_links"]:
        newsletter_score += 12

    if newsletter_score > 0:
        score -= newsletter_score
        reasons.append("Legitimate mailing-list or newsletter indicators detected")

    # Clamp floor
    if score < 0:
        score = 0

    # Final verdict
    if score >= 60:
        verdict = "likely phishing"
    elif score >= 30:
        verdict = "suspicious"
    else:
        verdict = "safe"

    return {
        "score": score,
        "verdict": verdict,
        "reasons": reasons,
    }