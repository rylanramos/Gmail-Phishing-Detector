# Attachment signal weights. These are STRUCTURAL signals: like domain
# mismatches, punycode, and IP-URLs on the email-body side, they are applied at
# full weight and are never reduced by the bulk-mail trusted-context mechanism
# or the newsletter deductions (see score_email). A message that looks like a
# legitimate newsletter but carries a macro-laden, auto-executing attachment is
# not made safer by looking like a newsletter.
ATTACH_EXTENSION_MISMATCH = 25
ATTACH_MACRO_PRESENT = 25
ATTACH_MACRO_AUTOEXEC = 10
ATTACH_MACRO_SHELL = 10
# The auto-exec + shell/process-exec combination is the classic weaponized-macro
# pattern; weighted high, comparable to the IP-URL / punycode structural signals.
ATTACH_MACRO_AUTOEXEC_AND_SHELL = 35
ATTACH_MACRO_OBFUSCATION = 10
ATTACH_MACRO_EMBEDDED_IOC = 10
ATTACH_EMBEDDED_OBJECT = 15
# A VirusTotal hash match with multiple engines flagging the file is corroborated
# evidence rather than a heuristic inference: the highest-severity single signal
# in the entire model, enough to reach "likely phishing" on its own.
ATTACH_VIRUSTOTAL_MALICIOUS = 100


def _score_attachments(attachment_findings):
    """Compute the additive attachment-signal score and its reasons.

    Signals are summed across every attachment on the message so that, e.g., two
    macro-laden attachments both contribute.
    """
    score = 0
    reasons = []

    for finding in attachment_findings:
        name = finding.get("filename") or "attachment"

        if finding.get("extension_mismatch"):
            score += ATTACH_EXTENSION_MISMATCH
            reasons.append(
                f"Attachment '{name}' extension does not match its actual file type"
            )

        if finding.get("has_macros"):
            score += ATTACH_MACRO_PRESENT
            reasons.append(f"Attachment '{name}' contains VBA macros")

            has_autoexec = bool(finding.get("macro_autoexec_triggers"))
            has_shell = bool(finding.get("macro_shell_calls"))

            if has_autoexec:
                score += ATTACH_MACRO_AUTOEXEC
            if has_shell:
                score += ATTACH_MACRO_SHELL
            if has_autoexec and has_shell:
                score += ATTACH_MACRO_AUTOEXEC_AND_SHELL
                reasons.append(
                    f"Attachment '{name}' macro combines auto-execution triggers "
                    "with shell/process-execution calls"
                )
            elif has_autoexec:
                reasons.append(
                    f"Attachment '{name}' macro contains auto-execution triggers"
                )
            elif has_shell:
                reasons.append(
                    f"Attachment '{name}' macro contains shell/process-execution calls"
                )

            if finding.get("macro_obfuscation"):
                score += ATTACH_MACRO_OBFUSCATION
                reasons.append(
                    f"Attachment '{name}' macro shows obfuscation indicators"
                )

            if finding.get("macro_urls") or finding.get("macro_ips"):
                score += ATTACH_MACRO_EMBEDDED_IOC
                reasons.append(
                    f"Attachment '{name}' macro contains embedded URLs or IP addresses"
                )

        if finding.get("has_embedded_objects"):
            score += ATTACH_EMBEDDED_OBJECT
            reasons.append(
                f"Attachment '{name}' contains embedded OLE objects or files"
            )

        vt = finding.get("virustotal")
        if vt and vt.get("available") and vt.get("status") == "malicious":
            malicious = vt.get("malicious") or 0
            total = vt.get("total") or 0
            if malicious > 0:
                score += ATTACH_VIRUSTOTAL_MALICIOUS
                reasons.append(
                    f"Attachment '{name}' flagged by VirusTotal: "
                    f"{malicious} of {total} engines detected it as malicious"
                )

    return score, reasons


def score_email(features, attachment_findings=None):
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

    # Floor the email-body score at zero BEFORE adding attachment signals. A
    # heavy newsletter deduction can zero out body signals, but it must never
    # eat into full-weight attachment signals: a message with a legitimate
    # newsletter structure but a weaponized attachment is not made safer by
    # looking like a newsletter. Adding attachment signals after this floor is
    # what keeps them immune from the bulk-mail discount, mirroring how the
    # structural email-body signals are treated.
    if score < 0:
        score = 0

    if attachment_findings:
        attach_score, attach_reasons = _score_attachments(attachment_findings)
        score += attach_score
        reasons.extend(attach_reasons)

    # Final clamp floor (attachment scores are non-negative, but keep the guard)
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