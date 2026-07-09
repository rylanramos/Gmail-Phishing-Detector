from gmail_client import get_gmail_service
from parser import parse_message
from features import build_features
from scorer import score_email
from storage import init_db, save_result, message_exists
from attachments import analyze_attachments
from virustotal import VirusTotalClient


def list_recent_messages(service, max_results=10, query=None):
    response = service.users().messages().list(
        userId="me",
        maxResults=max_results,
        q=query
    ).execute()
    return response.get("messages", [])


def list_recent_spam_messages(service, max_results=10, query=None):
    """Gmail's messages.list excludes the Spam and Trash folders by default,
    regardless of query terms - a plain query never sees them. Malicious
    attachments routinely land straight in Spam, so it must be scanned via an
    explicit, separate 'in:spam' pass rather than silently going unseen."""
    spam_query = f"{query} in:spam" if query else "in:spam"
    return list_recent_messages(service, max_results=max_results, query=spam_query)


def run_scan(max_results=10, query="newer_than:7d -category:social -category:promotions",
             include_spam=True, spam_max_results=10):
    init_db()
    service = get_gmail_service()

    # One VirusTotal client for the whole scan. If no API key is configured it
    # reports itself disabled and every lookup degrades to 'unavailable' - the
    # scan proceeds on static analysis alone.
    vt_client = VirusTotalClient()

    messages = list_recent_messages(
        service,
        max_results=max_results,
        query=query
    )

    if include_spam:
        seen_ids = {m["id"] for m in messages}
        for spam_msg in list_recent_spam_messages(service, max_results=spam_max_results, query=query):
            if spam_msg["id"] not in seen_ids:
                messages.append(spam_msg)
                seen_ids.add(spam_msg["id"])

    if not messages:
        return {
            "found": 0,
            "analyzed": 0,
            "skipped": 0,
            "errors": []
        }

    analyzed_count = 0
    skipped_count = 0
    errors = []
    results = []

    for msg in messages:
        try:
            if message_exists(msg["id"]):
                skipped_count += 1
                continue

            parsed = parse_message(service, msg["id"])
            features = build_features(parsed)
            attachment_findings = analyze_attachments(
                parsed.get("attachments", []), vt_client=vt_client
            )
            result = score_email(features, attachment_findings)
            save_result(parsed, features, result, attachment_findings)

            analyzed_count += 1
            results.append({
                "subject": parsed["subject"],
                "from": parsed["from"],
                "reply_to": parsed["reply_to"],
                "sender_domain": features["sender_domain"],
                "url_count": features["url_count"],
                "score": result["score"],
                "verdict": result["verdict"],
                "reasons": result["reasons"],
                "attachments": [
                    {
                        "filename": f["filename"],
                        "detected_type": f["detected_type"],
                        "extension_mismatch": f["extension_mismatch"],
                        "has_macros": f["has_macros"],
                    }
                    for f in attachment_findings
                ],
            })

        except Exception as e:
            errors.append(f"{msg['id']}: {e}")

    return {
        "found": len(messages),
        "analyzed": analyzed_count,
        "skipped": skipped_count,
        "errors": errors,
        "results": results,
    }