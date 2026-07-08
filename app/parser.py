import base64
import re
from bs4 import BeautifulSoup


def get_header(headers, name):
    for header in headers:
        if header.get("name", "").lower() == name.lower():
            return header.get("value", "")
    return ""


def decode_body(data):
    if not data:
        return ""

    try:
        decoded = base64.urlsafe_b64decode(data.encode("utf-8"))
        return decoded.decode("utf-8", errors="replace")
    except Exception:
        return ""


def decode_attachment_data(data):
    """Decode Gmail's base64url attachment payload to raw bytes.

    Unlike decode_body, this preserves the raw bytes (attachments are binary,
    not text) and tolerates missing base64 padding, which the Gmail API omits.
    """
    if not data:
        return b""

    try:
        padded = data + "=" * (-len(data) % 4)
        return base64.urlsafe_b64decode(padded.encode("utf-8"))
    except Exception:
        return b""


def extract_attachments(payload):
    """Walk the MIME part tree and collect every part that represents an
    attachment (i.e. carries a non-empty filename).

    Returns a list of dicts describing each attachment. The raw content is not
    fetched here: small attachments are delivered inline as ``body.data`` while
    larger ones are referenced by ``body.attachmentId`` and require a separate
    Gmail API call (see fetch_attachment_content).
    """
    attachments = []

    filename = payload.get("filename", "") or ""
    body = payload.get("body", {}) or {}

    if filename.strip():
        attachments.append({
            "filename": filename,
            "mime_type": payload.get("mimeType", ""),
            "attachment_id": body.get("attachmentId"),
            "inline_data": body.get("data"),
            "size": body.get("size", 0),
        })

    for part in payload.get("parts", []) or []:
        attachments.extend(extract_attachments(part))

    return attachments


def fetch_attachment_content(service, message_id, attachment):
    """Resolve the raw bytes for a single extracted attachment.

    Inline attachments carry their data directly; larger ones must be fetched
    by attachmentId. Returns raw bytes, or b"" if the payload is unavailable.
    """
    data = attachment.get("inline_data")

    if not data and attachment.get("attachment_id"):
        fetched = service.users().messages().attachments().get(
            userId="me",
            messageId=message_id,
            id=attachment["attachment_id"],
        ).execute()
        data = fetched.get("data")

    return decode_attachment_data(data)


def extract_parts(payload):
    plain_text = ""
    html_text = ""

    mime_type = payload.get("mimeType", "")
    body_data = payload.get("body", {}).get("data")

    if mime_type == "text/plain" and body_data:
        plain_text += decode_body(body_data)

    if mime_type == "text/html" and body_data:
        html_text += decode_body(body_data)

    for part in payload.get("parts", []) or []:
        p_text, p_html = extract_parts(part)
        if p_text:
            plain_text += "\n" + p_text
        if p_html:
            html_text += "\n" + p_html

    return plain_text.strip(), html_text.strip()


def extract_urls_from_text(text):
    if not text:
        return []

    pattern = r'https?://[^\s<>"\']+'
    return re.findall(pattern, text)


def extract_urls_from_html(html):
    if not html:
        return [], []

    soup = BeautifulSoup(html, "html.parser")
    urls = []
    anchors = []

    for a in soup.find_all("a", href=True):
        href = a.get("href", "").strip()
        text = a.get_text(" ", strip=True)
        urls.append(href)
        anchors.append({
            "text": text,
            "href": href
        })

    return urls, anchors


def parse_message(service, message_id):
    msg = service.users().messages().get(
        userId="me",
        id=message_id,
        format="full"
    ).execute()

    payload = msg.get("payload", {})
    headers = payload.get("headers", [])

    plain_text, html_text = extract_parts(payload)
    text_urls = extract_urls_from_text(plain_text)
    html_urls, anchors = extract_urls_from_html(html_text)

    attachments = []
    for att in extract_attachments(payload):
        attachments.append({
            "filename": att["filename"],
            "mime_type": att["mime_type"],
            "size": att.get("size", 0),
            "content": fetch_attachment_content(service, msg.get("id"), att),
        })

    return {
        "message_id": msg.get("id"),
        "thread_id": msg.get("threadId"),
        "snippet": msg.get("snippet", ""),
        "internal_date": msg.get("internalDate", ""),
        "from": get_header(headers, "From"),
        "reply_to": get_header(headers, "Reply-To"),
        "return_path": get_header(headers, "Return-Path"),
        "subject": get_header(headers, "Subject"),
        "date": get_header(headers, "Date"),
        "list_unsubscribe": get_header(headers, "List-Unsubscribe"),
        "list_id": get_header(headers, "List-Id"),
        "precedence": get_header(headers, "Precedence"),
        "plain_text": plain_text,
        "html_text": html_text,
        "text_urls": text_urls,
        "html_urls": html_urls,
        "anchors": anchors,
        "attachments": attachments,
    }