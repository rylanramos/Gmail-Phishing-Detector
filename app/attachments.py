"""Tier 1 attachment screening: static analysis and heuristics only.

This module inspects attachment *bytes and structure*. It never executes,
opens, detonates, or otherwise interprets an attachment's active content. VBA
macro source is recovered by statically parsing and decompressing the file's
streams (via oletools/olevba, per the MS-OVBA spec) - the macros are read as
data, never run. If a future signal ever required actually running a macro or
opening a document in an interpreter, that would cross into sandboxing and is
explicitly out of scope for this tier.

For each attachment we determine:
  * the true file type via magic-byte / file-signature inspection, independent
    of the filename's claimed extension (a mismatch is a signal on its own);
  * for Office documents, the presence of VBA macros and, if present, high-risk
    indicators within them (auto-exec triggers, shell/process execution,
    obfuscation, embedded URLs/IPs);
  * whether the document embeds OLE objects or other files;
  * the SHA-256 hash (always), used for VirusTotal reputation lookups.
"""

import hashlib
import logging
import re
import zipfile
from io import BytesIO

import filetype

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# File-type detection
# ---------------------------------------------------------------------------
# We use `filetype` (pure-Python) rather than python-magic: python-magic needs
# the native libmagic library, which is not reliably available on Windows.
# `filetype` covers PNG/JPEG/PDF/EXE/OOXML from content, but it cannot classify
# the OLE/CFBF compound format (legacy .doc/.xls/.ppt and vbaProject.bin), so we
# check that signature explicitly.
OLE_MAGIC = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"
ZIP_MAGIC = b"PK\x03\x04"

# Extensions we treat as Office documents worth scanning for macros.
OFFICE_EXTENSIONS = {
    "doc", "docx", "docm", "dot", "dotx", "dotm",
    "xls", "xlsx", "xlsm", "xlsb", "xlt", "xltx", "xltm", "xlam",
    "ppt", "pptx", "pptm", "pot", "potx", "potm", "ppam", "pps", "ppsx", "ppsm",
}

# Family map for the extension/type mismatch signal. Both the detected type and
# the claimed extension are reduced to a coarse family; a mismatch fires only
# when both families are known and differ. `zip` maps to None because a valid
# OOXML file is itself a zip and would otherwise false-positive against a .docx
# claim when filetype cannot see inside it.
_DETECTED_FAMILY = {
    "ole": "office",
    "docx": "office", "xlsx": "office", "pptx": "office",
    "pdf": "pdf",
    "rtf": "document",
    "exe": "executable", "elf": "executable", "mach": "executable",
    "png": "image", "jpg": "image", "gif": "image", "bmp": "image",
    "webp": "image", "tif": "image", "heic": "image",
    "zip": None,
}

_EXT_FAMILY = {
    **{e: "office" for e in OFFICE_EXTENSIONS},
    "pdf": "pdf",
    "rtf": "document",
    "exe": "executable", "dll": "executable", "scr": "executable",
    "com": "executable", "msi": "executable", "bat": "executable",
    "cmd": "executable", "js": "executable", "vbs": "executable",
    "png": "image", "jpg": "image", "jpeg": "image", "gif": "image",
    "bmp": "image", "webp": "image", "tif": "image", "tiff": "image",
    "zip": "archive", "rar": "archive", "7z": "archive", "gz": "archive",
}


def compute_sha256(content):
    return hashlib.sha256(content or b"").hexdigest()


def detect_file_type(content):
    """Return a short type token derived from the file's magic bytes, or None.

    Examples: 'ole', 'docx', 'pdf', 'exe', 'png', 'zip'. This is deliberately
    independent of any filename.
    """
    if not content:
        return None

    if content[:8] == OLE_MAGIC:
        return "ole"

    kind = filetype.guess(content)
    if kind is not None:
        return kind.extension

    if content[:4] == ZIP_MAGIC:
        return "zip"

    return None


def claimed_extension(filename):
    """Return the lowercased final extension of a filename, without the dot."""
    if not filename or "." not in filename:
        return ""
    return filename.rsplit(".", 1)[1].lower().strip()


def extension_mismatch(filename, detected_type):
    """True when the claimed extension and detected type belong to different,
    both-known file families (e.g. an EXE named invoice.pdf)."""
    ext = claimed_extension(filename)
    detected_family = _DETECTED_FAMILY.get(detected_type)
    ext_family = _EXT_FAMILY.get(ext)

    if detected_family is None or ext_family is None:
        return False

    return detected_family != ext_family


# ---------------------------------------------------------------------------
# VBA macro analysis
# ---------------------------------------------------------------------------
# Auto-executing triggers: run automatically when the document is opened.
AUTOEXEC_TRIGGERS = [
    "AutoOpen",
    "AutoExec",
    "Document_Open",
    "Workbook_Open",
]

# Shell / process-execution calls.
SHELL_CALLS = [
    "Shell",
    "WScript.Shell",
    "CreateObject",
]

_URL_RE = re.compile(r'https?://[^\s"\'<>)]+', re.IGNORECASE)
_IP_RE = re.compile(r'\b\d{1,3}(?:\.\d{1,3}){3}\b')
# A run of base64-ish characters long enough to plausibly encode a payload.
_BASE64_RE = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')
_CHR_RE = re.compile(r'\bchr[wb]?\s*\(', re.IGNORECASE)
# String concatenation across quoted literals: "..." & "..."
_CONCAT_RE = re.compile(r'"\s*&|&\s*"')

# Thresholds for the obfuscation heuristics.
_CHR_THRESHOLD = 5
_CONCAT_THRESHOLD = 10


def _find_keywords(code, keywords):
    """Return the subset of `keywords` that appear in `code` as whole words,
    case-insensitively, preserving the given order."""
    found = []
    for kw in keywords:
        pattern = r'\b' + re.escape(kw) + r'\b'
        if re.search(pattern, code, re.IGNORECASE):
            found.append(kw)
    return found


def analyze_vba_code(code):
    """Analyze VBA source (already statically extracted) for risk indicators."""
    code = code or ""

    autoexec = _find_keywords(code, AUTOEXEC_TRIGGERS)
    shell = _find_keywords(code, SHELL_CALLS)

    obfuscation_details = []
    if _BASE64_RE.search(code):
        obfuscation_details.append("base64-like string")
    chr_count = len(_CHR_RE.findall(code))
    if chr_count >= _CHR_THRESHOLD:
        obfuscation_details.append("Chr() character-code obfuscation")
    concat_count = len(_CONCAT_RE.findall(code))
    if concat_count >= _CONCAT_THRESHOLD:
        obfuscation_details.append("high string-concatenation density")

    urls = sorted(set(_URL_RE.findall(code)))
    ips = sorted(set(ip for ip in _IP_RE.findall(code)))

    return {
        "autoexec_triggers": autoexec,
        "shell_calls": shell,
        "obfuscation": bool(obfuscation_details),
        "obfuscation_details": obfuscation_details,
        "urls": urls,
        "ips": ips,
    }


def extract_office_macros(content, filename):
    """Statically extract VBA macro source from an Office document.

    Returns a dict: {has_macros, code, error}. On any parsing failure the error
    is captured and has_macros is False - a malformed attachment must not crash
    the scan.
    """
    # Imported lazily so a missing/oletools-incompatible environment degrades
    # gracefully rather than breaking module import.
    try:
        from oletools.olevba import VBA_Parser, TYPE_TEXT
    except Exception as exc:  # pragma: no cover - import guard
        logger.warning("oletools unavailable, skipping macro analysis: %s", exc)
        return {"has_macros": False, "code": "", "error": "oletools_unavailable"}

    vba_parser = None
    try:
        vba_parser = VBA_Parser(filename or "attachment", data=content)

        # When olevba cannot recognize the container as a real Office/OLE/OOXML
        # file it falls back to treating the raw bytes as a plain-text VBA
        # source file (type == TEXT), which would falsely report macros for any
        # non-office attachment. We only trust structurally-identified documents.
        if vba_parser.type == TYPE_TEXT:
            return {"has_macros": False, "code": "", "error": None}

        if not vba_parser.detect_vba_macros():
            return {"has_macros": False, "code": "", "error": None}

        code_parts = []
        for (_subfile, _stream, _vba_name, vba_code) in vba_parser.extract_macros():
            if vba_code:
                code_parts.append(vba_code)

        return {
            "has_macros": True,
            "code": "\n".join(code_parts),
            "error": None,
        }
    except Exception as exc:
        logger.warning("Macro extraction failed for %r: %s", filename, exc)
        return {"has_macros": False, "code": "", "error": "parse_error"}
    finally:
        if vba_parser is not None:
            try:
                vba_parser.close()
            except Exception:
                pass


def detect_embedded_objects(content, detected_type):
    """Detect embedded OLE objects / embedded files within a document.

    * OOXML (zip): embedded objects live under word/xl/ppt embeddings/ or
      oleObject parts inside the archive.
    * OLE/CFBF: embedded objects live in an ObjectPool storage or \\x01Ole
      streams.

    Pure structural inspection; nothing is opened or executed.
    """
    if not content:
        return False

    try:
        if detected_type == "ole" or content[:8] == OLE_MAGIC:
            return _ole_has_embedded_objects(content)
        if detected_type in ("docx", "xlsx", "pptx", "zip") or content[:4] == ZIP_MAGIC:
            return _zip_has_embedded_objects(content)
    except Exception as exc:
        logger.debug("Embedded-object detection failed: %s", exc)

    return False


def _zip_has_embedded_objects(content):
    with zipfile.ZipFile(BytesIO(content)) as zf:
        for name in zf.namelist():
            lowered = name.lower()
            if "embeddings/" in lowered or "/oleobject" in lowered or "embed" in lowered.split("/")[-1]:
                return True
    return False


def _ole_has_embedded_objects(content):
    try:
        import olefile
    except Exception:  # pragma: no cover - import guard
        return False

    if not olefile.isOleFile(BytesIO(content)):
        return False

    ole = olefile.OleFileIO(BytesIO(content))
    try:
        for entry in ole.listdir(streams=True, storages=True):
            joined = "/".join(part.lower() for part in entry)
            if "objectpool" in joined or "\x01ole" in joined or "\x01comp" in joined:
                return True
    finally:
        ole.close()
    return False


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def analyze_attachment(attachment, vt_client=None):
    """Run the full Tier 1 static analysis on one attachment dict.

    `attachment` must provide 'filename' and 'content' (raw bytes). A
    `vt_client` (app.virustotal.VirusTotalClient) is optional; if omitted or
    disabled, the VirusTotal result degrades to unavailable.
    """
    filename = attachment.get("filename", "") or ""
    content = attachment.get("content") or b""

    errors = []
    sha256 = compute_sha256(content)
    detected = detect_file_type(content)
    ext = claimed_extension(filename)
    mismatch = extension_mismatch(filename, detected)

    is_office = detected in ("ole", "docx", "xlsx", "pptx", "zip") or ext in OFFICE_EXTENSIONS

    macro = {
        "autoexec_triggers": [],
        "shell_calls": [],
        "obfuscation": False,
        "obfuscation_details": [],
        "urls": [],
        "ips": [],
    }
    has_macros = False

    if is_office:
        extracted = extract_office_macros(content, filename)
        if extracted["error"]:
            errors.append("macro:" + extracted["error"])
        has_macros = extracted["has_macros"]
        if has_macros:
            macro = analyze_vba_code(extracted["code"])

    embedded = False
    if is_office:
        embedded = detect_embedded_objects(content, detected)

    # VirusTotal reputation (hash only). Never allowed to raise.
    vt_result = None
    if vt_client is not None:
        try:
            vt_result = vt_client.lookup_hash(sha256)
        except Exception as exc:  # defensive: client already swallows errors
            logger.warning("VirusTotal lookup crashed for %s: %s", sha256, exc)
            vt_result = {"available": False, "status": "unavailable",
                         "reason": "client_error", "malicious": None, "total": None}
        if not vt_result.get("available"):
            logger.info(
                "VirusTotal unavailable for %s (%s); using static analysis only.",
                filename, vt_result.get("reason"),
            )

    return {
        "filename": filename,
        "size": len(content),
        "sha256": sha256,
        "detected_type": detected or "unknown",
        "claimed_extension": ext,
        "extension_mismatch": mismatch,
        "is_office_document": is_office,
        "has_macros": has_macros,
        "macro_autoexec_triggers": macro["autoexec_triggers"],
        "macro_shell_calls": macro["shell_calls"],
        "macro_obfuscation": macro["obfuscation"],
        "macro_obfuscation_details": macro["obfuscation_details"],
        "macro_urls": macro["urls"],
        "macro_ips": macro["ips"],
        "has_embedded_objects": embedded,
        "virustotal": vt_result,
        "analysis_errors": errors,
    }


def analyze_attachments(attachments, vt_client=None):
    """Analyze a list of attachment dicts; returns a list of finding dicts."""
    findings = []
    for attachment in attachments or []:
        try:
            findings.append(analyze_attachment(attachment, vt_client=vt_client))
        except Exception as exc:
            # A single bad attachment must not abort the whole message scan.
            logger.warning(
                "Attachment analysis failed for %r: %s",
                attachment.get("filename"), exc,
            )
            findings.append({
                "filename": attachment.get("filename", ""),
                "size": len(attachment.get("content") or b""),
                "sha256": compute_sha256(attachment.get("content") or b""),
                "detected_type": "unknown",
                "claimed_extension": claimed_extension(attachment.get("filename", "")),
                "extension_mismatch": False,
                "is_office_document": False,
                "has_macros": False,
                "macro_autoexec_triggers": [],
                "macro_shell_calls": [],
                "macro_obfuscation": False,
                "macro_obfuscation_details": [],
                "macro_urls": [],
                "macro_ips": [],
                "has_embedded_objects": False,
                "virustotal": None,
                "analysis_errors": ["analysis_error"],
            })
    return findings
