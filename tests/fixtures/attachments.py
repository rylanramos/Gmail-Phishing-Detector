"""Synthetic, benign attachment fixtures for the attachment-screening tests.

Everything here is generated from scratch at import time. There are NO real
malware samples, inert or otherwise, anywhere in this repository (it is public):
the fixtures are minimal, safe files that merely exercise the same static code
paths a malicious file would.

The macro-bearing fixtures are real enough that oletools/olevba genuinely
detects and statically extracts the embedded VBA source from them:

  * `make_ole_with_vba` builds a minimal OLE/CFBF (compound) file whose single
    stream carries VBA source compressed per the MS-OVBA 2.4.1 algorithm. This
    is the same container legacy .doc/.xls/.ppt and OOXML `vbaProject.bin` use.
  * `ms_ovba_compress` is a spec-compliant (literal-token-only) compressor,
    verified against olevba's own `decompress_stream`.

None of this executes anything - the VBA is stored as data and read back
statically. The "risky" sample macros contain the *keywords* a weaponized macro
would (AutoOpen, Shell, ...), but perform no harmful action.
"""

import io
import struct
import zipfile

SECTOR = 512
FREESECT = 0xFFFFFFFF
ENDOFCHAIN = 0xFFFFFFFE
FATSECT = 0xFFFFFFFD

OLE_MAGIC = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"


# ---------------------------------------------------------------------------
# Sample VBA source (benign keyword payloads)
# ---------------------------------------------------------------------------

BENIGN_MACRO = (
    'Attribute VB_Name = "Module1"\r\n'
    "Sub FormatCells()\r\n"
    "    Dim total As Double\r\n"
    "    total = 1 + 2\r\n"
    "    MsgBox \"Total is \" & total\r\n"
    "End Sub\r\n"
)

# The classic weaponized pattern: auto-executes on open and launches a process.
# It performs nothing harmful - it only contains the *keywords* a real dropper
# would, so it exercises the auto-exec + shell detection path.
AUTOOPEN_SHELL_MACRO = (
    'Attribute VB_Name = "Module1"\r\n'
    "Sub AutoOpen()\r\n"
    '    Dim wsh As Object\r\n'
    '    Set wsh = CreateObject("WScript.Shell")\r\n'
    '    Shell "notepad.exe", vbNormalFocus\r\n'
    "End Sub\r\n"
)

# Heavy obfuscation indicators (base64-ish blob, many Chr() calls, dense
# string concatenation) plus embedded IOCs.
OBFUSCATED_MACRO = (
    'Attribute VB_Name = "Module1"\r\n'
    "Sub AutoExec()\r\n"
    '    Dim s As String\r\n'
    '    s = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAABBBBBBBB"\r\n'
    '    s = Chr(104) & Chr(116) & Chr(116) & Chr(112) & Chr(58) & Chr(47)\r\n'
    '    s = "a" & "b" & "c" & "d" & "e" & "f" & "g" & "h" & "i" & "j" & "k" & "l"\r\n'
    '    s = "http://203.0.113.55/payload" & "?id=" & "1"\r\n'
    "End Sub\r\n"
)


# ---------------------------------------------------------------------------
# MS-OVBA compression (literal tokens only) - verified against olevba
# ---------------------------------------------------------------------------

def ms_ovba_compress(data):
    """Compress bytes into a valid MS-OVBA 2.4.1 CompressedContainer.

    Uses only literal tokens (no back-references), which keeps the encoder
    trivial while remaining spec-compliant. Each source slice is capped at 3600
    bytes so the compressed token stream (which adds one flag byte per eight
    literals) stays within the 4096-byte-per-chunk limit.
    """
    out = bytearray(b"\x01")  # signature byte
    pos = 0
    while pos < len(data):
        chunk = data[pos:pos + 3600]
        pos += len(chunk)
        tokens = bytearray()
        i = 0
        while i < len(chunk):
            group = chunk[i:i + 8]
            tokens.append(0x00)  # flag byte: all eight tokens are literals
            tokens.extend(group)
            i += 8
        chunk_size = len(tokens) + 2  # includes the 2-byte header
        header = ((chunk_size - 3) & 0x0FFF) | (0b011 << 12) | (1 << 15)
        out.extend(struct.pack("<H", header))
        out.extend(tokens)
    return bytes(out)


# ---------------------------------------------------------------------------
# Minimal OLE/CFBF writer (big sectors only)
# ---------------------------------------------------------------------------

def _dir_entry(name, obj_type, color, left, right, child, start, size):
    name_utf16 = name.encode("utf-16-le") + b"\x00\x00"
    name_len = len(name_utf16)
    e = bytearray(128)
    e[0:name_len] = name_utf16
    struct.pack_into("<H", e, 64, name_len)
    e[66] = obj_type          # 5 = root storage, 2 = stream
    e[67] = color             # 1 = black
    struct.pack_into("<i", e, 68, left)
    struct.pack_into("<i", e, 72, right)
    struct.pack_into("<i", e, 76, child)
    struct.pack_into("<I", e, 116, start)
    struct.pack_into("<Q", e, 120, size)
    return bytes(e)


def _make_ole(streams):
    """Build an OLE file from (name, bytes) streams, each >= 4096 bytes so they
    all live in regular (big) FAT sectors and no mini stream is needed."""
    def nsect(b):
        return (len(b) + SECTOR - 1) // SECTOR

    stream_start = {}
    cur = 0
    for name, data in streams:
        stream_start[name] = cur if data else ENDOFCHAIN
        cur += nsect(data)
    dir_sector = cur
    cur += 1
    fat_sector = cur
    cur += 1
    total = cur

    fat = [FREESECT] * total
    idx = 0
    for name, data in streams:
        n = nsect(data)
        for k in range(n):
            fat[idx + k] = (idx + k + 1) if k < n - 1 else ENDOFCHAIN
        idx += n
    fat[dir_sector] = ENDOFCHAIN
    fat[fat_sector] = FATSECT
    per = SECTOR // 4
    while len(fat) % per != 0:
        fat.append(FREESECT)

    entries = [_dir_entry("Root Entry", 5, 1, -1, -1, 1, ENDOFCHAIN, 0)]
    for i, (name, data) in enumerate(streams):
        right = (i + 2) if i < len(streams) - 1 else -1
        entries.append(_dir_entry(name, 2, 1, -1, right, -1, stream_start[name], len(data)))
    dir_bytes = b"".join(entries)
    if len(dir_bytes) % SECTOR:
        dir_bytes += b"\x00" * (SECTOR - (len(dir_bytes) % SECTOR))

    header = bytearray(512)
    header[0:8] = OLE_MAGIC
    struct.pack_into("<H", header, 24, 0x003E)
    struct.pack_into("<H", header, 26, 0x0003)
    struct.pack_into("<H", header, 28, 0xFFFE)
    struct.pack_into("<H", header, 30, 0x0009)   # sector shift -> 512
    struct.pack_into("<H", header, 32, 0x0006)   # mini sector shift -> 64
    struct.pack_into("<I", header, 44, 1)        # num FAT sectors
    struct.pack_into("<I", header, 48, dir_sector)
    struct.pack_into("<I", header, 56, 0x00001000)  # mini stream cutoff
    struct.pack_into("<I", header, 60, ENDOFCHAIN)
    struct.pack_into("<I", header, 64, 0)
    struct.pack_into("<I", header, 68, ENDOFCHAIN)
    struct.pack_into("<I", header, 72, 0)
    difat = [FREESECT] * 109
    difat[0] = fat_sector
    for i, v in enumerate(difat):
        struct.pack_into("<I", header, 76 + i * 4, v)

    body = bytearray()
    for name, data in streams:
        padded = data + b"\x00" * ((SECTOR - len(data) % SECTOR) % SECTOR)
        body.extend(padded)
    body.extend(dir_bytes)
    body.extend(b"".join(struct.pack("<I", v) for v in fat))
    return bytes(header) + bytes(body)


def _pad_source(vba_source):
    """Pad VBA source with benign comment lines so its compressed container is
    >= 4096 bytes (keeps the OLE stream in big sectors)."""
    filler = ("' benign padding comment line to reach the big-sector size\r\n") * 200
    return (vba_source + filler).encode("latin-1")


def make_ole_with_vba(vba_source):
    """Return bytes for a minimal OLE file carrying the given VBA source."""
    compressed = ms_ovba_compress(_pad_source(vba_source))
    return _make_ole([("Module1", compressed)])


# ---------------------------------------------------------------------------
# OOXML (zip) builders
# ---------------------------------------------------------------------------

def _make_ooxml(content_type, extra_parts=None):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/>'
            f'<Override PartName="/word/document.xml" ContentType="{content_type}"/>'
            '</Types>'
        )
        z.writestr(
            "_rels/.rels",
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
            'Target="word/document.xml"/></Relationships>'
        )
        z.writestr("word/document.xml", "<document><body><p>Hello</p></body></document>")
        for part_name, part_bytes in (extra_parts or {}).items():
            z.writestr(part_name, part_bytes)
    return buf.getvalue()


def make_clean_docx():
    """A well-formed .docx with no macros and no embedded objects."""
    return _make_ooxml(
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"
    )


def make_docm_with_macro(vba_source):
    """A macro-enabled Word document (.docm) whose word/vbaProject.bin carries
    the given VBA source in a real, statically-extractable form."""
    return _make_ooxml(
        "application/vnd.ms-word.document.macroEnabled.main+xml",
        extra_parts={"word/vbaProject.bin": make_ole_with_vba(vba_source)},
    )


def make_docx_with_embedded_object():
    """A .docx that embeds another file under word/embeddings/ (structural
    embedded-object signal), but has no macros."""
    return _make_ooxml(
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
        extra_parts={
            "word/embeddings/oleObject1.bin": make_ole_with_vba(BENIGN_MACRO),
        },
    )


# ---------------------------------------------------------------------------
# Non-office / mismatch fixtures
# ---------------------------------------------------------------------------

def make_fake_executable():
    """Bytes with a PE/MZ signature (detected as an executable). This is NOT a
    real program - just the header bytes plus padding - so it is safe to keep in
    a public repo while still exercising the executable-detection path."""
    return b"MZ" + b"\x90" * 128 + b"This is not a real executable." + b"\x00" * 64


def make_png_bytes():
    """A tiny but valid PNG signature block, detected as an image."""
    return bytes.fromhex("89504E470D0A1A0A") + b"\x00IHDR" + b"\x00" * 64


def make_pdf_bytes():
    return b"%PDF-1.5\n%\xe2\xe3\xcf\xd3\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF"


# ---------------------------------------------------------------------------
# Attachment / parsed-email helpers
# ---------------------------------------------------------------------------

def attachment(filename, content, mime_type="application/octet-stream"):
    """Build one attachment dict in the shape app.parser produces."""
    return {"filename": filename, "mime_type": mime_type, "size": len(content), "content": content}


def parsed_email_with_attachments(attachments, **overrides):
    """A minimal parsed-email dict (no body signals) carrying attachments, for
    end-to-end pipeline tests."""
    base = {
        "message_id": "att0000000000001",
        "thread_id": "att0000000000001",
        "snippet": "",
        "internal_date": "1751724862000",
        "from": '"Accounts Payable" <ap@vendor-portal-example.com>',
        "reply_to": "",
        "return_path": '"Accounts Payable" <ap@vendor-portal-example.com>',
        "subject": "Invoice attached",
        "date": "Sun, 05 Jul 2026 09:14:22 -0400",
        "list_unsubscribe": "",
        "list_id": "",
        "precedence": "",
        "plain_text": "Please see the attached invoice.",
        "html_text": "",
        "text_urls": [],
        "html_urls": [],
        "anchors": [],
        "attachments": attachments,
    }
    base.update(overrides)
    return base
