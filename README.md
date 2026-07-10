# Gmail Phishing Detector

A read-only triage tool that scans a Gmail inbox via the Gmail API, scores each
message with a heuristic phishing classifier, and surfaces the results in a
Streamlit dashboard.

## How it works

1. **Auth & fetch** ([app/gmail_client.py](app/gmail_client.py), [app/parser.py](app/parser.py), [app/scanner.py](app/scanner.py)) — authenticates with Gmail via OAuth
   (read-only scope) and pulls recent messages, extracting headers, plain
   text/HTML bodies, and links. Gmail's `messages.list` excludes the Spam and
   Trash folders by default regardless of query terms, so `run_scan()` runs an
   explicit second pass with `in:spam` appended and merges the results
   (deduped) — otherwise a malicious attachment landing straight in Spam,
   exactly where this kind of thing lands, would be invisible to the scanner
   entirely. On by default; pass `include_spam=False` to opt out.
2. **Feature extraction** ([app/features.py](app/features.py)) — derives signals from the parsed
   message: sender/reply-to domain mismatch, raw-IP or punycode URLs, link
   shorteners, anchor-text vs. href mismatches, urgent/credential-lure
   language, and bulk-mail indicators (`List-Unsubscribe`, `List-Id`,
   `Precedence: bulk`).
3. **Attachment screening** ([app/attachments.py](app/attachments.py)) — Tier 1,
   static analysis and heuristics only (no execution, sandboxing, or
   detonation). For each attachment it determines the true file type from
   magic bytes (independent of the filename's claimed extension, flagging any
   mismatch), computes a SHA-256 hash, and for Office documents statically
   extracts VBA macro source with `oletools`/`olevba` to flag auto-execution
   triggers (`AutoOpen`, `AutoExec`, `Document_Open`, `Workbook_Open`),
   shell/process-execution calls (`Shell`, `WScript.Shell`, `CreateObject`),
   obfuscation indicators, and embedded URLs/IPs, plus any embedded OLE
   objects. Macros are read as *data* and never run. The SHA-256 is used for an
   optional VirusTotal reputation lookup (see Setup).
4. **Scoring** ([app/scorer.py](app/scorer.py)) — combines those signals into a 0+ score and a
   verdict (`safe` / `suspicious` / `likely phishing`). Structural signals
   (domain mismatches, IP/punycode URLs, link/text mismatches) carry full
   weight since they're hard for a legitimate sender to trigger by accident.
   Language-based signals (urgent or credential-related phrasing) are heavily
   discounted when the message carries bulk-mail headers or its links point
   back to the sender's own domain — this is what keeps legitimate marketing
   and transactional email from being flagged as phishing. Attachment-based
   malicious indicators (extension/type mismatch, VBA macros, auto-exec + shell
   combinations, embedded objects, VirusTotal hits) are treated as structural
   signals at full weight and are **not** discounted by the bulk-mail
   mechanism: a newsletter-shaped message carrying a weaponized attachment is
   not made safer by looking like a newsletter. A confirmed VirusTotal
   detection is the single highest-severity signal in the model.
5. **Storage** ([app/storage.py](app/storage.py)) — results are persisted to SQLite. Schema
   changes are applied through small, numbered, idempotent migrations
   (tracked in a `schema_version` table) so the database upgrades in place
   instead of needing to be deleted when the schema evolves. Per-attachment
   findings are stored in their own table, queryable per email.
6. **Dashboard** ([app/streamlit_app.py](app/streamlit_app.py)) — gated behind Google sign-in
   (see Setup): only an explicitly allowlisted Google account can view results
   or trigger a scan. Once signed in, it lets you trigger a scan, filter
   results by verdict, and inspect the extracted features, reasons, and
   attachment-level findings behind each verdict.

## Setup

1. Create and activate a virtual environment, then install dependencies:
   ```
   python -m venv venv
   venv\Scripts\activate       # Windows
   source venv/bin/activate    # macOS/Linux
   pip install -r requirements.txt
   ```
2. In the [Google Cloud Console](https://console.cloud.google.com/), create an
   OAuth client ID (Desktop app) with the Gmail API enabled, and download the
   client secret as `credentials/credentials.json`.
3. **(Optional) VirusTotal reputation lookups.** Attachment screening works
   without VirusTotal (static analysis only), but adding a free API key enables
   hash-based reputation checks. Create a free account at
   [virustotal.com](https://www.virustotal.com/), open your profile → **API
   Key**, and provide the key in either of the ways the rest of the project
   handles secrets:
   - set the `VIRUSTOTAL_API_KEY` environment variable, **or**
   - save it to `credentials/virustotal_api_key.txt` (gitignored, alongside
     `credentials/credentials.json`).

   **Only the SHA-256 hash of each attachment is ever sent to VirusTotal — the
   attachment bytes never leave your machine.** The tool queries the
   `GET /files/{hash}` endpoint and never uploads file content. A hash that is
   unknown to VirusTotal is recorded as `unknown` (a neutral result, not
   evidence of safety). If the key is missing or the API is unreachable or
   rate-limited, attachment screening degrades gracefully to static-analysis
   results and logs the degradation — it never crashes the scan. The public API
   has a low requests-per-minute ceiling, so lookups use bounded exponential
   backoff on rate-limit (429) responses.
4. **Dashboard sign-in.** The dashboard is gated behind Google sign-in and
   will not load without it. This uses a **separate** OAuth client from the
   one above (a **Web application** client, not Desktop — Streamlit's
   built-in auth requires a configured redirect URI, which a Desktop-app
   client doesn't support):
   - In the [Google Cloud Console](https://console.cloud.google.com/), create
     an OAuth 2.0 Client ID of type **Web application**, and add
     `http://<host>:8501/oauth2callback` (matching wherever you'll run the
     dashboard) to its authorized redirect URIs.
   - Create `.streamlit/secrets.toml` (gitignored — never commit this file)
     with:
     ```toml
     [auth]
     redirect_uri = "http://<host>:8501/oauth2callback"
     cookie_secret = "<a random secret, e.g. `python -c \"import secrets; print(secrets.token_hex(32))\"`>"
     client_id = "<client_id from the Web application OAuth client above>"
     client_secret = "<client_secret from the same client>"
     server_metadata_url = "https://accounts.google.com/.well-known/openid-configuration"
     ```
   - Restrict access by editing `ALLOWED_USERS` at the top of
     [app/streamlit_app.py](app/streamlit_app.py) to the Google account(s)
     that should be allowed in — any other authenticated account sees
     "Unauthorized account" and is stopped before any dashboard content
     renders.
   - This uses [Authlib](https://docs.authlib.org/) (already in
     `requirements.txt`) via Streamlit's built-in `st.login()` / `st.user` /
     `st.logout()`.
5. Run the dashboard:
   ```
   streamlit run app/streamlit_app.py
   ```
   The first run opens a browser window for the Gmail OAuth consent flow and
   writes a `token.json` in the project root for subsequent runs.

Alternatively, run a one-off scan from the command line:
```
python app/main.py
```

## Token maintenance

This app's Google OAuth consent screen is in **Testing** status (not
Production), which means Google expires issued refresh tokens after **7
days** — a deliberate policy for unverified apps, not a bug. When that
happens, a scan run on a headless machine (e.g. a remote container running
the scanner on a schedule) fails with
`google.auth.exceptions.RefreshError: invalid_grant`.

Minting a new refresh token requires a real, interactive browser consent
flow, which can only happen on a machine with a browser — not the headless
host. [regenerate-token.ps1](regenerate-token.ps1) automates every step of
that process except the browser "Allow" click itself:

```
pwsh -ExecutionPolicy Bypass -File .\regenerate-token.ps1
```

Run it from a machine with a browser (requires **PowerShell 7+**). It backs
up the existing `token.json`, deletes it so the interactive consent flow is
forced, runs `app/main.py` to trigger that flow, verifies a genuinely fresh
token was written (not just that a file exists), transfers it to the
configured remote host via `scp` (defaults to
`root@192.168.2.51:/opt/phishing-detector/token.json`), and verifies the
remote copy's hash matches before cleaning up the backup. It is designed to
be paranoid rather than optimistic: at no point does it leave the project
with neither a valid token nor a backup, and every failure path (cancelled
consent, timeout, unreachable host, failed transfer, mismatched remote copy,
etc.) exits with a distinct code and prints the exact current state plus the
recovery step needed — see the script's own comment header for the full list.

## Testing

Run the test suite from the repository root:
```
pytest
```
The suite (in [tests/](tests/)) has **204 tests** and covers both the
email-body pipeline and attachment screening:

- **Feature extraction and scoring** (`app/features.py`, `app/scorer.py`):
  known-phishing patterns individually and in combination (domain mismatches,
  raw-IP and punycode URLs, anchor-text/href mismatches, credential-lure
  language), known-good marketing, transactional, and personal mail, and edge
  cases around the safe/suspicious/likely-phishing thresholds — including a
  phish that adds a fraudulent `List-Unsubscribe` header to try to game the
  bulk-mail discount. Fixtures are realistic synthetic emails in
  [tests/fixtures/emails.py](tests/fixtures/emails.py), built through the same
  parser functions the production pipeline uses.
- **Attachment screening** (`app/attachments.py`, `app/virustotal.py`,
  `app/parser.py`, `app/storage.py`): magic-byte type detection and
  extension/type-mismatch flagging, SHA-256 hashing, and VBA macro indicator
  extraction (auto-exec triggers, shell/process calls, obfuscation, embedded
  URLs/IPs, embedded objects). The macro fixtures in
  [tests/fixtures/attachments.py](tests/fixtures/attachments.py) are minimal,
  **synthetic, benign** OLE/OOXML files generated at import time (no real
  malware, inert or otherwise) that are nonetheless really parsed and extracted
  by `oletools`/`olevba`, so they exercise the exact static code path a
  malicious file would. VirusTotal calls are mocked (both the known-malicious
  and unknown-hash response paths) — no network requests are made. Coverage also
  includes the storage migration, the parser's attachment-extraction path, and
  an **end-to-end regression test**
  (`test_newsletter_framing_does_not_suppress_weaponized_attachment_end_to_end`)
  that runs a fully newsletter-shaped message carrying a weaponized macro
  document through the real pipeline and pins the score at `80`
  (`likely phishing`), locking in the scoring order that prevents the bulk-mail
  discount from suppressing a malicious attachment.

## Known limitations

- The trusted-context discount reduces language-based signals when a
  message's links point back to the sender's own domain. This means a
  phishing email sent from attacker-controlled infrastructure, with
  self-consistent links (sender and landing page on the same
  attacker-owned domain), may not trigger language-based signals.
  Structural signals (domain mismatches, punycode, IP URLs, anchor/href
  mismatches) still apply at full weight regardless.

### Attachment screening (Tier 1)

- **Static analysis only.** This tier never executes, opens, sandboxes, or
  detonates attachments. VBA macro *source* is recovered by statically parsing
  and decompressing file streams (it is read as data, never run), so behavioral
  detection — what a macro would actually do at runtime — is out of scope. A
  macro that hides its intent from static keyword/pattern inspection (heavy
  runtime construction, novel obfuscation) can evade the macro heuristics.
- **Encrypted / password-protected Office documents cannot be analyzed for
  macros.** When a document's VBA streams are encrypted (the standard
  password-protection mechanism), the macro content cannot be statically
  extracted without the password, so no macro-based signals fire. Such a file is
  still typed and hashed, and its VirusTotal hash reputation still applies, but
  it will not raise macro/auto-exec/shell findings. It degrades silently rather
  than erroring.
- **Non-Office attachments get type + hash scrutiny only.** Every attachment
  receives magic-byte file-type detection, an extension/type-mismatch check,
  a SHA-256 hash, and (if configured) a VirusTotal hash-reputation lookup.
  Beyond that, deep structural inspection is limited to VBA macros in Office
  documents. PDFs are **not** parsed for embedded JavaScript or actions,
  archives (`.zip`, `.rar`, etc.) are **not** recursed into or unpacked, and
  Excel 4.0 / XLM macros are not deeply analyzed. A malicious PDF or a threat
  nested inside an archive will only be caught if its hash is already flagged by
  VirusTotal.
- **VirusTotal reputation depends on prior submission.** An unknown hash is
  treated as neutral (not clean), by design. A novel or targeted attachment that
  VirusTotal has never seen gets no reputation benefit, and only the static
  heuristics apply. When no API key is configured, or the API is unreachable or
  rate-limited, screening degrades to static-analysis-only and logs it.
- **Coarse extension/type-mismatch families.** The mismatch check groups types
  into broad families (office, executable, image, pdf, …). It reliably catches
  cross-family disguises (e.g. an executable named `invoice.pdf`) but will not
  flag same-family relabeling (e.g. an `.xlsx` renamed to `.docx`), and it does
  not fire when the true type cannot be determined from magic bytes.

## Notes

- Gmail access is read-only (`gmail.readonly` scope) — the app never
  modifies, sends, or deletes mail.
- `credentials/credentials.json`, `token.json`, `.streamlit/secrets.toml`,
  and the SQLite database are gitignored; they're local secrets/state and
  shouldn't be committed. `secrets.toml` should also be file-permissioned to
  the account running the dashboard only (e.g. `chmod 600`), since it holds
  the dashboard OAuth client secret and cookie-signing key.
