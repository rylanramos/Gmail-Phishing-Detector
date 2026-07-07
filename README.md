# Gmail Phishing Detector

A read-only triage tool that scans a Gmail inbox via the Gmail API, scores each
message with a heuristic phishing classifier, and surfaces the results in a
Streamlit dashboard.

## How it works

1. **Auth & fetch** ([app/gmail_client.py](app/gmail_client.py), [app/parser.py](app/parser.py)) — authenticates with Gmail via OAuth
   (read-only scope) and pulls recent messages, extracting headers, plain
   text/HTML bodies, and links.
2. **Feature extraction** ([app/features.py](app/features.py)) — derives signals from the parsed
   message: sender/reply-to domain mismatch, raw-IP or punycode URLs, link
   shorteners, anchor-text vs. href mismatches, urgent/credential-lure
   language, and bulk-mail indicators (`List-Unsubscribe`, `List-Id`,
   `Precedence: bulk`).
3. **Scoring** ([app/scorer.py](app/scorer.py)) — combines those signals into a 0+ score and a
   verdict (`safe` / `suspicious` / `likely phishing`). Structural signals
   (domain mismatches, IP/punycode URLs, link/text mismatches) carry full
   weight since they're hard for a legitimate sender to trigger by accident.
   Language-based signals (urgent or credential-related phrasing) are heavily
   discounted when the message carries bulk-mail headers or its links point
   back to the sender's own domain — this is what keeps legitimate marketing
   and transactional email from being flagged as phishing.
4. **Storage** ([app/storage.py](app/storage.py)) — results are persisted to SQLite. Schema
   changes are applied through small, numbered, idempotent migrations
   (tracked in a `schema_version` table) so the database upgrades in place
   instead of needing to be deleted when the schema evolves.
5. **Dashboard** ([app/streamlit_app.py](app/streamlit_app.py)) — lets you trigger a scan, filter
   results by verdict, and inspect the extracted features and reasons behind
   each verdict.

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
3. Run the dashboard:
   ```
   streamlit run app/streamlit_app.py
   ```
   The first run opens a browser window for the Gmail OAuth consent flow and
   writes a `token.json` in the project root for subsequent runs.

Alternatively, run a one-off scan from the command line:
```
python app/main.py
```

## Testing

Run the test suite from the repository root:
```
pytest
```
The suite (in [tests/](tests/)) covers the feature-extraction and scoring
logic in `app/features.py` and `app/scorer.py`: known-phishing patterns
individually and in combination (domain mismatches, raw-IP and punycode
URLs, anchor-text/href mismatches, credential-lure language), known-good
marketing, transactional, and personal mail, and edge cases around the
safe/suspicious/likely-phishing thresholds — including a phish that adds a
fraudulent `List-Unsubscribe` header to try to game the bulk-mail discount.
Fixtures are realistic synthetic emails in
[tests/fixtures/emails.py](tests/fixtures/emails.py), built through the same
parser functions the production pipeline uses.

## Notes

- Gmail access is read-only (`gmail.readonly` scope) — the app never
  modifies, sends, or deletes mail.
- `credentials/credentials.json`, `token.json`, and the SQLite database are
  gitignored; they're local secrets/state and shouldn't be committed.
