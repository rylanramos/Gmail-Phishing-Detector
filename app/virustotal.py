"""Hash-based reputation lookups against the VirusTotal public API (v3).

Design constraints (deliberate, see README):

* Only the SHA-256 hash of an attachment is ever transmitted. Attachment bytes
  never leave the host. We query the ``GET /files/{hash}`` endpoint, which does
  not upload anything.
* An unknown hash (HTTP 404) is a NEUTRAL result, not evidence of safety. It is
  reported with status ``"unknown"``.
* Every failure mode - missing API key, network error, rate limiting that
  outlasts our retries, malformed responses - degrades gracefully to an
  ``available=False`` result and is logged. A VirusTotal problem must never
  crash the overall scan; attachment screening falls back to static analysis.

The public API has a low requests-per-minute ceiling (historically 4/min), so a
429 response triggers bounded exponential backoff with retries.
"""

import logging
import os
import time
from pathlib import Path

import requests

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent
# Consistent with how credentials/credentials.json is handled for Gmail: a
# local, gitignored file under credentials/. The environment variable takes
# precedence so CI / container deployments never need a file on disk.
API_KEY_FILE = BASE_DIR / "credentials" / "virustotal_api_key.txt"

API_URL = "https://www.virustotal.com/api/v3/files/{sha256}"


def get_api_key():
    """Return the VirusTotal API key, or None if it is not configured.

    Order of precedence: VIRUSTOTAL_API_KEY environment variable, then the
    contents of credentials/virustotal_api_key.txt.
    """
    env_key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
    if env_key:
        return env_key

    try:
        if API_KEY_FILE.exists():
            key = API_KEY_FILE.read_text(encoding="utf-8").strip()
            if key:
                return key
    except OSError as exc:
        logger.warning("Could not read VirusTotal API key file: %s", exc)

    return None


def unavailable_result(reason):
    """A neutral, non-crashing result used whenever a lookup cannot be made."""
    return {
        "available": False,
        "status": "unavailable",
        "reason": reason,
        "malicious": None,
        "total": None,
    }


class VirusTotalClient:
    """Thin, defensive wrapper around the VirusTotal v3 file-report endpoint."""

    def __init__(
        self,
        api_key=None,
        session=None,
        max_retries=3,
        backoff_base=2.0,
        timeout=15,
        sleep=time.sleep,
    ):
        self.api_key = api_key if api_key is not None else get_api_key()
        self.session = session or requests.Session()
        self.max_retries = max_retries
        self.backoff_base = backoff_base
        self.timeout = timeout
        # Injectable so tests never actually sleep during backoff.
        self._sleep = sleep

    @property
    def enabled(self):
        return bool(self.api_key)

    def lookup_hash(self, sha256):
        """Look up a single SHA-256 hash.

        Returns a dict with an ``available`` flag and, when available, a
        ``status`` of ``"malicious"``, ``"harmless"`` or ``"unknown"`` plus the
        ``malicious``/``total`` engine counts. Never raises.
        """
        if not self.api_key:
            logger.info(
                "VirusTotal lookup skipped for %s: no API key configured; "
                "degrading to static analysis only.", sha256
            )
            return unavailable_result("no_api_key")

        url = API_URL.format(sha256=sha256)
        headers = {"x-apikey": self.api_key}

        for attempt in range(self.max_retries + 1):
            try:
                response = self.session.get(
                    url, headers=headers, timeout=self.timeout
                )
            except requests.RequestException as exc:
                logger.warning(
                    "VirusTotal request error for %s: %s", sha256, exc
                )
                return unavailable_result("network_error")

            if response.status_code == 200:
                return self._parse_report(response, sha256)

            if response.status_code == 404:
                # Hash unknown to VirusTotal: explicitly neutral.
                return {
                    "available": True,
                    "status": "unknown",
                    "malicious": None,
                    "total": None,
                }

            if response.status_code == 401:
                logger.warning(
                    "VirusTotal rejected the API key (401) for %s.", sha256
                )
                return unavailable_result("unauthorized")

            if response.status_code == 429:
                if attempt < self.max_retries:
                    delay = self.backoff_base * (2 ** attempt)
                    logger.info(
                        "VirusTotal rate limit hit for %s; backing off %.1fs "
                        "(attempt %d/%d).",
                        sha256, delay, attempt + 1, self.max_retries,
                    )
                    self._sleep(delay)
                    continue
                logger.warning(
                    "VirusTotal rate limit persisted for %s after %d retries.",
                    sha256, self.max_retries,
                )
                return unavailable_result("rate_limited")

            logger.warning(
                "VirusTotal returned unexpected status %d for %s.",
                response.status_code, sha256,
            )
            return unavailable_result("http_%d" % response.status_code)

        return unavailable_result("rate_limited")

    def _parse_report(self, response, sha256):
        try:
            stats = (
                response.json()
                .get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
            )
        except ValueError:
            logger.warning(
                "VirusTotal returned malformed JSON for %s.", sha256
            )
            return unavailable_result("malformed_response")

        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        total = sum(int(v or 0) for v in stats.values())

        return {
            "available": True,
            "status": "malicious" if malicious > 0 else "harmless",
            "malicious": malicious,
            "suspicious": suspicious,
            "total": total,
        }
