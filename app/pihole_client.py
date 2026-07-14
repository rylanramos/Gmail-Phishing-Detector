"""Thin, defensive client for the Pi-hole v6 REST API (session/SID-based auth).

Schemas below were confirmed against the live instance's own self-hosted
OpenAPI docs (http://<pihole-host>/api/docs/specs/{auth,queries}.yaml), which
match the exact API version running, not generic online documentation.

Design constraints (deliberate, mirroring app/virustotal.py):

* The API password is never hardcoded. Order of precedence: PIHOLE_API_PASSWORD
  environment variable, then credentials/pihole_api_password.txt (gitignored),
  matching how the VirusTotal API key is handled.
* Every failure mode - missing password, network error, bad credentials, rate
  limiting - degrades gracefully to an ``available=False`` result and is
  logged. A Pi-hole problem must never crash the correlation run.
* Sessions are short-lived (Pi-hole's default validity is a few minutes,
  confirmed live) and are explicitly closed (``DELETE /api/auth``) when the
  client is done, rather than left to expire server-side.

Auth flow (POST /api/auth):
    request:  {"password": "<app password or regular password>"}
    response: {"session": {"valid": true, "totp": false,
                            "sid": "vFA+EP4MQ5JJvJg+3Q2Jnw=",
                            "csrf": "Ux87YTIiMOf/GKCefVIOMw=",
                            "validity": 300, "message": "correct password"},
               "took": 0.003}
    Bad password -> HTTP 400 with a "password_inval" style error body.
    The SID is sent back on subsequent requests via the "sid" header.

Queries endpoint (GET /api/queries), confirmed live query params include:
    from, until (unix timestamps), length, start, cursor,
    domain (wildcard-capable: "*" matches any run of characters),
    client_ip, client_name, upstream, type, status, reply, dnssec, disk
    response: {"queries": [{"id": 112421354, "time": 1581907991.54,
                             "type": "A", "domain": "community.stoplight.io",
                             "cname": null, "status": "FORWARDED",
                             "client": {"ip": "192.168.0.14", "name": "desktop.lan"},
                             "dnssec": "INSECURE",
                             "reply": {"type": "IP", "time": 19},
                             "list_id": null, "upstream": "localhost#5353",
                             "ede": {"code": 0, "text": null}}, ...],
               "cursor": 175881, "recordsTotal": 1234, "recordsFiltered": 1234,
               ...}
"""

import logging
import os
import time
from pathlib import Path

import requests

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent
# Same pattern as credentials/virustotal_api_key.txt: a local, gitignored
# file under credentials/. The environment variable takes precedence so
# container/CI deployments never need a file on disk.
API_PASSWORD_FILE = BASE_DIR / "credentials" / "pihole_api_password.txt"

DEFAULT_BASE_URL = "http://192.168.2.52"


def get_api_password():
    """Return the Pi-hole API password, or None if it is not configured.

    Order of precedence: PIHOLE_API_PASSWORD environment variable, then the
    contents of credentials/pihole_api_password.txt.
    """
    env_password = os.environ.get("PIHOLE_API_PASSWORD", "").strip()
    if env_password:
        return env_password

    try:
        if API_PASSWORD_FILE.exists():
            password = API_PASSWORD_FILE.read_text(encoding="utf-8").strip()
            if password:
                return password
    except OSError as exc:
        logger.warning("Could not read Pi-hole API password file: %s", exc)

    return None


def unavailable_result(reason):
    """A neutral, non-crashing result used whenever Pi-hole cannot be reached
    or queried."""
    return {"available": False, "reason": reason, "queries": []}


class PiholeClient:
    """Session-based client for the Pi-hole v6 REST API.

    Authenticates lazily on first use (not in __init__, so constructing a
    client with no password configured never raises) and reuses the session
    ID until close() is called or a request comes back unauthorized, in which
    case a single re-authentication is attempted before giving up.
    """

    def __init__(
        self,
        base_url=None,
        password=None,
        session=None,
        max_retries=3,
        backoff_base=2.0,
        timeout=15,
        sleep=time.sleep,
    ):
        self.base_url = (base_url or os.environ.get("PIHOLE_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")
        self.password = password if password is not None else get_api_password()
        self.session = session or requests.Session()
        self.max_retries = max_retries
        self.backoff_base = backoff_base
        self.timeout = timeout
        self._sleep = sleep
        self._sid = None

    @property
    def enabled(self):
        return bool(self.password)

    def _url(self, path):
        return f"{self.base_url}/api{path}"

    def authenticate(self):
        """Establish a session. Returns True on success, False on any
        failure (never raises). Safe to call multiple times; a cached SID is
        reused until explicitly cleared."""
        if self._sid:
            return True

        if not self.password:
            logger.info(
                "Pi-hole authentication skipped: no API password configured."
            )
            return False

        try:
            response = self.session.post(
                self._url("/auth"),
                json={"password": self.password},
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            logger.warning("Pi-hole auth request error: %s", exc)
            return False

        if response.status_code == 200:
            try:
                body = response.json()
            except ValueError:
                logger.warning("Pi-hole auth returned malformed JSON.")
                return False
            session_info = body.get("session", {})
            if session_info.get("valid") and session_info.get("sid"):
                self._sid = session_info["sid"]
                return True
            logger.warning(
                "Pi-hole auth response did not contain a valid session: %s",
                session_info.get("message"),
            )
            return False

        if response.status_code == 400:
            logger.warning(
                "Pi-hole rejected the authentication request (400) - "
                "check the configured password."
            )
            return False

        if response.status_code == 429:
            logger.warning("Pi-hole auth rate-limited (429).")
            return False

        logger.warning(
            "Pi-hole auth returned unexpected status %d.", response.status_code
        )
        return False

    def close(self):
        """End the current session, if any. Best-effort; never raises."""
        if not self._sid:
            return
        try:
            self.session.delete(
                self._url("/auth"),
                headers={"sid": self._sid},
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            logger.info("Pi-hole session close failed (non-fatal): %s", exc)
        finally:
            self._sid = None

    def get_queries(self, domain=None, from_ts=None, until_ts=None, length=100,
                     client_ip=None):
        """Fetch recent DNS queries, optionally filtered.

        `domain` supports Pi-hole's wildcard syntax ("*" matches any run of
        characters). Returns a dict: {"available": bool, "queries": [...],
        and on failure "reason": str}. Never raises.
        """
        if not self.authenticate():
            return unavailable_result(
                "no_api_password" if not self.password else "auth_failed"
            )

        params = {"length": length}
        if domain is not None:
            params["domain"] = domain
        if from_ts is not None:
            params["from"] = from_ts
        if until_ts is not None:
            params["until"] = until_ts
        if client_ip is not None:
            params["client_ip"] = client_ip

        for attempt in range(self.max_retries + 1):
            try:
                response = self.session.get(
                    self._url("/queries"),
                    headers={"sid": self._sid},
                    params=params,
                    timeout=self.timeout,
                )
            except requests.RequestException as exc:
                logger.warning("Pi-hole queries request error: %s", exc)
                return unavailable_result("network_error")

            if response.status_code == 200:
                try:
                    body = response.json()
                except ValueError:
                    logger.warning("Pi-hole queries returned malformed JSON.")
                    return unavailable_result("malformed_response")
                return {"available": True, "queries": body.get("queries", [])}

            if response.status_code == 401:
                # Session may have expired between authenticate() and this
                # call; retry once with a fresh session before giving up.
                if attempt == 0:
                    self._sid = None
                    if self.authenticate():
                        continue
                logger.warning("Pi-hole rejected the session (401).")
                return unavailable_result("unauthorized")

            if response.status_code == 429:
                if attempt < self.max_retries:
                    delay = self.backoff_base * (2 ** attempt)
                    logger.info(
                        "Pi-hole rate limit hit; backing off %.1fs "
                        "(attempt %d/%d).", delay, attempt + 1, self.max_retries,
                    )
                    self._sleep(delay)
                    continue
                logger.warning("Pi-hole rate limit persisted after retries.")
                return unavailable_result("rate_limited")

            logger.warning(
                "Pi-hole queries returned unexpected status %d.",
                response.status_code,
            )
            return unavailable_result("http_%d" % response.status_code)

        return unavailable_result("rate_limited")
