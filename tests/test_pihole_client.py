"""Unit tests for app.pihole_client.PiholeClient.

Every Pi-hole call is mocked - no real network requests are made. Request/
response shapes are pinned to what was confirmed against the live instance's
own self-hosted OpenAPI docs (POST/DELETE /api/auth, GET /api/queries).
"""

import pytest
import requests

from app import pihole_client
from app.pihole_client import PiholeClient, get_api_password


class FakeResponse:
    def __init__(self, status_code, json_data=None, raise_json=False):
        self.status_code = status_code
        self._json = json_data
        self._raise_json = raise_json

    def json(self):
        if self._raise_json:
            raise ValueError("malformed json")
        return self._json


class FakeSession:
    """Separate response queues per HTTP verb, since a single correlation run
    authenticates once (POST) but may issue many GETs against the cached
    session, and closes with one DELETE."""

    def __init__(self, post=None, get=None, delete=None):
        self._post = list(post or [])
        self._get = list(get or [])
        self._delete = list(delete or [])
        self.post_calls = []
        self.get_calls = []
        self.delete_calls = []

    def _pop(self, queue, calls, record):
        calls.append(record)
        item = queue.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    def post(self, url, json=None, timeout=None):
        return self._pop(self._post, self.post_calls,
                          {"url": url, "json": json, "timeout": timeout})

    def get(self, url, headers=None, params=None, timeout=None):
        return self._pop(self._get, self.get_calls,
                          {"url": url, "headers": headers, "params": params, "timeout": timeout})

    def delete(self, url, headers=None, timeout=None):
        return self._pop(self._delete, self.delete_calls,
                          {"url": url, "headers": headers, "timeout": timeout})


AUTH_OK = {
    "session": {
        "valid": True, "totp": False,
        "sid": "vFA+EP4MQ5JJvJg+3Q2Jnw=",
        "csrf": "Ux87YTIiMOf/GKCefVIOMw=",
        "validity": 300, "message": "correct password",
    },
    "took": 0.003,
}

AUTH_BAD_PASSWORD = {
    "error": {"key": "bad_request", "message": "Invalid password", "hint": None},
    "took": 0.001,
}


def _query(id_, domain, status="FORWARDED", client_ip="192.168.2.10",
           client_name="main-pc", time_=1751900000.0):
    return {
        "id": id_, "time": time_, "type": "A", "domain": domain,
        "cname": None, "status": status,
        "client": {"ip": client_ip, "name": client_name},
        "dnssec": "INSECURE", "reply": {"type": "IP", "time": 19},
        "list_id": None, "upstream": "localhost#5353",
        "ede": {"code": 0, "text": None},
    }


class TestAuthenticate:
    def test_successful_auth_caches_sid(self):
        session = FakeSession(post=[FakeResponse(200, AUTH_OK)])
        client = PiholeClient(password="app-pw", session=session)

        assert client.authenticate() is True
        assert client._sid == "vFA+EP4MQ5JJvJg+3Q2Jnw="
        # A second call must reuse the cached SID, not POST again.
        assert client.authenticate() is True
        assert len(session.post_calls) == 1

    def test_bad_password_fails_cleanly(self):
        session = FakeSession(post=[FakeResponse(400, AUTH_BAD_PASSWORD)])
        client = PiholeClient(password="wrong", session=session)

        assert client.authenticate() is False
        assert client._sid is None

    def test_no_password_configured_skips_without_network_call(self):
        session = FakeSession()
        client = PiholeClient(password=None, session=session)

        assert client.enabled is False
        assert client.authenticate() is False
        assert session.post_calls == []

    def test_network_error_degrades_gracefully(self):
        session = FakeSession(post=[requests.ConnectionError("boom")])
        client = PiholeClient(password="app-pw", session=session)

        assert client.authenticate() is False

    def test_malformed_json_degrades_gracefully(self):
        session = FakeSession(post=[FakeResponse(200, raise_json=True)])
        client = PiholeClient(password="app-pw", session=session)

        assert client.authenticate() is False

    def test_rate_limited_auth_fails_without_crashing(self):
        session = FakeSession(post=[FakeResponse(429)])
        client = PiholeClient(password="app-pw", session=session)

        assert client.authenticate() is False

    def test_password_sent_not_leaked_in_url(self):
        session = FakeSession(post=[FakeResponse(200, AUTH_OK)])
        client = PiholeClient(base_url="http://192.168.2.52", password="app-pw", session=session)

        client.authenticate()

        call = session.post_calls[0]
        assert call["url"] == "http://192.168.2.52/api/auth"
        assert call["json"] == {"password": "app-pw"}


class TestGetQueries:
    def test_matching_domain_returned(self):
        session = FakeSession(
            post=[FakeResponse(200, AUTH_OK)],
            get=[FakeResponse(200, {"queries": [_query(1, "paypal-secure-login.com")]})],
        )
        client = PiholeClient(password="app-pw", session=session)

        result = client.get_queries(domain="*paypal-secure-login.com")

        assert result["available"] is True
        assert len(result["queries"]) == 1
        assert result["queries"][0]["domain"] == "paypal-secure-login.com"

    def test_sid_sent_as_header(self):
        session = FakeSession(
            post=[FakeResponse(200, AUTH_OK)],
            get=[FakeResponse(200, {"queries": []})],
        )
        client = PiholeClient(password="app-pw", session=session)

        client.get_queries(domain="*example.com")

        call = session.get_calls[0]
        assert call["headers"]["sid"] == "vFA+EP4MQ5JJvJg+3Q2Jnw="
        assert call["params"]["domain"] == "*example.com"

    def test_no_password_returns_unavailable_without_network_call(self):
        session = FakeSession()
        client = PiholeClient(password=None, session=session)

        result = client.get_queries(domain="*example.com")

        assert result["available"] is False
        assert result["reason"] == "no_api_password"
        assert result["queries"] == []
        assert session.get_calls == []

    def test_expired_session_reauthenticates_once(self):
        session = FakeSession(
            post=[FakeResponse(200, AUTH_OK), FakeResponse(200, AUTH_OK)],
            get=[FakeResponse(401), FakeResponse(200, {"queries": [_query(2, "evil.com")]})],
        )
        client = PiholeClient(password="app-pw", session=session)

        result = client.get_queries(domain="*evil.com")

        assert result["available"] is True
        assert len(result["queries"]) == 1
        assert len(session.post_calls) == 2  # initial auth + re-auth after 401

    def test_persistent_unauthorized_degrades_gracefully(self):
        session = FakeSession(
            post=[FakeResponse(200, AUTH_OK), FakeResponse(200, AUTH_OK)],
            get=[FakeResponse(401), FakeResponse(401)],
        )
        client = PiholeClient(password="app-pw", session=session)

        result = client.get_queries(domain="*evil.com")

        assert result["available"] is False
        assert result["reason"] == "unauthorized"

    def test_rate_limit_backoff_then_success(self):
        session = FakeSession(
            post=[FakeResponse(200, AUTH_OK)],
            get=[FakeResponse(429), FakeResponse(200, {"queries": []})],
        )
        sleeps = []
        client = PiholeClient(password="app-pw", session=session, sleep=sleeps.append)

        result = client.get_queries(domain="*example.com")

        assert result["available"] is True
        assert sleeps == [2.0]

    def test_network_error_degrades_gracefully(self):
        session = FakeSession(
            post=[FakeResponse(200, AUTH_OK)],
            get=[requests.ConnectionError("boom")],
        )
        client = PiholeClient(password="app-pw", session=session)

        result = client.get_queries(domain="*example.com")

        assert result["available"] is False
        assert result["reason"] == "network_error"

    def test_no_results_is_a_clean_empty_list(self):
        session = FakeSession(
            post=[FakeResponse(200, AUTH_OK)],
            get=[FakeResponse(200, {"queries": []})],
        )
        client = PiholeClient(password="app-pw", session=session)

        result = client.get_queries(domain="*never-queried.example")

        assert result["available"] is True
        assert result["queries"] == []


class TestClose:
    def test_close_sends_delete_with_sid(self):
        session = FakeSession(
            post=[FakeResponse(200, AUTH_OK)],
            delete=[FakeResponse(204)],
        )
        client = PiholeClient(password="app-pw", session=session)
        client.authenticate()

        client.close()

        assert session.delete_calls[0]["headers"]["sid"] == "vFA+EP4MQ5JJvJg+3Q2Jnw="
        assert client._sid is None

    def test_close_without_a_session_is_a_noop(self):
        session = FakeSession()
        client = PiholeClient(password="app-pw", session=session)

        client.close()  # never authenticated - must not call delete or raise

        assert session.delete_calls == []

    def test_close_swallows_network_errors(self):
        session = FakeSession(
            post=[FakeResponse(200, AUTH_OK)],
            delete=[requests.ConnectionError("boom")],
        )
        client = PiholeClient(password="app-pw", session=session)
        client.authenticate()

        client.close()  # must not raise


class TestApiPasswordResolution:
    def test_env_var_takes_precedence(self, monkeypatch, tmp_path):
        monkeypatch.setenv("PIHOLE_API_PASSWORD", "env-pw")
        pw_file = tmp_path / "pihole_api_password.txt"
        pw_file.write_text("file-pw", encoding="utf-8")
        monkeypatch.setattr(pihole_client, "API_PASSWORD_FILE", pw_file)

        assert get_api_password() == "env-pw"

    def test_falls_back_to_credentials_file(self, monkeypatch, tmp_path):
        monkeypatch.delenv("PIHOLE_API_PASSWORD", raising=False)
        pw_file = tmp_path / "pihole_api_password.txt"
        pw_file.write_text("file-pw\n", encoding="utf-8")
        monkeypatch.setattr(pihole_client, "API_PASSWORD_FILE", pw_file)

        assert get_api_password() == "file-pw"

    def test_none_when_unconfigured(self, monkeypatch, tmp_path):
        monkeypatch.delenv("PIHOLE_API_PASSWORD", raising=False)
        monkeypatch.setattr(pihole_client, "API_PASSWORD_FILE", tmp_path / "missing.txt")

        assert get_api_password() is None
