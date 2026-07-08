"""Unit tests for app.virustotal.VirusTotalClient.

Every VirusTotal call is mocked - no real network requests are made. Both the
'known malicious hash' and 'unknown hash' response paths are exercised, along
with rate-limit backoff, error handling, and graceful degradation.
"""

import pytest
import requests

from app import virustotal
from app.virustotal import VirusTotalClient, get_api_key


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
    """Returns queued responses in order; an Exception item is raised."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def get(self, url, headers=None, timeout=None):
        self.calls.append({"url": url, "headers": headers, "timeout": timeout})
        item = self._responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def _stats(malicious=0, suspicious=0, harmless=0, undetected=0, timeout=0):
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                    "timeout": timeout,
                }
            }
        }
    }


HASH = "a" * 64


class TestKnownHash:
    def test_known_malicious_hash_surfaces_engine_counts(self):
        session = FakeSession([FakeResponse(200, _stats(malicious=5, harmless=60, undetected=5))])
        client = VirusTotalClient(api_key="key", session=session)

        result = client.lookup_hash(HASH)

        assert result["available"] is True
        assert result["status"] == "malicious"
        assert result["malicious"] == 5
        assert result["total"] == 70

    def test_known_clean_hash_is_harmless(self):
        session = FakeSession([FakeResponse(200, _stats(malicious=0, harmless=68, undetected=2))])
        client = VirusTotalClient(api_key="key", session=session)

        result = client.lookup_hash(HASH)

        assert result["available"] is True
        assert result["status"] == "harmless"
        assert result["malicious"] == 0
        assert result["total"] == 70

    def test_hash_is_sent_not_content(self):
        session = FakeSession([FakeResponse(200, _stats(malicious=1, harmless=1))])
        client = VirusTotalClient(api_key="key", session=session)

        client.lookup_hash(HASH)

        # The request targets the GET /files/{hash} endpoint (no upload).
        assert session.calls[0]["url"].endswith("/files/" + HASH)
        assert session.calls[0]["headers"]["x-apikey"] == "key"


class TestUnknownHash:
    def test_unknown_hash_is_neutral_not_clean(self):
        session = FakeSession([FakeResponse(404)])
        client = VirusTotalClient(api_key="key", session=session)

        result = client.lookup_hash(HASH)

        assert result["available"] is True
        assert result["status"] == "unknown"
        # Not a malicious/harmless verdict: explicitly neutral.
        assert result["malicious"] is None


class TestGracefulDegradation:
    def test_missing_api_key_never_raises(self, monkeypatch):
        monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
        monkeypatch.setattr(virustotal, "get_api_key", lambda: None)
        client = VirusTotalClient(api_key=None, session=FakeSession([]))

        result = client.lookup_hash(HASH)

        assert result["available"] is False
        assert result["status"] == "unavailable"
        assert result["reason"] == "no_api_key"
        assert client.enabled is False

    def test_network_error_degrades_gracefully(self):
        session = FakeSession([requests.ConnectionError("boom")])
        client = VirusTotalClient(api_key="key", session=session)

        result = client.lookup_hash(HASH)

        assert result["available"] is False
        assert result["reason"] == "network_error"

    def test_unauthorized_key_degrades(self):
        session = FakeSession([FakeResponse(401)])
        client = VirusTotalClient(api_key="badkey", session=session)

        result = client.lookup_hash(HASH)

        assert result["available"] is False
        assert result["reason"] == "unauthorized"

    def test_malformed_json_degrades(self):
        session = FakeSession([FakeResponse(200, raise_json=True)])
        client = VirusTotalClient(api_key="key", session=session)

        result = client.lookup_hash(HASH)

        assert result["available"] is False
        assert result["reason"] == "malformed_response"

    def test_unexpected_status_degrades(self):
        session = FakeSession([FakeResponse(500)])
        client = VirusTotalClient(api_key="key", session=session)

        result = client.lookup_hash(HASH)

        assert result["available"] is False
        assert result["reason"] == "http_500"


class TestRateLimitBackoff:
    def test_retries_after_429_then_succeeds(self):
        session = FakeSession([
            FakeResponse(429),
            FakeResponse(429),
            FakeResponse(200, _stats(malicious=3, harmless=60)),
        ])
        sleeps = []
        client = VirusTotalClient(
            api_key="key", session=session, max_retries=3,
            backoff_base=2.0, sleep=sleeps.append,
        )

        result = client.lookup_hash(HASH)

        assert result["status"] == "malicious"
        assert result["malicious"] == 3
        # Exponential backoff: 2 * 2**0, then 2 * 2**1.
        assert sleeps == [2.0, 4.0]

    def test_persistent_rate_limit_exhausts_retries(self):
        session = FakeSession([FakeResponse(429)] * 4)
        sleeps = []
        client = VirusTotalClient(
            api_key="key", session=session, max_retries=3, sleep=sleeps.append,
        )

        result = client.lookup_hash(HASH)

        assert result["available"] is False
        assert result["reason"] == "rate_limited"
        assert len(sleeps) == 3  # one sleep per retry


class TestApiKeyResolution:
    def test_env_var_takes_precedence(self, monkeypatch, tmp_path):
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "env-key")
        key_file = tmp_path / "virustotal_api_key.txt"
        key_file.write_text("file-key", encoding="utf-8")
        monkeypatch.setattr(virustotal, "API_KEY_FILE", key_file)

        assert get_api_key() == "env-key"

    def test_falls_back_to_credentials_file(self, monkeypatch, tmp_path):
        monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
        key_file = tmp_path / "virustotal_api_key.txt"
        key_file.write_text("file-key\n", encoding="utf-8")
        monkeypatch.setattr(virustotal, "API_KEY_FILE", key_file)

        assert get_api_key() == "file-key"

    def test_none_when_unconfigured(self, monkeypatch, tmp_path):
        monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
        monkeypatch.setattr(virustotal, "API_KEY_FILE", tmp_path / "missing.txt")

        assert get_api_key() is None
