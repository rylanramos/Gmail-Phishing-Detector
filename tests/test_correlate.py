"""Tests for app.correlate: extracting flagged domains from email_analysis
and correlating them against Pi-hole's DNS query log.

Email fixtures are modeled on real shapes pulled from the production
database (a 'likely phishing'-scored bulk-marketing email with tracking-link
URLs whose registered domain differs from the sender - the exact pattern
flagged in this project's own README as a known false-positive source, which
makes it realistic material here regardless of whether it was a true
positive). Pi-hole query fixtures are modeled on the real response shape
confirmed against the live instance's self-hosted OpenAPI docs.
"""

import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

# correlate.py uses bare intra-package imports (e.g. `from features import ...`),
# so app/ must be on sys.path to import it - matching how it runs in production
# via `python app/correlate_main.py` (see tests/test_scanner.py for the same pattern).
APP_DIR = Path(__file__).resolve().parents[1] / "app"
sys.path.insert(0, str(APP_DIR))

import storage        # noqa: E402  (import after sys.path tweak)
from correlate import correlate, get_flagged_domains  # noqa: E402


@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    db_dir = tmp_path / "data"
    monkeypatch.setattr(storage, "DB_DIR", db_dir)
    monkeypatch.setattr(storage, "DB_FILE", db_dir / "test.db")
    storage.init_db()
    return storage.DB_FILE


def _save_email(message_id, sender_domain, verdict, score, subject="Test subject",
                 all_urls=None, analyzed_at=None):
    import json
    now = analyzed_at or datetime.utcnow().isoformat()
    raw_features = {"sender_domain": sender_domain, "all_urls": all_urls or []}

    with storage.get_connection() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO email_analysis (
                gmail_message_id, subject, sender, sender_domain,
                score, verdict, reasons, raw_features, snippet, analyzed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            message_id, subject, f"Sender <x@{sender_domain}>", sender_domain,
            score, verdict, json.dumps([]), json.dumps(raw_features), "snippet", now,
        ))
        conn.commit()


def _pihole_query(id_, domain, status="FORWARDED", client_ip="192.168.2.10",
                   client_name="main-pc", time_=1751900000.0):
    """Shaped exactly like a real Pi-hole /api/queries entry."""
    return {
        "id": id_, "time": time_, "type": "A", "domain": domain,
        "cname": None, "status": status,
        "client": {"ip": client_ip, "name": client_name},
        "dnssec": "INSECURE", "reply": {"type": "IP", "time": 19},
        "list_id": None, "upstream": "localhost#5353",
        "ede": {"code": 0, "text": None},
    }


class FakePiholeClient:
    """Stands in for app.pihole_client.PiholeClient at the interface level
    (enabled / get_queries / close), driven by a domain -> queries mapping so
    tests can assert exactly what correlate() does with real-shaped
    responses, without any HTTP mocking."""

    def __init__(self, domain_queries=None, enabled=True, unavailable_domains=None):
        self._domain_queries = domain_queries or {}
        self._unavailable_domains = unavailable_domains or set()
        self.enabled = enabled
        self.calls = []
        self.closed = False

    def get_queries(self, domain, from_ts=None, until_ts=None, length=100, client_ip=None):
        self.calls.append({"domain": domain, "from_ts": from_ts, "length": length})
        # correlate() always calls with a "*"-prefixed wildcard.
        assert domain.startswith("*")
        bare = domain[1:]
        if bare in self._unavailable_domains:
            return {"available": False, "reason": "network_error", "queries": []}
        return {"available": True, "queries": self._domain_queries.get(bare, [])}

    def close(self):
        self.closed = True


class TestGetFlaggedDomains:
    def test_sender_domain_extracted(self, temp_db):
        _save_email("phish-1", "paypal-account-review.com", "likely phishing", 80)

        flagged = get_flagged_domains()

        assert "paypal-account-review.com" in flagged
        assert flagged["paypal-account-review.com"][0]["source"] == "sender"
        assert flagged["paypal-account-review.com"][0]["gmail_message_id"] == "phish-1"

    def test_link_domains_extracted_and_reduced_to_registered_domain(self, temp_db):
        # Modeled on the real production shape: a bulk-marketing email whose
        # links are ESP tracking subdomains (view.email.ticketmaster.com),
        # which must reduce to the registered domain (ticketmaster.com).
        _save_email(
            "phish-1", "icloud.com", "likely phishing", 60,
            all_urls=[
                "https://view.email.ticketmaster.com/?qs=ABB7abc123",
                "https://click.email.ticketmaster.com/?qs=ABB7def456",
            ],
        )

        flagged = get_flagged_domains()

        assert "ticketmaster.com" in flagged
        sources = {p["source"] for p in flagged["ticketmaster.com"]}
        assert sources == {"link"}
        assert len(flagged["ticketmaster.com"]) == 2  # one per link URL

    def test_safe_emails_excluded(self, temp_db):
        _save_email("safe-1", "legit-sender.com", "safe", 0,
                    all_urls=["https://legit-sender.com/receipt"])

        flagged = get_flagged_domains()

        assert flagged == {}

    def test_suspicious_included_alongside_likely_phishing(self, temp_db):
        _save_email("susp-1", "sketchy.example", "suspicious", 35)
        _save_email("phish-1", "evil.example", "likely phishing", 80)

        flagged = get_flagged_domains()

        assert "sketchy.example" in flagged
        assert "evil.example" in flagged

    def test_lookback_window_excludes_old_emails(self, temp_db):
        old = (datetime.utcnow() - timedelta(days=30)).isoformat()
        _save_email("old-phish", "evil.example", "likely phishing", 80, analyzed_at=old)

        flagged = get_flagged_domains(lookback_days=7)

        assert flagged == {}

    def test_same_domain_from_multiple_emails_accumulates_provenance(self, temp_db):
        _save_email("phish-1", "evil.example", "likely phishing", 80, subject="First phish")
        _save_email("phish-2", "evil.example", "likely phishing", 90, subject="Second phish")

        flagged = get_flagged_domains()

        assert len(flagged["evil.example"]) == 2
        ids = {p["gmail_message_id"] for p in flagged["evil.example"]}
        assert ids == {"phish-1", "phish-2"}

    def test_urls_with_no_parseable_domain_are_skipped_not_crashing(self, temp_db):
        _save_email("phish-1", "evil.example", "likely phishing", 80,
                    all_urls=["not a url at all", ""])

        flagged = get_flagged_domains()

        # The sender domain is still there; the garbage URLs contribute nothing.
        assert "evil.example" in flagged
        assert len(flagged["evil.example"]) == 1  # sender only


class TestCorrelate:
    def test_correlate_self_migrates_an_unmigrated_database(self, tmp_path, monkeypatch):
        # Regression test: this script has its own systemd timer, independent
        # of the scanner's run_scan() (which calls init_db() itself), so it
        # must not assume the database has already been migrated - e.g. a
        # fresh install, or this timer's first fire racing the scanner's.
        # Deliberately does NOT use the temp_db fixture, which pre-migrates.
        db_dir = tmp_path / "data"
        monkeypatch.setattr(storage, "DB_DIR", db_dir)
        monkeypatch.setattr(storage, "DB_FILE", db_dir / "unmigrated.db")

        pihole = FakePiholeClient()
        result = correlate(pihole_client=pihole)  # must not raise "no such table"

        assert result["available"] is True
        assert result["flagged_domain_count"] == 0
        with storage.get_connection() as conn:
            row = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='pihole_correlations'"
            ).fetchone()
        assert row is not None

    def test_no_flagged_emails_short_circuits_without_pihole_call(self, temp_db):
        pihole = FakePiholeClient()

        result = correlate(pihole_client=pihole)

        assert result["available"] is True
        assert result["flagged_domain_count"] == 0
        assert result["hits"] == []
        assert pihole.calls == []

    def test_matching_dns_query_produces_a_hit(self, temp_db):
        _save_email("phish-1", "paypal-account-review.com", "likely phishing", 80,
                    subject="Verify your account now")
        pihole = FakePiholeClient(domain_queries={
            "paypal-account-review.com": [_pihole_query(101, "paypal-account-review.com")],
        })

        result = correlate(pihole_client=pihole)

        assert result["available"] is True
        assert result["flagged_domain_count"] == 1
        assert len(result["hits"]) == 1
        hit = result["hits"][0]
        assert hit["domain"] == "paypal-account-review.com"
        assert hit["gmail_message_id"] == "phish-1"
        assert hit["pihole_query_id"] == 101
        assert hit["pihole_client_ip"] == "192.168.2.10"

        # And it was actually persisted, queryable independently.
        assert len(storage.get_recent_pihole_correlations()) == 1

    def test_no_matching_query_produces_no_hit(self, temp_db):
        _save_email("phish-1", "evil.example", "likely phishing", 80)
        pihole = FakePiholeClient(domain_queries={})  # nothing ever queried

        result = correlate(pihole_client=pihole)

        assert result["hits"] == []
        assert storage.get_recent_pihole_correlations() == []

    def test_wildcard_prefilter_false_positive_is_excluded_client_side(self, temp_db):
        # Pi-hole's wildcard filter is a plain substring match server-side;
        # correlate() must re-check the registered domain and reject a
        # same-suffix decoy that a naive substring match would let through.
        _save_email("phish-1", "paypal.com", "likely phishing", 80)
        pihole = FakePiholeClient(domain_queries={
            "paypal.com": [
                _pihole_query(1, "paypal.com"),          # real match
                _pihole_query(2, "evil-paypal.com"),      # decoy: must be excluded
                _pihole_query(3, "paypal.com.evil.net"),  # decoy: must be excluded
            ],
        })

        result = correlate(pihole_client=pihole)

        assert len(result["hits"]) == 1
        assert result["hits"][0]["pihole_query_id"] == 1

    def test_subdomain_query_matches_registered_domain(self, temp_db):
        # A device querying a subdomain of a flagged registered domain still
        # counts: mirrors the real ticketmaster.com/exct.net tracking-link
        # pattern seen in production.
        _save_email("phish-1", "icloud.com", "likely phishing", 60,
                    all_urls=["https://click.email.ticketmaster.com/track"])
        pihole = FakePiholeClient(domain_queries={
            "ticketmaster.com": [_pihole_query(5, "click.email.ticketmaster.com")],
        })

        result = correlate(pihole_client=pihole)

        assert len(result["hits"]) == 1
        assert result["hits"][0]["domain"] == "ticketmaster.com"

    def test_no_password_configured_degrades_without_crashing(self, temp_db):
        _save_email("phish-1", "evil.example", "likely phishing", 80)
        pihole = FakePiholeClient(enabled=False)

        result = correlate(pihole_client=pihole)

        assert result["available"] is False
        assert result["reason"] == "no_api_password"
        assert result["flagged_domain_count"] == 1
        assert result["hits"] == []
        assert pihole.calls == []  # never attempted a query without a password

    def test_partial_pihole_failure_does_not_abort_remaining_domains(self, temp_db):
        _save_email("phish-1", "evil-one.example", "likely phishing", 80)
        _save_email("phish-2", "evil-two.example", "likely phishing", 80)
        pihole = FakePiholeClient(
            domain_queries={"evil-two.example": [_pihole_query(9, "evil-two.example")]},
            unavailable_domains={"evil-one.example"},
        )

        result = correlate(pihole_client=pihole)

        assert result["available"] is True
        assert result["reason"] == "partial_pihole_unavailable"
        assert len(result["hits"]) == 1
        assert result["hits"][0]["domain"] == "evil-two.example"

    def test_client_is_always_closed_even_on_partial_failure(self, temp_db):
        _save_email("phish-1", "evil.example", "likely phishing", 80)
        pihole = FakePiholeClient(unavailable_domains={"evil.example"})

        correlate(pihole_client=pihole)

        assert pihole.closed is True

    def test_same_domain_two_source_emails_both_produce_hits(self, temp_db):
        # Two different phishing emails reference the same attacker domain;
        # one real DNS query for it must still be attributed to both emails.
        _save_email("phish-1", "shared-evil.example", "likely phishing", 80, subject="Phish A")
        _save_email("phish-2", "shared-evil.example", "likely phishing", 90, subject="Phish B")
        pihole = FakePiholeClient(domain_queries={
            "shared-evil.example": [_pihole_query(7, "shared-evil.example")],
        })

        result = correlate(pihole_client=pihole)

        assert len(result["hits"]) == 2
        subjects = {h["email_subject"] for h in result["hits"]}
        assert subjects == {"Phish A", "Phish B"}
        assert len(storage.get_recent_pihole_correlations()) == 2

    def test_rerunning_correlate_does_not_duplicate_persisted_hits(self, temp_db):
        _save_email("phish-1", "evil.example", "likely phishing", 80)
        pihole_run_1 = FakePiholeClient(domain_queries={
            "evil.example": [_pihole_query(1, "evil.example")],
        })
        pihole_run_2 = FakePiholeClient(domain_queries={
            "evil.example": [_pihole_query(1, "evil.example")],
        })

        correlate(pihole_client=pihole_run_1)
        correlate(pihole_client=pihole_run_2)

        assert len(storage.get_recent_pihole_correlations()) == 1
