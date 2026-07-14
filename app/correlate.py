"""Correlate phishing-detector-flagged domains against Pi-hole's DNS query
log: a domain that both (a) the phishing detector flagged as suspicious or
likely-phishing (via a sender address or a link in the email body) and
(b) a device on the network actually queried, is a materially stronger
signal than either tool alone - it means a domain that arrived via a
phishing email was actually resolved by something on the network, not just
theoretically dangerous.

Flagged domains come from two places in email_analysis, both reduced to
their registered domain via the same app.features helpers the scorer itself
uses, for consistency:
  * sender_domain (the email's From address domain)
  * raw_features["all_urls"] (every link URL found in the email body)

Pi-hole is queried per flagged domain (not by pulling and filtering the
entire recent query log) using its wildcard domain filter, then results are
re-checked client-side against the exact registered domain to eliminate
false-positive substring matches from the wildcard (e.g. a "*paypal.com"
filter must not treat "notpaypal.com" as a match).
"""

import logging
from datetime import datetime, timedelta, timezone

from features import get_domain_from_url, get_registered_domain
from pihole_client import PiholeClient
from storage import get_flagged_emails_since, init_db, save_pihole_correlation

logger = logging.getLogger(__name__)

DEFAULT_EMAIL_LOOKBACK_DAYS = 7
DEFAULT_PIHOLE_LOOKBACK_HOURS = 24


def get_flagged_domains(lookback_days=DEFAULT_EMAIL_LOOKBACK_DAYS):
    """Return {registered_domain: [provenance, ...]} for every domain found
    on a suspicious/likely-phishing email analyzed within the lookback
    window. Each provenance dict identifies which email and which source
    (sender address vs. a body link) the domain came from."""
    cutoff = (datetime.utcnow() - timedelta(days=lookback_days)).isoformat()
    flagged_emails = get_flagged_emails_since(cutoff)

    domains = {}

    def add(domain, source, email):
        if not domain:
            return
        registered = get_registered_domain(domain)
        if not registered:
            return
        domains.setdefault(registered, []).append({
            "source": source,
            "gmail_message_id": email["gmail_message_id"],
            "verdict": email["verdict"],
            "score": email["score"],
            "subject": email["subject"],
        })

    for email in flagged_emails:
        add(email.get("sender_domain"), "sender", email)

        all_urls = (email.get("raw_features") or {}).get("all_urls") or []
        for url in all_urls:
            add(get_domain_from_url(url), "link", email)

    return domains


def _matching_queries(pihole, domain, from_ts):
    """Query Pi-hole for `domain` (via a wildcard prefilter) and return only
    the results whose own registered domain is an EXACT match - the wildcard
    is a plain substring match server-side, so this client-side re-check is
    what prevents e.g. "evil-paypal.com" from matching a "paypal.com" filter."""
    result = pihole.get_queries(domain=f"*{domain}", from_ts=from_ts, length=500)
    if not result["available"]:
        return result

    exact_matches = [
        q for q in result["queries"]
        if get_registered_domain(q.get("domain", "")) == domain
    ]
    return {"available": True, "queries": exact_matches}


def correlate(email_lookback_days=DEFAULT_EMAIL_LOOKBACK_DAYS,
              pihole_lookback_hours=DEFAULT_PIHOLE_LOOKBACK_HOURS,
              pihole_client=None):
    """Run one correlation pass. Returns a summary dict; never raises -
    Pi-hole being unreachable or unconfigured degrades to an empty,
    clearly-flagged result rather than crashing the scheduled run."""
    # This script is scheduled independently of the scanner (its own systemd
    # timer), so it cannot assume run_scan() has already migrated the
    # database - e.g. on a fresh install, or if this timer's first fire
    # happens to race the scanner's.
    init_db()

    flagged_domains = get_flagged_domains(email_lookback_days)

    if not flagged_domains:
        return {
            "available": True,
            "flagged_domain_count": 0,
            "hits": [],
            "reason": None,
        }

    pihole = pihole_client or PiholeClient()

    if not pihole.enabled:
        logger.warning(
            "Pi-hole correlation skipped: no API password configured "
            "(set PIHOLE_API_PASSWORD or credentials/pihole_api_password.txt)."
        )
        return {
            "available": False,
            "flagged_domain_count": len(flagged_domains),
            "hits": [],
            "reason": "no_api_password",
        }

    from_ts = (
        datetime.now(timezone.utc) - timedelta(hours=pihole_lookback_hours)
    ).timestamp()

    hits = []
    unreachable = False

    try:
        for domain, provenance_list in flagged_domains.items():
            result = _matching_queries(pihole, domain, from_ts)

            if not result["available"]:
                # A Pi-hole hiccup on one domain shouldn't abort the whole
                # run; log it and keep checking the remaining domains.
                logger.warning(
                    "Pi-hole query for domain %r unavailable (%s); skipping.",
                    domain, result.get("reason"),
                )
                unreachable = True
                continue

            for pihole_query in result["queries"]:
                for provenance in provenance_list:
                    hit = {
                        "domain": domain,
                        "domain_source": provenance["source"],
                        "gmail_message_id": provenance["gmail_message_id"],
                        "email_verdict": provenance["verdict"],
                        "email_score": provenance["score"],
                        "email_subject": provenance["subject"],
                        "pihole_query_id": pihole_query.get("id"),
                        "pihole_query_time": pihole_query.get("time"),
                        "pihole_client_ip": (pihole_query.get("client") or {}).get("ip"),
                        "pihole_client_name": (pihole_query.get("client") or {}).get("name"),
                        "pihole_query_status": pihole_query.get("status"),
                    }
                    save_pihole_correlation(hit)
                    hits.append(hit)
    finally:
        pihole.close()

    return {
        "available": True,
        "flagged_domain_count": len(flagged_domains),
        "hits": hits,
        "reason": "partial_pihole_unavailable" if unreachable else None,
    }
