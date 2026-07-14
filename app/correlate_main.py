"""CLI entry point for the Pi-hole correlation check. Runs one correlation
pass and prints a human-readable summary. Intended to be invoked on a
schedule via systemd (see systemd/phishing-pihole-correlate.{service,timer}),
the same pattern app/main.py uses for the email scanner.
"""

from correlate import correlate


def print_summary(result):
    print("=" * 70)
    if not result["available"]:
        print("Pi-hole correlation SKIPPED:", result["reason"])
        print(f"Flagged domains that would have been checked: {result['flagged_domain_count']}")
        print("=" * 70)
        return

    print(f"Flagged domains checked : {result['flagged_domain_count']}")
    print(f"Correlation hits        : {len(result['hits'])}")
    if result["reason"] == "partial_pihole_unavailable":
        print("NOTE: one or more Pi-hole lookups failed; results may be incomplete.")
    print()

    if result["hits"]:
        for hit in result["hits"]:
            print("-" * 70)
            print(f"Domain        : {hit['domain']} (via {hit['domain_source']})")
            print(f"From email    : {hit['email_subject']} [{hit['email_verdict']}, score {hit['email_score']}]")
            print(f"Gmail msg id  : {hit['gmail_message_id']}")
            print(f"DNS query at  : {hit['pihole_query_time']}")
            print(f"Client        : {hit['pihole_client_name'] or 'unknown'} ({hit['pihole_client_ip']})")
            print(f"Query status  : {hit['pihole_query_status']}")
    else:
        print("No devices on the network queried any flagged domain.")

    print("=" * 70)


def main():
    result = correlate()
    print_summary(result)


if __name__ == "__main__":
    main()
