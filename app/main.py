"""CLI entry point. Runs a scan and prints a human-readable summary.

For programmatic use (e.g. the Streamlit dashboard), call
scanner.run_scan() directly instead of importing this module.
"""

from scanner import run_scan


def print_results(scan_result):
    for item in scan_result["results"]:
        print("=" * 70)
        print(f"Subject       : {item['subject']}")
        print(f"From          : {item['from']}")
        print(f"Reply-To      : {item['reply_to'] or 'none'}")
        print(f"Sender Domain : {item['sender_domain'] or 'unknown'}")
        print(f"Verdict       : {item['verdict']}")
        print(f"Score         : {item['score']}")
        print(f"Links         : {item['url_count']}")
        print("Reasons:")
        if item["reasons"]:
            for reason in item["reasons"]:
                print(f"  - {reason}")
        else:
            print("  - none")
        print()

    for error in scan_result["errors"]:
        print(f"Error processing message: {error}")

    print("=" * 70)
    print("Run complete.")
    print(f"Analyzed : {scan_result['analyzed']}")
    print(f"Skipped  : {scan_result['skipped']}")


def main():
    scan_result = run_scan(max_results=10)
    print_results(scan_result)


if __name__ == "__main__":
    main()
