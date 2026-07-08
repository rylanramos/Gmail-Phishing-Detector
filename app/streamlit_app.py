import pandas as pd
import streamlit as st

from scanner import run_scan
from storage import (
    init_db,
    get_recent_results,
    get_results_by_verdict,
    get_summary_stats,
    get_top_suspicious_domains,
    get_attachments_for_message,
)

st.set_page_config(
    page_title="Gmail Phishing Detector",
    page_icon="🛡️",
    layout="wide"
)


def load_results(view, limit):
    if view == "All":
        return get_recent_results(limit=limit)
    if view == "Safe":
        return get_results_by_verdict("safe", limit=limit)
    if view == "Suspicious":
        return get_results_by_verdict("suspicious", limit=limit)
    return get_results_by_verdict("likely phishing", limit=limit)


def verdict_badge(verdict):
    if verdict == "safe":
        return "✅ Safe"
    if verdict == "suspicious":
        return "⚠️ Suspicious"
    return "🚨 Likely phishing"


def _virustotal_label(attachment):
    if not attachment.get("vt_available"):
        return "unavailable (static analysis only)"
    status = attachment.get("vt_status")
    if status == "malicious":
        return f"🚨 {attachment.get('vt_malicious')} / {attachment.get('vt_total')} engines flagged malicious"
    if status == "harmless":
        return f"clean ({attachment.get('vt_total')} engines, 0 malicious)"
    if status == "unknown":
        return "unknown hash (neutral, not a clean signal)"
    return status or "unavailable"


def render_attachments(message_id):
    """Surface persisted attachment-level findings for the selected email."""
    if not message_id:
        return

    attachments = get_attachments_for_message(message_id)
    st.markdown("**Attachments:**")
    if not attachments:
        st.write("- none")
        return

    for att in attachments:
        triggers = att.get("macro_triggers") or {}
        flags = []
        if att.get("extension_mismatch"):
            flags.append("⚠️ extension/type mismatch")
        if att.get("has_macros"):
            flags.append("📎 VBA macro detected")
        if triggers.get("autoexec"):
            flags.append("auto-exec: " + ", ".join(triggers["autoexec"]))
        if triggers.get("shell"):
            flags.append("shell/exec: " + ", ".join(triggers["shell"]))
        if triggers.get("obfuscation"):
            flags.append("obfuscation indicators")
        if triggers.get("urls") or triggers.get("ips"):
            flags.append("embedded URLs/IPs in macro")
        if triggers.get("embedded_objects"):
            flags.append("embedded OLE objects")

        header = (
            f"{att.get('filename') or '(unnamed)'} "
            f"— detected: {att.get('detected_type') or 'unknown'}"
        )
        with st.expander(header, expanded=bool(flags)):
            st.write(f"SHA-256: `{att.get('sha256') or 'n/a'}`")
            st.write(f"Claimed extension: {att.get('claimed_extension') or '(none)'}")
            st.write(f"VirusTotal: {_virustotal_label(att)}")
            if flags:
                st.markdown("Findings:")
                for flag in flags:
                    st.write(f"- {flag}")
            else:
                st.write("No attachment-level risk indicators.")


def main():
    init_db()

    st.title("🛡️ Gmail Phishing Detector")
    st.caption("Read-only Gmail analysis dashboard")

    with st.sidebar:
        st.header("Controls")
        max_scan = st.slider("Emails to scan", min_value=5, max_value=50, value=10, step=5)
        result_limit = st.slider("Rows to show", min_value=10, max_value=200, value=50, step=10)
        view = st.selectbox("Filter verdict", ["All", "Safe", "Suspicious", "Likely phishing"])

        default_query = "newer_than:7d -category:social -category:promotions"
        query = st.text_input("Gmail query", value=default_query)

        if st.button("Run scan", use_container_width=True):
            with st.spinner("Scanning mailbox..."):
                scan_result = run_scan(max_results=max_scan, query=query)
            st.session_state["last_scan"] = scan_result
            st.rerun()

    stats = get_summary_stats()
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total analyzed", stats["total"])
    c2.metric("Safe", stats["safe"])
    c3.metric("Suspicious", stats["suspicious"])
    c4.metric("Likely phishing", stats["likely_phishing"])

    if "last_scan" in st.session_state:
        last_scan = st.session_state["last_scan"]
        with st.expander("Last scan result", expanded=True):
            st.write(
                f"Found: {last_scan['found']} | "
                f"Analyzed: {last_scan['analyzed']} | "
                f"Skipped: {last_scan['skipped']}"
            )
            if last_scan["errors"]:
                st.error("Errors occurred during scan:")
                for err in last_scan["errors"]:
                    st.code(err)

    left, right = st.columns([2, 1])

    with right:
        st.subheader("Top suspicious domains")
        domains = get_top_suspicious_domains(limit=10)
        if domains:
            domain_df = pd.DataFrame(domains)
            st.dataframe(domain_df, use_container_width=True, hide_index=True)
        else:
            st.info("No suspicious domains recorded yet.")

    with left:
        st.subheader("Results")
        results = load_results(view, result_limit)

        if not results:
            st.info("No results found yet. Run a scan first.")
            return

        table_rows = []
        for item in results:
            table_rows.append({
                "Subject": item["subject"] or "(no subject)",
                "Sender": item["sender"] or "unknown",
                "Domain": item["sender_domain"] or "unknown",
                "Verdict": item["verdict"],
                "Score": item["score"],
                "Analyzed At": item["analyzed_at"],
            })

        results_df = pd.DataFrame(table_rows)
        st.dataframe(results_df, use_container_width=True, hide_index=True)

        st.subheader("Email details")
        options = []
        for item in results:
            subject = item["subject"] or "(no subject)"
            options.append(f"{subject} | {item['verdict']} | {item['score']}")

        selected_label = st.selectbox("Select an analyzed email", options)

        selected_index = options.index(selected_label)
        selected_item = results[selected_index]

        st.markdown(f"**Subject:** {selected_item['subject'] or '(no subject)'}")
        st.markdown(f"**Sender:** {selected_item['sender'] or 'unknown'}")
        st.markdown(f"**Sender domain:** {selected_item['sender_domain'] or 'unknown'}")
        st.markdown(f"**Verdict:** {verdict_badge(selected_item['verdict'])}")
        st.markdown(f"**Score:** {selected_item['score']}")
        st.markdown(f"**Analyzed at:** {selected_item['analyzed_at']}")
        st.markdown(f"**Snippet:** {selected_item['snippet'] or '(none)'}")

        st.markdown("**Reasons:**")
        if selected_item["reasons"]:
            for reason in selected_item["reasons"]:
                st.write(f"- {reason}")
        else:
            st.write("- none")

        render_attachments(selected_item.get("gmail_message_id"))

        st.markdown("**Extracted features:**")
        st.json(selected_item["raw_features"])


if __name__ == "__main__":
    main()