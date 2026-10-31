"""Run from the repository root: python -m streamlit run app.py."""

import json

import pandas as pd
import plotly.express as px
import streamlit as st

from sbom_triage.clients import LiveSources
from sbom_triage.demo import DEMO_SBOM, DemoSources
from sbom_triage.reports import csv_bytes, json_bytes, pdf_bytes
from sbom_triage.triage import scan

st.set_page_config(page_title="SBOM Triage", page_icon="🛡️", layout="wide")
st.caption("PRODUCT SECURITY / VULNERABILITY WORKBENCH")
st.title("From inventory to investigation")
st.write(
    "Correlate package vulnerabilities, inspect the evidence, and decide what to investigate first."
)

with st.sidebar:
    st.header("Scan workspace")
    if st.button("Load offline demo", type="primary", use_container_width=True):
        st.session_state.report = scan(json.dumps(DEMO_SBOM).encode(), DemoSources())
    st.divider()
    uploaded = st.file_uploader(
        "CycloneDX JSON", type=["json"], help="5 MiB / 500 components maximum"
    )
    consent = st.checkbox("Send package identifiers to OSV and CVE IDs to FIRST")
    st.caption(
        "Live mode uses public APIs. The full SBOM is not uploaded. Do not use proprietary identifiers without authorization."
    )
    if st.button(
        "Run live scan", disabled=uploaded is None or not consent, use_container_width=True
    ):
        st.session_state.pop("report", None)
        sources = LiveSources()
        try:
            with st.spinner("Matching packages and collecting evidence..."):
                st.session_state.report = scan(uploaded.getvalue(), sources)
        except ValueError as exc:
            st.error(str(exc))
        finally:
            sources.close()

report = st.session_state.get("report")
if report is None:
    st.info("Start with the offline demo, or upload an SBOM for a live scan.")
    st.markdown(
        "**Read the evidence in order:** package match → CVSS severity → EPSS likelihood → KEV exploitation evidence → product context."
    )
    st.stop()

if report["mode"] == "demo":
    st.warning(
        "OFFLINE DEMO — synthetic scores and API responses for teaching; not current vulnerability intelligence."
    )
if report["status"] == "partial":
    st.warning(
        "Partial coverage. Some components or data sources could not be assessed. Review Coverage below."
    )
st.caption(f"Generated {report['generated_at']} · Policy {report['policy_version']}")

summary = report["summary"]
metrics = st.columns(4)
metrics[0].metric("Components queried", f"{summary['queried']} / {summary['components']}")
metrics[1].metric("Findings", summary["findings"])
metrics[2].metric("Known exploited", sum(f["kev"] is True for f in report["findings"]))
metrics[3].metric("Incomplete evidence", summary["needs_review"])

results_tab, coverage_tab, policy_tab = st.tabs(
    ["Prioritized findings", "Coverage & sources", "How priority works"]
)
with results_tab:
    filters = st.columns([2, 1, 2])
    tiers = filters[0].multiselect(
        "Priority", ["P0", "P1", "P2", "P3"], default=["P0", "P1", "P2", "P3"]
    )
    only_kev = filters[1].checkbox("KEV only")
    search = filters[2].text_input("Find a package or vulnerability")
    findings = [
        f
        for f in report["findings"]
        if f["priority"] in tiers
        and (not only_kev or f["kev"] is True)
        and search.casefold() in (f["component"] + " " + " ".join(f["aliases"])).casefold()
    ]
    filtered_report = {
        **report,
        "findings": findings,
        "summary": {
            **summary,
            "findings": len(findings),
            "needs_review": sum(bool(f["review_notes"]) for f in findings),
        },
    }
    st.caption(
        f"Showing {len(findings)} of {summary['findings']} findings. Downloads use these filters; coverage remains scan-wide."
    )
    if findings:
        frame = pd.DataFrame(findings)
        charts = st.columns(2)
        by_priority = frame.groupby("priority").size().rename("findings").reset_index()
        by_severity = frame.groupby("severity").size().rename("findings").reset_index()
        charts[0].plotly_chart(
            px.bar(
                by_priority,
                x="priority",
                y="findings",
                title="Investigation queue",
                color="priority",
                color_discrete_map={
                    "P0": "#ef665b",
                    "P1": "#edae49",
                    "P2": "#5ba8e5",
                    "P3": "#71bda6",
                },
            ),
            use_container_width=True,
        )
        charts[1].plotly_chart(
            px.bar(
                by_severity,
                x="severity",
                y="findings",
                title="Technical severity",
                category_orders={
                    "severity": ["Critical", "High", "Medium", "Low", "None", "Unknown"]
                },
                color_discrete_sequence=["#69a8b6"],
            ),
            use_container_width=True,
        )
        table = frame[
            ["priority", "component", "version", "vulnerability", "cvss", "epss", "kev", "reason"]
        ].copy()
        table["epss"] = table["epss"].map(lambda x: f"{x:.2%}" if pd.notna(x) else "Unknown")
        table["kev"] = table["kev"].map({True: "Yes", False: "No", None: "Unknown"})
        st.dataframe(table, hide_index=True, use_container_width=True)
        selected = st.selectbox(
            "Inspect evidence",
            range(len(findings)),
            format_func=lambda i: f"{findings[i]['component']} · {findings[i]['vulnerability']}",
        )
        with st.expander("Aliases, vectors, source dates and affected ranges"):
            st.json(findings[selected])
    else:
        st.info(
            "No findings match these filters. Check coverage before interpreting this as a clean result."
        )
    buttons = st.columns(3)
    buttons[0].download_button(
        "Download CSV",
        csv_bytes(filtered_report),
        "report.csv",
        "text/csv",
        use_container_width=True,
    )
    buttons[1].download_button(
        "Download JSON evidence",
        json_bytes(filtered_report),
        "report.json",
        "application/json",
        use_container_width=True,
    )
    buttons[2].download_button(
        "Download PDF",
        pdf_bytes(filtered_report),
        "report.pdf",
        "application/pdf",
        use_container_width=True,
    )
with coverage_tab:
    st.dataframe(pd.DataFrame(report["components"]), hide_index=True, use_container_width=True)
    for error in report["errors"]:
        st.error(error)
    st.json(report["sources"])
    st.code(report["input_sha256"], language=None)
    st.caption(
        "SHA-256 identifies the exact input bytes. No known match does not mean a component is safe."
    )
with policy_tab:
    st.table(
        pd.DataFrame(
            [
                ["P0", "CISA KEV match", "Urgently assess applicability and mitigations"],
                ["P1", "CVSS ≥9.0 or EPSS ≥10%", "Prompt investigation"],
                ["P2", "CVSS ≥7.0, EPSS ≥1%, or missing evidence", "Investigate and track"],
                ["P3", "Complete evidence below those thresholds", "Review and track"],
            ],
            columns=["Priority", "Rule (first match wins)", "Action"],
        )
    )
    st.write(
        "These thresholds are a documented teaching policy. CVSS is severity; EPSS predicts exploitation in the next 30 days; KEV records observed exploitation. None proves that your particular product is exploitable."
    )
    st.write(
        "The tool does not automatically downgrade unreachable code. Document exposure, reachability, compensating controls and VEX evidence with a reviewer. Patient safety and validated change control remain separate assessments."
    )
