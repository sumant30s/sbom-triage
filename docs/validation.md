# Validation record

Validated on **1 November 2026 (India time)** in a Linux / Python 3.12 environment. API provenance in JSON uses UTC timestamps.

| Check | Observed result |
|---|---|
| pytest | 54 passed, including Streamlit AppTest interactions |
| Ruff | All checks passed |
| Bandit | No findings in `src` and `app.py` |
| Semgrep | 3 local rules, 8 Python source files, 0 findings |
| Dependency consistency | `pip check`: no broken requirements |
| Offline demo | 5 components; 4 queried; 1 skipped; 4 findings; 1 with incomplete evidence; expected exit 3 |
| Live sample | Log4j core 2.14.1; 1 component queried; 8 grouped findings; all three intelligence sources obtained; exit 0 |
| PDF | Demo page and both live-report pages rendered and visually inspected; embedded fonts, wrapped cells and page numbers |
| CSV and JSON | Tests cover CSV formula protection, row count and evidence serialization |

The live scan's source retrieval times were 2026-10-31 19:03:27–19:03:51 UTC. The primary CISA endpoint returned HTTP 403. CISA's official `cisagov/kev-data` mirror succeeded, using catalog version `2026.10.30`. The fallback and original error are recorded in `examples/live-report/report.json`. The sample is a dated snapshot; scores and advisory records change.

One non-failing `importlib.metadata` deprecation warning appeared during the Streamlit test in this runtime. It did not cause an application exception.

## Hosted GitHub Actions verification

[Run 2](https://github.com/sumant30s/sbom-triage/actions/runs/41271276645) completed successfully on 1 November 2026 for source commit `c736fa3a9ed51cb3302a19e40cafafc262b0edc7`.

- All four Windows/Linux and Python 3.11/3.12 test jobs passed, including pytest, Ruff and Bandit.
- Semgrep passed with the three local rules.
- Trivy passed its HIGH/CRITICAL vulnerability and secret gate, and the coverage step confirmed all **51 pinned Python dependencies** were scanned. The JSON report is retained as a workflow artifact for seven days.
- The first Trivy job had exited successfully without finding a dependency manifest. The corrected workflow copies the tested snapshot to `requirements.txt` and requires every pinned name/version to appear in Trivy's package inventory.
- A local check confirmed that the new coverage guard accepts a complete scan and rejects an empty scan.

This dependency scan covers the recorded validation snapshot, not every newly resolved dependency environment. A passing scan does not prove an absence of vulnerabilities.

## Not yet verified

- Browser visual QA of the Streamlit application was not performed; its interaction flow was tested through Streamlit AppTest.
- Syft/Grype commands are supplied for the learning exercise; those tools were not executed in this session.
- No performance/load, clinical validation, regulatory compliance or exhaustive vulnerability-coverage claim is made.

The project repository is [sumant30s/sbom-triage](https://github.com/sumant30s/sbom-triage). It is private. Documentation-only follow-up commits do not change the tested application or workflow.
