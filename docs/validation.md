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

## Not yet verified

- Windows execution was not run locally; the workflow includes Windows/Python 3.11 and 3.12 jobs.
- The hosted GitHub Actions pipeline and Trivy dependency scan have not run in this session.
- Browser visual QA of the Streamlit application was not performed; its interaction flow was tested through Streamlit AppTest.
- Syft/Grype commands are supplied for the learning exercise; those tools were not executed in this session.
- No performance/load, clinical validation, regulatory compliance or exhaustive vulnerability-coverage claim is made.

The project repository is [sumant30s/sbom-triage](https://github.com/sumant30s/sbom-triage). It is private. Hosted workflow results must be checked separately from the local results above.
