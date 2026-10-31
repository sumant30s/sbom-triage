# Build understanding across days 6–9

The supplied learning schedule spans **15 days**. This project occupies days 6–9. If only nine days remain before the interview, bring a short mock interview and medical-device awareness session into day 9 and defer the extra breadth. Do not quietly squeeze fifteen full study days into nine.

The project is implemented, but owning it means being able to change and explain it. Work in a feature branch, read each module, make the exercises below, run tests and commit your changes. Do not claim independent authorship of code you cannot explain.

| Day | Timebox | Learn and practice | Completion evidence |
|---|---|---|---|
| 6 | 3–4 hours | SBOM, CycloneDX vs SPDX; purl, package/version identity; generate an SBOM with Syft and compare Grype output; read `sbom.py` | Parse a new SBOM, explain every skipped component, add one parser test |
| 7 | 3–4 hours | CVE vs CWE; severity vs likelihood vs observed exploitation; trace OSV alias merging; read `triage.py` | Explain two priority decisions and an unknown; add a boundary test |
| 8 | 3–4 hours | `requests`, JSON, exceptions, timeouts, retries, `argparse`, logging, pytest mocks; read `clients.py` and `cli.py` | Simulate HTTP 429, timeout and malformed JSON; explain why errors never mean zero vulnerabilities |
| 9 | 3–4 hours | pandas, Streamlit, Plotly, exports and GitHub; read `reports.py` and `app.py` | Demo filters and all exports, run tests, record a 90-second explanation and do a short mock interview |

## Day 6: identify before looking up

Input: a JSON file containing component records. Output: component name, version, purl and an explicit identity issue if lookup is not possible.

The parser does not infer that a name such as `core` belongs to Python or npm. It uses a purl, which includes the package ecosystem. If the component says version `1.0` but its purl says `2.0`, it records a conflict instead of querying either silently.

Exercises:

1. Open `examples/demo-sbom.cdx.json`. Predict which component will be skipped.
2. Remove a version from both the purl and component. Observe the coverage result.
3. Add a nested component and explain why recursive traversal is needed.
4. Explain SBOM vs CBOM: software inventory vs inventory of cryptographic assets and their properties. A CBOM helps locate cryptographic dependencies relevant to algorithm migration; this tool does not create or analyze one.
5. Explain VEX: a supplier/analyst statement about vulnerability impact on a product, supported by justification. It is not an automatic guarantee of safety.

Read: [CycloneDX CBOM](https://cyclonedx.org/capabilities/cbom/) and [VEX](https://cyclonedx.org/capabilities/vex/).

## Day 7: prioritize without inventing risk

Trace the demo finding with a KEV match. Observe how its alias identifies a CVE, and how the CVE is used for EPSS and KEV enrichment. Compare it with `DEMO-NO-CVE`, which has insufficient scoring evidence.

Exercises:

1. Explain why two OSV records that refer to the same CVE should normally be grouped for the same component.
2. Explain why the same CVE affecting two different component instances still appears twice.
3. Change the EPSS threshold in a feature branch, update both tests and policy documentation, and observe the changed queue.
4. Answer: “CVSS is 9.8, but the vulnerable function is unreachable.” Validate the version/configuration and reachability evidence, record controls and uncertainty, obtain review and track the decision. Do not silently delete the finding.

## Day 8: make failures visible

Dry-run the request flow:

| Event | Tool behavior | Why |
|---|---|---|
| HTTP 200 with valid JSON | Process evidence | Successful data retrieval |
| HTTP 429 | Respect bounded Retry-After and retry | Avoid hammering the provider |
| Timeout / 5xx | Retry up to three attempts | Allow transient recovery |
| HTTP 400 | Fail that lookup | Retrying the same invalid query is unhelpful |
| Invalid vector | Keep score unknown and require review | An invalid vector does not mean a score of zero |
| Unavailable KEV source | Try CISA's official mirror; record provenance | Retain source transparency |
| Both KEV sources unavailable | Report unknown KEV status and partial coverage | Avoid false reassurance |

Write a small standalone script that loads a JSON file and prints the names and versions of all components. Then add a function, a `try/except`, a CLI argument and a pytest test. This is a good interview live-coding rehearsal.

## Day 9: demonstrate and explain

1. Launch Streamlit and load the offline demo.
2. Explain the “4 / 5 components queried” metric and the partial-coverage banner.
3. Filter to P0, inspect vectors and aliases, then export CSV, PDF and JSON.
4. Run the live Log4j sample; do not expect the same scores forever.
5. Run pytest, Ruff and Bandit. Read a failure before trying to fix it.
6. Use the README to publish from your own terminal if the GitHub browser sign-in is unavailable:

```powershell
git init -b main
git add .
git commit -m "Build SBOM vulnerability triage portfolio project"
# Requires GitHub CLI to be installed and authenticated:
gh repo create sbom-triage --public --source=. --remote=origin --push
```

These commands apply to a fresh local checkout with no existing remote. Never overwrite an unrelated repository. Review the GitHub Actions page after publishing. Pin action commit SHAs and package locks for a production pipeline; this educational workflow uses documented release tags and bounded package versions.

## Interview readiness check

- Can you explain one function without reading its code aloud?
- Can you change a threshold and update its test?
- Can you distinguish API failure, no known match and a clean-looking report?
- Can you state exactly which parts you tested locally and which hosted checks remain unverified?
- Can you describe one real limitation and a sensible next improvement?
