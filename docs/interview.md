# Explain the project honestly

## A 60–90 second answer

Use this only after running and understanding the project. Adapt the wording to the work you personally completed:

> “I worked on a Python SBOM vulnerability triage project. It takes a CycloneDX JSON inventory and uses package URLs and versions to query OSV. It groups advisory aliases so the same issue is not counted multiple times for one component, calculates CVSS scores from supplied vectors, and adds EPSS and CISA KEV evidence through CVE IDs.
>
> The output is a prioritized report and a Streamlit dashboard with coverage information and CSV, JSON and PDF exports. I kept the priority rules explicit, so an analyst can see why a finding is high priority. Missing scores and failed API requests remain unknown; they do not become zero-risk results.
>
> I tested parsing, alias merging, API failures, priority thresholds, exports and dashboard filters. The main limitation is that package matching does not prove runtime reachability or patient impact. Those need product-specific review. My next improvements would be validated VEX handling, persistent caching and broader package coverage.”

If asked about assistance, say what was AI-assisted, what you reviewed, what you changed yourself, and what you tested. Do not claim production deployments, clinical validation, penetration testing or compliance approval from this exercise.

## Explain each design choice

| Question | Answer structure |
|---|---|
| Why OSV instead of keyword searching NVD? | OSV accepts ecosystem/package identity and version. Keyword search can return name collisions; CPE matching needs its own careful design. |
| Why does a purl matter? | The same name can exist in different registries. Package type, namespace/name and version clarify identity. |
| CVSS vs EPSS vs KEV? | Severity vs predicted exploitation in 30 days vs known exploitation. Product context is still needed. |
| What does “unknown” mean? | Missing or unusable evidence. It is distinct from zero probability and from absence in a successfully retrieved catalog. |
| How are duplicates handled? | Transitive aliases are grouped within a component; separate component instances remain separate findings. |
| What happens on an API outage? | Timeouts and bounded retries; explicit source errors, partial scan coverage, and exit code 3. |
| Is this a vulnerability scanner? | It correlates a supplied inventory with vulnerability intelligence. It does not inspect binaries, exploit systems or discover unknown flaws. |
| How would you pick a fixed version? | Inspect vendor advisories and matching affected ranges/branches, upgrade compatibly, and test. Do not blindly choose the smallest `fixed` event. |
| What about medical devices? | Combine security evidence with patient-safety impact, deployment constraints, product lifecycle and validated change control. This tool does not make that decision. |

## A real issue to explain

The live validation encountered an HTTP 403 from the primary CISA feed. The first run correctly reported partial coverage instead of “not in KEV.” A fallback to CISA's own public `cisagov/kev-data` mirror was then added, with the actual URL and original failure recorded in report provenance. See `validation.md` for the final observed result; do not claim the fallback succeeded unless that record confirms it.

Another review issue was package-specific CVSS: an advisory can list multiple affected packages. The code only includes package-specific severity for the queried identity, preventing an unrelated package's score from leaking into the finding. A regression test verifies this.

## Live-coding practice

1. Load a JSON SBOM and print components that have no version.
2. Make a function that returns P0 for KEV, P1 for CVSS ≥9, and P2 for missing CVSS.
3. Test the boundary at 8.9 and 9.0, and distinguish `None` from `0.0`.
4. Mock a timeout and verify that the output says “lookup failed.”
5. Explain why an SBOM alone cannot identify CVEs: you need a vulnerability database/correlation step.

## Improvements in a sensible order

1. Add timestamped caching and staleness policies, plus provider quotas.
2. Validate full CycloneDX schemas and improve supported ecosystem coverage.
3. Add reviewed VEX/applicability evidence with audit history.
4. Add NVD enrichment with explicit score-source selection and rate limiting.
5. Add persistent ownership/status tracking, authentication and deployment controls.
6. Evaluate performance, Unicode PDF fonts and large-report layout.
