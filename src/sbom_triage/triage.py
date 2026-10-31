"""Correlation and transparent prioritization; no invented exploitability claims."""

import hashlib
from dataclasses import asdict

from cvss import CVSS2, CVSS3, CVSS4
from cvss.exceptions import CVSSError
from packageurl import PackageURL

from .clients import CVE_RE, SourceError, now
from .sbom import parse_sbom


def cluster_aliases(records: list[dict]) -> list[list[dict]]:
    """Merge transitive alias groups within ONE component, excluding withdrawn records."""
    parent: dict[str, str] = {}

    def root(value):
        parent.setdefault(value, value)
        while parent[value] != value:
            parent[value] = parent[parent[value]]
            value = parent[value]
        return value

    active = [v for v in records if not v.get("withdrawn")]
    for record in active:
        aliases = record.get("aliases", [])
        if not isinstance(aliases, list) or any(not isinstance(a, str) for a in aliases):
            raise SourceError("OSV aliases must be a list of identifiers.")
        identifiers = [record["id"], *aliases]
        for identifier in identifiers:
            parent[root(identifier)] = root(identifiers[0])
    groups: dict[str, list] = {}
    for record in active:
        groups.setdefault(root(record["id"]), []).append(record)
    return list(groups.values())


def cvss_evidence(
    records: list[dict], component_purl: str | None = None
) -> tuple[list[dict], list[str]]:
    evidence, warnings, seen = [], [], set()
    for record in records:
        severity = record.get("severity", [])
        # OSV allows both advisory-level and package-specific severity.
        for affected in record.get("affected", []):
            if matching_package(affected.get("package", {}), component_purl):
                severity = severity + affected.get("severity", [])
        for item in severity:
            vector = item.get("score", "")
            kind = item.get("type", "")
            identity = (record["id"], kind, vector)
            if identity in seen:
                continue
            seen.add(identity)
            try:
                calculator = {"CVSS_V2": CVSS2, "CVSS_V3": CVSS3, "CVSS_V4": CVSS4}.get(kind)
                if calculator is None:
                    warnings.append(f"Unsupported severity type {kind} in {record['id']}")
                    continue
                score = float(calculator(vector).scores()[0])
                evidence.append(
                    {"source": record["id"], "type": kind, "vector": vector, "score": score}
                )
            except (CVSSError, ValueError, TypeError):
                warnings.append(f"Invalid CVSS vector in {record['id']}")
    return evidence, warnings


def matching_package(package: dict, purl: str | None) -> bool:
    if not purl:
        return False
    parsed = PackageURL.from_string(purl)
    if package.get("purl"):
        try:
            candidate = PackageURL.from_string(package["purl"])
            return (candidate.type, candidate.namespace, candidate.name) == (
                parsed.type,
                parsed.namespace,
                parsed.name,
            )
        except ValueError:
            return False
    ecosystems = {
        "pypi": "PyPI",
        "npm": "npm",
        "maven": "Maven",
        "golang": "Go",
        "cargo": "crates.io",
        "nuget": "NuGet",
        "gem": "RubyGems",
        "composer": "Packagist",
    }
    name = parsed.name
    if parsed.namespace:
        name = parsed.namespace + (":" if parsed.type == "maven" else "/") + name
    candidate_name = package.get("name", "")
    if parsed.type == "pypi":
        import re

        name = re.sub(r"[-_.]+", "-", name).lower()
        candidate_name = re.sub(r"[-_.]+", "-", candidate_name).lower()
    if parsed.type in {"nuget", "cargo"}:
        name, candidate_name = name.lower(), candidate_name.lower()
    if parsed.type == "cargo":
        name, candidate_name = name.replace("_", "-"), candidate_name.replace("_", "-")
    return package.get("ecosystem") == ecosystems.get(parsed.type) and candidate_name == name


def priority(cvss: float | None, epss: float | None, kev: bool | None) -> tuple[str, str]:
    if kev is True:
        return (
            "P0",
            "CISA KEV lists known exploitation; urgently assess applicability and mitigations.",
        )
    if cvss is not None and cvss >= 9:
        return "P1", "Critical CVSS (>=9.0); assess exposure and remediation promptly."
    if epss is not None and epss >= 0.10:
        return "P1", "EPSS >=10%; assess exposure and remediation promptly."
    if cvss is not None and cvss >= 7:
        return "P2", "High CVSS (>=7.0); investigate applicability and plan remediation."
    if epss is not None and epss >= 0.01:
        return "P2", "EPSS >=1%; investigate applicability and plan remediation."
    if cvss is None or epss is None or kev is None:
        return "P2", "Evidence is incomplete; manual review required before lowering priority."
    return "P3", "Below configured escalation thresholds; review and track."


def severity_name(score: float | None) -> str:
    if score is None:
        return "Unknown"
    if score >= 9:
        return "Critical"
    if score >= 7:
        return "High"
    if score >= 4:
        return "Medium"
    return "Low" if score else "None"


def scan(raw: bytes, sources) -> dict:
    components = parse_sbom(raw)
    inventory, pending, errors, cache = [], [], [], {}
    for component in components:
        entry = asdict(component)
        entry.update(status="skipped", advisory_count=0)
        if component.issue:
            inventory.append(entry)
            continue
        try:
            if component.purl not in cache:
                try:
                    cache[component.purl] = sources.query(component.purl)
                except SourceError as exc:
                    cache[component.purl] = exc
            records = cache[component.purl]
            if isinstance(records, SourceError):
                raise records
            groups = cluster_aliases(records)
            entry.update(
                status="matched" if groups else "no_known_match", advisory_count=len(groups)
            )
            for group in groups:
                pending.append((component, group))
        except SourceError as exc:
            entry.update(status="error", issue=str(exc))
            errors.append(f"OSV lookup failed for component {component.ref}: {exc}")
        inventory.append(entry)

    all_cves = sorted(
        {
            identifier
            for _, records in pending
            for record in records
            for identifier in [record["id"], *record.get("aliases", [])]
            if CVE_RE.fullmatch(identifier)
        }
    )
    epss, epss_errors = sources.epss(all_cves) if all_cves else ({}, [])
    errors.extend(epss_errors)
    kev = None
    if all_cves:
        try:
            kev = sources.kev()
        except SourceError as exc:
            errors.append(f"CISA KEV unavailable: {exc}")
    findings = []
    for component, records in pending:
        aliases = sorted({i for r in records for i in [r["id"], *r.get("aliases", [])]})
        cves = [i for i in aliases if CVE_RE.fullmatch(i)]
        scores, score_warnings = cvss_evidence(records, component.purl)
        cvss = max((s["score"] for s in scores), default=None)
        epss_rows = {c: epss[c] for c in cves if c in epss}
        epss_score = max((e["score"] for e in epss_rows.values()), default=None)
        kev_rows = {c: kev[c] for c in cves if kev is not None and c in kev}
        kev_flag = bool(kev_rows) if kev is not None and cves else None
        missing = list(score_warnings)
        if cvss is None:
            missing.append("No usable numeric CVSS vector from OSV.")
        if not cves:
            missing.append("No CVE alias; EPSS and KEV correlation unavailable.")
        elif len(epss_rows) != len(cves):
            missing.append("EPSS unavailable for one or more CVE aliases.")
        if cves and kev is None:
            missing.append("KEV status unknown because the catalog lookup failed.")
        tier, reason = priority(cvss, epss_score, kev_flag)
        if missing and tier == "P3":
            tier, reason = (
                "P2",
                "Evidence is incomplete; manual review required before lowering priority.",
            )
        # Affected ranges may span branches and packages. Keep them with context;
        # do not claim the smallest 'fixed' event is a safe upgrade target.
        affected = [{"source": r["id"], "packages": r.get("affected", [])} for r in records]
        findings.append(
            {
                "component_ref": component.ref,
                "component": component.name,
                "version": component.version,
                "purl": component.purl,
                "vulnerability": cves[0] if cves else aliases[0],
                "aliases": aliases,
                "advisory_ids": sorted({r["id"] for r in records}),
                "cves": cves,
                "summary": next(
                    (r.get("summary") for r in records if r.get("summary")), "No summary supplied"
                ),
                "cvss": cvss,
                "severity": severity_name(cvss),
                "cvss_evidence": scores,
                "epss": epss_score,
                "epss_by_cve": epss_rows,
                "kev": kev_flag,
                "kev_by_cve": kev_rows,
                "priority": tier,
                "reason": reason,
                "review_notes": missing,
                "affected_evidence": affected,
                "references": sorted(
                    {ref["url"] for r in records for ref in r.get("references", []) if "url" in ref}
                ),
                "source_modified": {r["id"]: r.get("modified") for r in records},
                "reachability": "Not assessed",
                "patient_safety_impact": "Not assessed",
            }
        )
    findings.sort(
        key=lambda f: (
            f["priority"],
            -(f["epss"] or 0),
            -(f["cvss"] or 0),
            f["purl"],
            f["vulnerability"],
        )
    )
    complete = not errors and all(c["status"] not in {"skipped", "error"} for c in inventory)
    return {
        "schema_version": "1.0",
        "generated_at": now(),
        "mode": sources.mode,
        "input_sha256": hashlib.sha256(raw).hexdigest(),
        "status": "complete" if complete else "partial",
        "policy_version": "educational-v1",
        "summary": {
            "components": len(inventory),
            "queried": sum(c["status"] in {"matched", "no_known_match"} for c in inventory),
            "skipped": sum(c["status"] == "skipped" for c in inventory),
            "failed": sum(c["status"] == "error" for c in inventory),
            "findings": len(findings),
            "needs_review": sum(bool(f["review_notes"]) for f in findings),
        },
        "sources": sources.provenance,
        "errors": errors,
        "components": inventory,
        "findings": findings,
        "limitations": [
            "No known match is not evidence of absence of vulnerabilities.",
            "Priority is an educational policy, not a clinical risk score or remediation SLA.",
            "Reachability, exposure, VEX validity and patient-safety impact require human assessment.",
            "CVSS is the highest supplied score, not a conversion between CVSS versions.",
            "EPSS is the maximum among CVE aliases; per-CVE values and dates are retained.",
        ],
    }
