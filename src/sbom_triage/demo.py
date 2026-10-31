"""Synthetic, deterministic responses for offline teaching and tests."""

from copy import deepcopy

from .clients import SourceError

VECTOR_CRITICAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
VECTOR_MEDIUM = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"
LOG4J = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
REQUESTS = "pkg:pypi/requests@2.19.1"
YAML = "pkg:pypi/pyyaml@5.3.1"
DEMO_SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "version": 1,
    "components": [
        {
            "type": "library",
            "bom-ref": "log4j",
            "name": "log4j-core",
            "version": "2.14.1",
            "purl": LOG4J,
        },
        {
            "type": "library",
            "bom-ref": "requests",
            "name": "requests",
            "version": "2.19.1",
            "purl": REQUESTS,
        },
        {"type": "library", "bom-ref": "yaml", "name": "PyYAML", "version": "5.3.1", "purl": YAML},
        {
            "type": "library",
            "bom-ref": "example",
            "name": "example-only-package",
            "version": "1.0.0",
            "purl": "pkg:npm/example-only-package@1.0.0",
        },
        {
            "type": "firmware",
            "bom-ref": "firmware",
            "name": "example-device-firmware",
            "version": "1.0",
        },
    ],
}


def advisory(identifier, aliases, vector=None, summary="Synthetic training advisory"):
    return {
        "id": identifier,
        "aliases": aliases,
        "summary": summary,
        "modified": "2024-01-01T00:00:00Z",
        "severity": [{"type": "CVSS_V3", "score": vector}] if vector else [],
        "affected": [],
        "references": [],
    }


class DemoSources:
    mode = "demo"

    def __init__(self):
        self.provenance = {
            "demo": {
                "notice": "All responses are synthetic teaching fixtures, NOT live intelligence.",
                "fixture_version": "1",
                "sample_epss_date": "2024-01-01",
            }
        }
        self.records = {
            LOG4J: [advisory("DEMO-LOG4J", ["CVE-2021-44228"], VECTOR_CRITICAL)],
            REQUESTS: [
                advisory("DEMO-REQUESTS-A", ["CVE-2018-18074"], VECTOR_MEDIUM),
                advisory("DEMO-REQUESTS-B", ["DEMO-REQUESTS-A"]),
                advisory(
                    "DEMO-NO-CVE", [], summary="Training example with missing CVSS and CVE alias"
                ),
            ],
            YAML: [advisory("DEMO-YAML", ["CVE-2020-14343"], VECTOR_CRITICAL)],
            "pkg:npm/example-only-package@1.0.0": [],
        }

    def close(self):
        pass

    def query(self, purl):
        if purl not in self.records:
            raise SourceError("Demo fixture has no record for this package; use live mode.")
        return deepcopy(self.records[purl])

    def epss(self, cves):
        data = {
            "CVE-2021-44228": {"score": 0.42, "percentile": 0.98, "date": "2024-01-01"},
            "CVE-2018-18074": {"score": 0.02, "percentile": 0.7, "date": "2024-01-01"},
            "CVE-2020-14343": {"score": 0.005, "percentile": 0.5, "date": "2024-01-01"},
        }
        return {c: data[c] for c in cves if c in data}, []

    def kev(self):
        return {
            "CVE-2021-44228": {
                "cveID": "CVE-2021-44228",
                "requiredAction": "Synthetic fixture: review vendor guidance.",
            }
        }
