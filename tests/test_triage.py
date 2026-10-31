import json

import pytest

from sbom_triage.clients import SourceError
from sbom_triage.demo import DEMO_SBOM, LOG4J, DemoSources, advisory
from sbom_triage.triage import cluster_aliases, cvss_evidence, priority, scan


@pytest.mark.parametrize(
    "cvss,epss,kev,tier",
    [
        (1, 0.001, True, "P0"),
        (9, 0.001, False, "P1"),
        (4, 0.1, False, "P1"),
        (7, 0, False, "P2"),
        (4, 0.01, False, "P2"),
        (None, 0, False, "P2"),
        (0, None, False, "P2"),
        (0, 0, None, "P2"),
        (4, 0.001, False, "P3"),
        (0, 0, False, "P3"),
    ],
)
def test_priority_boundaries(cvss, epss, kev, tier):
    assert priority(cvss, epss, kev)[0] == tier


def test_transitive_aliases_and_withdrawn():
    records = [
        advisory("A", ["B"]),
        advisory("C", ["B"]),
        {**advisory("D", []), "withdrawn": "2024-01-01"},
    ]
    assert len(cluster_aliases(records)) == 1
    assert len(cluster_aliases(records)[0]) == 2


def test_bad_vector_not_zero():
    scores, warnings = cvss_evidence([advisory("A", [], "bad-vector")])
    assert scores == [] and warnings


def test_v4_vector():
    record = advisory("A", [])
    record["severity"] = [
        {
            "type": "CVSS_V4",
            "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N",
        }
    ]
    scores, warnings = cvss_evidence([record])
    assert scores[0]["score"] == 9.9 and not warnings


def test_other_packages_severity_does_not_leak():
    record = advisory("A", [])
    record["affected"] = [
        {
            "package": {"name": "other", "ecosystem": "PyPI"},
            "severity": [
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
            ],
        }
    ]
    assert cvss_evidence([record], "pkg:pypi/requests@1")[0] == []
    record["affected"][0]["package"]["name"] = "requests"
    assert cvss_evidence([record], "pkg:pypi/requests@1")[0][0]["score"] == 9.8


def test_demo_aliases_unknowns_and_coverage(demo_bytes):
    report = scan(demo_bytes, DemoSources())
    assert report["status"] == "partial"
    assert report["summary"] == {
        "components": 5,
        "queried": 4,
        "skipped": 1,
        "failed": 0,
        "findings": 4,
        "needs_review": 1,
    }
    assert report["findings"][0]["priority"] == "P0"
    unscored = next(f for f in report["findings"] if f["vulnerability"] == "DEMO-NO-CVE")
    assert unscored["cvss"] is None and unscored["kev"] is None and unscored["priority"] == "P2"


def test_outage_never_becomes_clean(demo_bytes):
    class Broken(DemoSources):
        def query(self, purl):
            raise SourceError("offline")

    report = scan(demo_bytes, Broken())
    assert report["status"] == "partial" and report["summary"]["failed"] == 4
    assert not report["findings"]


def test_kev_outage_is_unknown(demo_bytes):
    class BrokenKEV(DemoSources):
        def kev(self):
            raise SourceError("offline")

    report = scan(demo_bytes, BrokenKEV())
    assert report["status"] == "partial" and all(f["kev"] is None for f in report["findings"])


def test_per_run_query_reuse_but_per_component_findings():
    component = DEMO_SBOM["components"][0]
    raw = json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [component, {**component, "bom-ref": "second"}],
        }
    ).encode()

    class Counted(DemoSources):
        calls = 0

        def query(self, purl):
            self.calls += 1
            return super().query(purl)

    source = Counted()
    result = scan(raw, source)
    assert source.calls == 1 and len(result["findings"]) == 2
    assert result["status"] == "complete"


def test_unrecognized_demo_package_is_error():
    source = DemoSources()
    with pytest.raises(SourceError):
        source.query(LOG4J.replace("2.14.1", "99"))
