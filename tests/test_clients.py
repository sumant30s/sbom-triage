import json

import pytest
import requests
import responses

from sbom_triage.clients import (
    EPSS_URL,
    KEV_MIRROR_URL,
    KEV_URL,
    OSV_URL,
    JsonHTTP,
    LiveSources,
    SourceError,
)
from sbom_triage.demo import LOG4J


@responses.activate
def test_pagination_preserves_purl_without_duplicate_version():
    responses.post(OSV_URL, json={"vulns": [{"id": "A"}], "next_page_token": "next"})
    responses.post(OSV_URL, json={"vulns": [{"id": "B"}]})
    assert [v["id"] for v in LiveSources().query(LOG4J)] == ["A", "B"]
    first = json.loads(responses.calls[0].request.body)
    second = json.loads(responses.calls[1].request.body)
    assert first == {"package": {"purl": LOG4J}}
    assert second["page_token"] == "next"


@responses.activate
def test_repeated_page_rejected_not_clean():
    responses.post(OSV_URL, json={"next_page_token": "loop"})
    with pytest.raises(SourceError, match="repeated"):
        LiveSources().query(LOG4J)


@responses.activate
def test_rate_limit_retry_after():
    waits = []
    responses.get(KEV_URL, status=429, headers={"Retry-After": "3"})
    responses.get(KEV_URL, json={})
    assert JsonHTTP(sleeper=waits.append).request("GET", KEV_URL) == {}
    assert waits == [3]


@responses.activate
def test_too_long_retry_is_reported():
    responses.get(KEV_URL, status=429, headers={"Retry-After": "120"})
    with pytest.raises(SourceError, match="budget"):
        JsonHTTP(sleeper=lambda _: None).request("GET", KEV_URL)


@responses.activate
def test_timeout_retry_budget():
    responses.get(KEV_URL, body=requests.Timeout())
    with pytest.raises(SourceError, match="3 attempts"):
        JsonHTTP(sleeper=lambda _: None).request("GET", KEV_URL)
    assert len(responses.calls) == 3


@responses.activate
def test_400_not_retried():
    responses.post(OSV_URL, status=400)
    with pytest.raises(SourceError, match="400"):
        LiveSources().query(LOG4J)
    assert len(responses.calls) == 1


@responses.activate
def test_invalid_json_rejected():
    responses.get(KEV_URL, body="oops")
    with pytest.raises(SourceError):
        LiveSources().kev()


@responses.activate
def test_malformed_osv_severity_not_clean():
    responses.post(OSV_URL, json={"vulns": [{"id": "A", "severity": [None]}]})
    with pytest.raises(SourceError):
        LiveSources().query(LOG4J)


@responses.activate
def test_epss_batches_and_missing_values():
    cves = [f"CVE-2024-{i:04d}" for i in range(101)]
    responses.get(
        EPSS_URL,
        json={
            "status": "OK",
            "total": 1,
            "data": [{"cve": cves[0], "epss": "0.25", "percentile": "0.9", "date": "2024-01-01"}],
        },
    )
    responses.get(EPSS_URL, json={"status": "OK", "total": 0, "data": []})
    result, errors = LiveSources().epss(cves)
    assert not errors and result[cves[0]]["score"] == 0.25
    assert cves[1] not in result and len(responses.calls) == 3


@responses.activate
def test_nan_epss_not_accepted():
    responses.get(
        EPSS_URL,
        json={
            "status": "OK",
            "total": 1,
            "data": [
                {"cve": "CVE-2024-1000", "epss": "nan", "percentile": "0.9", "date": "2024-01-01"}
            ],
        },
    )
    result, errors = LiveSources().epss(["CVE-2024-1000"])
    assert result == {} and errors


@responses.activate
def test_kev_feed_integrity_and_provenance():
    responses.get(
        KEV_URL,
        json={
            "catalogVersion": "sample",
            "dateReleased": "2024-01-01",
            "count": 1,
            "vulnerabilities": [{"cveID": "CVE-2024-1000"}],
        },
    )
    source = LiveSources()
    assert "CVE-2024-1000" in source.kev()
    assert source.provenance["kev"]["catalog_version"] == "sample"


@responses.activate
def test_truncated_kev_rejected():
    responses.get(KEV_URL, json={"count": 2, "vulnerabilities": []})
    with pytest.raises(SourceError):
        LiveSources().kev()


@responses.activate
def test_official_kev_mirror_fallback_keeps_provenance():
    responses.get(KEV_URL, status=403)
    responses.get(
        KEV_MIRROR_URL,
        json={
            "count": 0,
            "vulnerabilities": [],
            "catalogVersion": "sample",
            "dateReleased": "2024-01-01",
        },
    )
    source = LiveSources()
    assert source.kev() == {}
    assert source.provenance["kev"]["url"] == KEV_MIRROR_URL
    assert "403" in source.provenance["kev"]["fallback_reason"]


@responses.activate
def test_both_kev_sources_unavailable():
    responses.get(KEV_URL, status=403)
    responses.get(KEV_MIRROR_URL, status=403)
    with pytest.raises(SourceError):
        LiveSources().kev()
