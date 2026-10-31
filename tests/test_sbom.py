import json

import pytest

from sbom_triage.sbom import MAX_BYTES, parse_sbom


def bom(components, **extra):
    return json.dumps(
        {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": components, **extra}
    )


def test_version_only_in_purl_and_scoped_npm():
    result = parse_sbom(bom([{"name": "@team/widget", "purl": "pkg:npm/%40team/widget@1.2.3"}]))
    assert result[0].version == "1.2.3"
    assert result[0].purl == "pkg:npm/%40team/widget@1.2.3"


def test_version_added_to_unversioned_purl():
    assert parse_sbom(
        bom([{"name": "requests", "version": "2.19.1", "purl": "pkg:pypi/requests"}])
    )[0].purl.endswith("@2.19.1")


@pytest.mark.parametrize(
    "item,expected",
    [
        ({"name": "test"}, "Missing purl"),
        ({"name": "test", "purl": "not-a-purl"}, "purl"),
        ({"name": "test", "purl": "pkg:pypi/test"}, "Missing exact"),
        ({"name": "test", "version": "2", "purl": "pkg:pypi/test@1"}, "disagree"),
        ({"name": "test", "purl": "pkg:generic/test@1"}, "Unsupported"),
    ],
)
def test_identity_gaps_not_silently_queried(item, expected):
    c = parse_sbom(bom([item]))[0]
    assert c.purl is None and expected.lower() in c.issue.lower()


def test_nested_and_metadata_components_preserved():
    result = parse_sbom(
        bom(
            [{"name": "parent", "components": [{"name": "child"}]}],
            metadata={"component": {"name": "root"}},
        )
    )
    assert [c.name for c in result] == ["root", "parent", "child"]


@pytest.mark.parametrize("raw", [b"not JSON", b"[]", b'{"bomFormat":"SPDX"}', b"{}", b"\xff"])
def test_invalid_input(raw):
    with pytest.raises(ValueError):
        parse_sbom(raw)


def test_size_and_count_limits():
    with pytest.raises(ValueError, match="5 MiB"):
        parse_sbom(b" " * (MAX_BYTES + 1))
    with pytest.raises(ValueError, match="500"):
        parse_sbom(bom([{"name": "x"}] * 501))


def test_duplicate_refs_rejected():
    with pytest.raises(ValueError, match="unique"):
        parse_sbom(bom([{"name": "a", "bom-ref": "same"}, {"name": "b", "bom-ref": "same"}]))
