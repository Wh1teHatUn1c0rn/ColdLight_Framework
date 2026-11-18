"""Tests for the vulnerability-detail enrichment: reference classification,
full advisory text, CWE catalogue, EPSS and Exploit-DB metadata.

All offline -- the HTTP layer is stubbed.
"""

import json

import pytest

import coldlight_cwe as cwe
import coldlight_exploitintel as ei
import coldlight_vulnintel as vi


# ---------------------------------------------------------------------------
# CWE catalogue
# ---------------------------------------------------------------------------

def test_every_cwe_our_scanner_emits_has_an_entry():
    """The catalogue and the rule table must not drift apart."""
    import coldlight_codescan as cs

    emitted = {rule.cwe for rule in cs.RULES if rule.cwe}
    assert emitted
    missing = sorted(c for c in emitted if cwe.describe(c) is None)
    assert missing == [], f"no catalogue entry for {missing}"


def test_entries_are_actionable():
    for weakness in cwe.CATALOG.values():
        assert weakness.name
        assert len(weakness.description) > 40, weakness.cwe
        assert weakness.mitigations, f"{weakness.cwe} has no mitigation"
        for mitigation in weakness.mitigations:
            assert len(mitigation) > 10


def test_lookup_and_summary():
    weakness = cwe.describe("CWE-78")
    assert "Command Injection" in weakness.name
    assert weakness.url == "https://cwe.mitre.org/data/definitions/78.html"
    assert cwe.summarise("CWE-78").startswith("CWE-78 —")


def test_lookup_is_case_insensitive_and_trims():
    assert cwe.describe("  cwe-78 ") is not None


def test_unknown_and_placeholder_ids_resolve_to_nothing():
    assert cwe.describe("CWE-99999") is None
    assert cwe.describe("") is None
    assert cwe.describe(None) is None
    # NVD uses these when it assigned no weakness; they are not weaknesses.
    for placeholder in ("NVD-CWE-noinfo", "NVD-CWE-Other"):
        assert cwe.describe(placeholder) is None


def test_summarise_falls_back_to_the_bare_id():
    assert cwe.summarise("CWE-99999") == "CWE-99999"


def test_catalog_is_serialisable():
    json.dumps([w.to_dict() for w in cwe.CATALOG.values()])


# ---------------------------------------------------------------------------
# Reference classification
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("tags,expected", [
    (["Patch"], vi.KIND_PATCH),
    (["Exploit"], vi.KIND_EXPLOIT),
    (["Mitigation"], vi.KIND_MITIGATION),
    (["Vendor Advisory"], vi.KIND_ADVISORY),
    (["Third Party Advisory"], vi.KIND_ADVISORY),
    (["Issue Tracking"], vi.KIND_REPORT),
    (["Mailing List"], vi.KIND_REPORT),
    (["Product"], vi.KIND_OTHER),
    ([], vi.KIND_OTHER),
    (None, vi.KIND_OTHER),
])
def test_nvd_tag_classification(tags, expected):
    assert vi.classify_nvd_tags(tags) == expected


def test_patch_outranks_other_tags_on_the_same_reference():
    assert vi.classify_nvd_tags(["Third Party Advisory", "Patch"]) == vi.KIND_PATCH
    assert vi.classify_nvd_tags(["Mailing List", "Exploit"]) == vi.KIND_EXPLOIT


@pytest.mark.parametrize("osv_type,expected", [
    ("FIX", vi.KIND_PATCH),
    ("GIT", vi.KIND_PATCH),
    ("ADVISORY", vi.KIND_ADVISORY),
    ("REPORT", vi.KIND_REPORT),
    ("EVIDENCE", vi.KIND_EXPLOIT),
    ("WEB", vi.KIND_OTHER),
    ("PACKAGE", vi.KIND_OTHER),
    ("", vi.KIND_OTHER),
])
def test_osv_type_classification(osv_type, expected):
    assert vi.classify_osv_type(osv_type) == expected


@pytest.mark.parametrize("url", [
    "https://github.com/apache/logging-log4j2/pull/608",
    "https://github.com/o/r/commit/abc123",
    "https://gitlab.com/o/r/-/commit/abc123",
    "https://github.com/o/r/releases/tag/v1.2.3",
    "https://github.com/o/r/compare/v1.0...v1.1",
])
def test_patch_shaped_urls_are_inferred(url):
    assert vi.infer_patch_reference(url) is True


@pytest.mark.parametrize("url", [
    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
    "https://example.com/blog/log4shell",
    "https://www.exploit-db.com/exploits/50592",
])
def test_non_patch_urls_are_not_inferred(url):
    assert vi.infer_patch_reference(url) is False


@pytest.mark.parametrize("url", [
    "https://github.com/github/advisory-database/pull/5501",
    "https://github.com/pypa/advisory-database/commit/abc",
    "https://github.com/golang/vulndb/pull/42",
    "https://github.com/rustsec/advisory-db/commit/def",
])
def test_advisory_database_changes_are_not_called_patches(url):
    """A PR against an advisory database changes the advisory, not the
    vulnerable code. The naive URL heuristic would get this wrong."""
    assert vi.infer_patch_reference(url) is False


def test_inference_never_produces_the_asserted_patch_kind():
    """patch means the database said so; patch_likely means we guessed."""
    grouped = vi._group_references([
        ("https://github.com/o/r/commit/abc", vi.KIND_OTHER),
        ("https://vendor.example/advisory", vi.KIND_PATCH),
    ])
    assert grouped[vi.KIND_PATCH] == ["https://vendor.example/advisory"]
    assert grouped[vi.KIND_PATCH_LIKELY] == ["https://github.com/o/r/commit/abc"]


def test_explicit_labels_are_never_downgraded_by_inference():
    grouped = vi._group_references([
        ("https://github.com/o/r/commit/abc", vi.KIND_PATCH),
    ])
    assert vi.KIND_PATCH_LIKELY not in grouped


def test_groups_are_ordered_by_usefulness():
    grouped = vi._group_references([
        ("u1", vi.KIND_OTHER), ("u2", vi.KIND_ADVISORY), ("u3", vi.KIND_PATCH),
    ])
    assert list(grouped) == [vi.KIND_PATCH, vi.KIND_ADVISORY, vi.KIND_OTHER]


def test_duplicate_urls_are_not_repeated():
    grouped = vi._group_references([("u", vi.KIND_PATCH), ("u", vi.KIND_PATCH)])
    assert grouped[vi.KIND_PATCH] == ["u"]


# ---------------------------------------------------------------------------
# Parsing: classification + full detail
# ---------------------------------------------------------------------------

NVD_WITH_TAGS = {
    "cve": {
        "id": "CVE-2021-44228",
        "descriptions": [{"lang": "en", "value": "A " + "long " * 150 + "end."}],
        "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {
            "baseScore": 10.0, "baseSeverity": "CRITICAL",
            "vectorString": "CVSS:3.1/AV:N"}}]},
        "weaknesses": [{"description": [{"lang": "en", "value": "CWE-20"}]}],
        "references": [
            {"url": "https://vendor.example/patch", "tags": ["Patch"]},
            {"url": "https://exp.example/poc", "tags": ["Exploit"]},
            {"url": "https://vendor.example/adv", "tags": ["Vendor Advisory"]},
            {"url": "https://lists.example/thread", "tags": ["Mailing List"]},
        ],
    }
}


def test_nvd_parse_classifies_and_names_the_cwe():
    finding = vi.parse_nvd_cve(NVD_WITH_TAGS)
    assert finding.reference_kinds[vi.KIND_PATCH] == ["https://vendor.example/patch"]
    assert finding.reference_kinds[vi.KIND_EXPLOIT] == ["https://exp.example/poc"]
    assert finding.cwe == "CWE-20"
    assert finding.cwe_name == "Improper Input Validation"


def test_nvd_description_is_not_truncated():
    finding = vi.parse_nvd_cve(NVD_WITH_TAGS)
    assert len(finding.details) > 400


OSV_LONG = {
    "id": "GHSA-test",
    "aliases": ["CVE-2024-0001"],
    "summary": "Short headline",
    "details": "## Impact\n" + ("Detailed explanation. " * 80),
    "affected": [{
        "package": {"name": "pkg", "ecosystem": "PyPI"},
        "ranges": [{"type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "2.0"}]}],
    }],
    "references": [
        {"type": "FIX", "url": "https://github.com/o/r/commit/deadbeef"},
        {"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-test"},
        {"type": "WEB", "url": "https://github.com/o/r/pull/99"},
        {"type": "WEB", "url": "https://blog.example/post"},
    ],
}


def test_osv_keeps_the_headline_and_the_full_writeup():
    finding = vi.parse_osv_vuln(OSV_LONG, package="pkg", ecosystem="PyPI",
                                version="1.0")
    assert finding.summary == "Short headline"
    assert len(finding.details) > 400          # previously clipped to 400
    assert "Impact" in finding.details


def test_osv_fix_type_becomes_an_asserted_patch():
    finding = vi.parse_osv_vuln(OSV_LONG, package="pkg", ecosystem="PyPI",
                                version="1.0")
    assert finding.reference_kinds[vi.KIND_PATCH] == [
        "https://github.com/o/r/commit/deadbeef"]
    # The WEB-typed pull request is inferred, not asserted.
    assert finding.reference_kinds[vi.KIND_PATCH_LIKELY] == [
        "https://github.com/o/r/pull/99"]
    assert "https://blog.example/post" in finding.reference_kinds[vi.KIND_OTHER]


def test_osv_without_a_summary_still_truncates_the_headline():
    """With no summary, details stands in for it -- that one stays short."""
    vuln = dict(OSV_LONG)
    vuln.pop("summary")
    finding = vi.parse_osv_vuln(vuln, package="pkg", ecosystem="PyPI",
                                version="1.0")
    assert len(finding.summary) <= 400
    assert len(finding.details) > 400          # the full text is still kept


# ---------------------------------------------------------------------------
# Merge must not lose the new fields
# ---------------------------------------------------------------------------

def test_merge_keeps_the_fuller_writeup_and_unions_references():
    thin = vi.Finding(identifier="CVE-1", package="p", installed_version="1",
                      ecosystem="PyPI", details="short",
                      reference_kinds={vi.KIND_ADVISORY: ["a"]})
    rich = vi.Finding(identifier="CVE-1", package="p", installed_version="1",
                      ecosystem="PyPI", details="a much longer explanation",
                      reference_kinds={vi.KIND_PATCH: ["p1"]})

    merged = vi.merge_findings([thin, rich])
    assert len(merged) == 1
    assert merged[0].details == "a much longer explanation"
    assert merged[0].reference_kinds[vi.KIND_PATCH] == ["p1"]
    assert merged[0].reference_kinds[vi.KIND_ADVISORY] == ["a"]


def test_merge_keeps_epss_and_exploits():
    plain = vi.Finding(identifier="CVE-1", package="p", installed_version="1",
                       ecosystem="PyPI")
    scored = vi.Finding(identifier="CVE-1", package="p", installed_version="1",
                        ecosystem="PyPI", epss_score=0.9, epss_percentile=0.99,
                        exploits=[{"edb_id": "1"}])

    merged = vi.merge_findings([plain, scored])[0]
    assert merged.epss_score == 0.9
    assert merged.exploits == [{"edb_id": "1"}]


def test_merge_backfills_the_cwe_name():
    a = vi.Finding(identifier="CVE-1", package="p", installed_version="1",
                   ecosystem="PyPI")
    b = vi.Finding(identifier="CVE-1", package="p", installed_version="1",
                   ecosystem="PyPI", cwe="CWE-78")
    assert vi.merge_findings([a, b])[0].cwe_name == (
        cwe.describe("CWE-78").name)


# ---------------------------------------------------------------------------
# EPSS
# ---------------------------------------------------------------------------

EPSS_PAYLOAD = {"status": "OK", "data": [
    {"cve": "CVE-2021-44228", "epss": "0.99999", "percentile": "1.0",
     "date": "2026-11-17"},
    {"cve": "CVE-2019-10906", "epss": "0.03603", "percentile": "0.897",
     "date": "2026-11-17"},
]}


def test_fetch_epss_parses_scores(monkeypatch):
    monkeypatch.setattr(ei, "_http_json", lambda *a, **k: EPSS_PAYLOAD)
    scores = ei.fetch_epss(["CVE-2021-44228", "CVE-2019-10906"])
    assert scores["CVE-2021-44228"].score == pytest.approx(0.99999)
    assert scores["CVE-2019-10906"].percentile == pytest.approx(0.897)


def test_fetch_epss_ignores_non_cve_identifiers(monkeypatch):
    seen = {}

    def capture(url, *a, **k):
        seen["url"] = url
        return {"data": []}

    monkeypatch.setattr(ei, "_http_json", capture)
    ei.fetch_epss(["GHSA-xxxx", "PYSEC-2021-1", "CVE-2021-1"])
    assert "CVE-2021-1" in seen["url"]
    assert "GHSA" not in seen["url"]


def test_fetch_epss_batches_long_lists(monkeypatch):
    calls = []
    monkeypatch.setattr(ei, "_http_json",
                        lambda url, *a, **k: calls.append(url) or {"data": []})
    ei.fetch_epss([f"CVE-2021-{i:05d}" for i in range(250)], batch=100)
    assert len(calls) == 3


def test_apply_epss_matches_via_alias(monkeypatch):
    monkeypatch.setattr(ei, "_http_json", lambda *a, **k: EPSS_PAYLOAD)
    finding = vi.Finding(identifier="GHSA-abc", aliases=["CVE-2021-44228"])
    assert ei.apply_epss([finding], ei.fetch_epss(["CVE-2021-44228"])) == 1
    assert finding.epss_score == pytest.approx(0.99999)


def test_unscored_cves_are_left_alone():
    finding = vi.Finding(identifier="CVE-1999-0001")
    assert ei.apply_epss([finding], {}) == 0
    assert finding.epss_score is None


@pytest.mark.parametrize("score,band", [
    (0.9, "very high"), (0.5, "very high"), (0.2, "high"),
    (0.05, "moderate"), (0.001, "low"), (None, ""),
])
def test_epss_bands(score, band):
    assert ei.epss_band(score) == band


def test_epss_description_includes_the_percentile():
    text = ei.describe_epss(0.99999, 1.0)
    assert "0.99999" in text and "very high" in text and "100.0th" in text


# ---------------------------------------------------------------------------
# Exploit-DB index (metadata only)
# ---------------------------------------------------------------------------

EDB_CSV = (
    "id,file,description,date_published,author,type,platform,port,"
    "date_added,date_updated,verified,codes,tags,aliases\n"
    "50592,exploits/java/remote/50592.py,Apache Log4j 2 - RCE,2021-12-14,"
    "x,remote,java,,2021-12-14,,1,CVE-2021-44228,,\n"
    "51183,exploits/java/remote/51183.txt,AD Manager Plus - RCE,2023-04-01,"
    "y,remote,java,,2023-04-01,,0,CVE-2021-44228;OSVDB-1,,\n"
    "99999,exploits/php/webapps/99999.txt,No CVE here,2020-01-01,"
    "z,webapps,php,,2020-01-01,,0,,,\n"
)


def test_index_maps_cves_to_exploit_metadata():
    index = ei._parse_index(EDB_CSV)
    assert set(index) == {"CVE-2021-44228"}
    records = index["CVE-2021-44228"]
    assert len(records) == 2
    assert {r["edb_id"] for r in records} == {"50592", "51183"}


def test_index_records_the_verified_flag():
    records = ei._parse_index(EDB_CSV)["CVE-2021-44228"]
    verified = {r["edb_id"]: r["verified"] for r in records}
    assert verified == {"50592": True, "51183": False}


def test_index_links_the_browsable_page_not_the_exploit_body():
    """We surface the Exploit-DB page. The CSV's `file` column -- the path to
    the exploit itself -- is deliberately never read."""
    record = ei._parse_index(EDB_CSV)["CVE-2021-44228"][0]
    assert record["url"] == "https://www.exploit-db.com/exploits/50592"
    assert "file" not in record
    assert ".py" not in json.dumps(record)


def test_index_skips_rows_with_no_cve():
    assert "99999" not in json.dumps(ei._parse_index(EDB_CSV))


def test_index_splits_multiple_codes():
    index = ei._parse_index(
        "id,description,date_published,type,platform,verified,codes\n"
        "1,x,2020-01-01,remote,linux,1,CVE-2020-1;CVE-2020-2\n")
    assert set(index) == {"CVE-2020-1", "CVE-2020-2"}


def test_apply_exploitdb_attaches_and_orders_verified_first():
    index = ei._parse_index(EDB_CSV)
    finding = vi.Finding(identifier="CVE-2021-44228")
    assert ei.apply_exploitdb([finding], index) == 1
    assert finding.exploits[0]["verified"] is True


def test_apply_exploitdb_matches_via_alias():
    index = ei._parse_index(EDB_CSV)
    finding = vi.Finding(identifier="GHSA-x", aliases=["CVE-2021-44228"])
    assert ei.apply_exploitdb([finding], index) == 1


def test_findings_without_exploits_are_untouched():
    finding = vi.Finding(identifier="CVE-2000-0001")
    assert ei.apply_exploitdb([finding], ei._parse_index(EDB_CSV)) == 0
    assert finding.exploits == []


def test_index_is_cached(tmp_path, monkeypatch):
    monkeypatch.setattr(vi, "cache_dir", lambda: tmp_path)
    monkeypatch.setattr(ei, "cache_dir", lambda: tmp_path)
    calls = []
    monkeypatch.setattr(ei, "_fetch_index_csv",
                        lambda: calls.append(1) or EDB_CSV)

    first = ei.load_exploitdb_index()
    second = ei.load_exploitdb_index()
    assert first == second
    assert len(calls) == 1          # the second call came from cache


def test_describe_exploits_summarises():
    text = ei.describe_exploits([
        {"edb_id": "1", "verified": True, "date": "2021-12-14"},
        {"edb_id": "2", "verified": False, "date": "2023-04-01"},
    ])
    assert "2 public exploit(s)" in text
    assert "1 verified" in text
    assert "2021-12-14" in text


def test_describe_exploits_empty():
    assert ei.describe_exploits([]) == ""


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def test_report_leads_with_the_patch_and_labels_inference():
    finding = vi.Finding(
        identifier="CVE-1", severity="HIGH", package="p",
        installed_version="1", ecosystem="PyPI",
        reference_kinds={vi.KIND_PATCH: ["https://x/commit/a"],
                         vi.KIND_PATCH_LIKELY: ["https://y/pull/1"]},
    )
    text = vi.format_finding(finding)
    assert "patch: https://x/commit/a" in text
    assert "likely patch: https://y/pull/1" in text


def test_report_shows_epss_and_exploit_counts():
    finding = vi.Finding(
        identifier="CVE-1", severity="HIGH", epss_score=0.99999,
        exploits=[{"edb_id": "50592", "verified": True, "type": "remote",
                   "platform": "java", "date": "2021-12-14",
                   "url": "https://www.exploit-db.com/exploits/50592"}],
    )
    text = vi.format_finding(finding)
    assert "epss 1.000 (very high)" in text
    assert "PUBLIC EXPLOIT: 1 listed on Exploit-DB, 1 verified" in text
    assert "EDB-50592" in text


def test_verbose_report_includes_the_weakness_and_mitigations():
    finding = vi.Finding(identifier="CVE-1", severity="HIGH", cwe="CWE-78",
                         cwe_name="OS Command Injection",
                         summary="short", details="a much fuller explanation")
    text = vi.format_finding(finding, verbose=True)
    assert "weakness: Improper Neutralization" in text
    assert "fix: Pass an argument list" in text
    assert "a much fuller explanation" in text


def test_new_fields_reach_the_json_report():
    finding = vi.Finding(identifier="CVE-1", epss_score=0.5, cwe="CWE-78",
                         cwe_name="OS Command Injection",
                         details="full text",
                         reference_kinds={vi.KIND_PATCH: ["u"]},
                         exploits=[{"edb_id": "1"}])
    payload = vi.json_report(vi.ScanResult(findings=[finding]))
    entry = payload["findings"][0]
    assert entry["epss_score"] == 0.5
    assert entry["cwe_name"] == "OS Command Injection"
    assert entry["details"] == "full text"
    assert entry["reference_kinds"]["patch"] == ["u"]
    assert entry["exploits"] == [{"edb_id": "1"}]
    json.dumps(payload)
