"""Tests for coldlight_vulnintel. Fully offline: the HTTP layer is stubbed."""

import json

import pytest

import coldlight_vulnintel as vi


# ---------------------------------------------------------------------------
# Manifest parsers
# ---------------------------------------------------------------------------

def test_parse_requirements_takes_pins_only():
    text = """
    # a comment
    requests==2.25.1
    jinja2[i18n]==2.4.1
    flask>=1.0            # not pinned -> skipped
    -r other-requirements.txt
    -e .
    urllib3==1.26.5 ; python_version >= "3.7"
    """
    assert vi.parse_requirements(text) == [
        ("requests", "2.25.1"),
        ("jinja2", "2.4.1"),
        ("urllib3", "1.26.5"),
    ]


def test_parse_package_lock_v3():
    text = json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "my-app", "version": "1.0.0"},
            "node_modules/lodash": {"version": "4.17.11"},
            "node_modules/minimist": {"version": "1.2.0"},
        },
    })
    assert sorted(vi.parse_package_lock(text)) == [
        ("lodash", "4.17.11"),
        ("minimist", "1.2.0"),
    ]


def test_parse_package_lock_v1_walks_nested_deps():
    text = json.dumps({
        "lockfileVersion": 1,
        "dependencies": {
            "lodash": {"version": "4.17.11"},
            "express": {
                "version": "4.16.0",
                "dependencies": {"qs": {"version": "6.5.1"}},
            },
        },
    })
    assert sorted(vi.parse_package_lock(text)) == [
        ("express", "4.16.0"),
        ("lodash", "4.17.11"),
        ("qs", "6.5.1"),
    ]


def test_parse_package_json_strips_range_prefixes():
    text = json.dumps({
        "dependencies": {"lodash": "^4.17.11", "axios": "~0.21.0"},
        "devDependencies": {"jest": ">=26.0.0"},
        "optionalDependencies": {"fsevents": "*"},   # no base version -> skipped
    })
    got = dict(vi.parse_package_json(text))
    assert got == {"lodash": "4.17.11", "axios": "0.21.0", "jest": "26.0.0"}


def test_parse_go_mod_block_and_single_line():
    text = """
    module example.com/app

    go 1.21

    require github.com/single/dep v1.0.0

    require (
        github.com/gogo/protobuf v1.3.1
        golang.org/x/text v0.3.2 // indirect
    )
    """
    got = dict(vi.parse_go_mod(text))
    assert got["github.com/gogo/protobuf"] == "1.3.1"   # 'v' stripped for OSV
    assert got["golang.org/x/text"] == "0.3.2"
    assert got["github.com/single/dep"] == "1.0.0"


def test_parse_cargo_lock():
    text = """
version = 3

[[package]]
name = "smallvec"
version = "0.6.13"

[[package]]
name = "serde"
version = "1.0.136"
"""
    assert sorted(vi.parse_cargo_lock(text)) == [
        ("serde", "1.0.136"),
        ("smallvec", "0.6.13"),
    ]


# ---------------------------------------------------------------------------
# Manifest discovery
# ---------------------------------------------------------------------------

def test_discover_manifests_finds_and_skips(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.25.1")
    (tmp_path / "go.mod").write_text("module x\nrequire a/b v1.0.0\n")

    vendored = tmp_path / "node_modules" / "evil"
    vendored.mkdir(parents=True)
    (vendored / "package.json").write_text("{}")

    found = {p.name for p, _eco, _parser in vi.discover_manifests(tmp_path)}
    assert found == {"requirements.txt", "go.mod"}


def test_lockfile_wins_over_package_json(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"a": "1.0.0"}}))
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {"node_modules/a": {"version": "1.0.0"}},
    }))
    found = {p.name for p, _eco, _parser in vi.discover_manifests(tmp_path)}
    assert found == {"package-lock.json"}


# ---------------------------------------------------------------------------
# NVD parsing
# ---------------------------------------------------------------------------

NVD_FIXTURE = {
    "cve": {
        "id": "CVE-2021-44228",
        "published": "2021-12-10T10:15:09.143",
        "descriptions": [
            {"lang": "es", "value": "ignorar"},
            {"lang": "en", "value": "JNDI features do not protect against attacker "
                                    "controlled LDAP endpoints."},
        ],
        "metrics": {
            "cvssMetricV31": [{
                "type": "Primary",
                "cvssData": {
                    "baseScore": 10.0,
                    "baseSeverity": "CRITICAL",
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                },
            }],
        },
        "weaknesses": [{"description": [{"lang": "en", "value": "CWE-502"}]}],
        "references": [
            {"url": "https://logging.apache.org/log4j/2.x/security.html"},
            {"url": "https://www.exploit-db.com/exploits/50592"},
        ],
    }
}


def test_parse_nvd_cve_extracts_everything():
    f = vi.parse_nvd_cve(NVD_FIXTURE)
    assert f.identifier == "CVE-2021-44228"
    assert f.severity == "CRITICAL"
    assert f.cvss_score == 10.0
    assert f.cvss_vector.startswith("CVSS:3.1/")
    assert f.cwe == "CWE-502"
    assert "JNDI" in f.summary
    assert f.published == "2021-12-10"
    assert f.exploitdb_refs == ["https://www.exploit-db.com/exploits/50592"]
    assert len(f.references) == 2


def test_pick_cvss_prefers_newest_version():
    metrics = {
        "cvssMetricV2": [{"cvssData": {"baseScore": 5.0, "vectorString": "AV:N"}}],
        "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL",
                                        "vectorString": "CVSS:3.1/AV:N"}}],
    }
    score, vector, severity = vi._pick_cvss(metrics)
    assert (score, severity) == (9.8, "CRITICAL")
    assert vector.startswith("CVSS:3.1")


def test_is_cve_id():
    assert vi.is_cve_id("CVE-2021-44228")
    assert vi.is_cve_id("cve-1999-0001")
    assert not vi.is_cve_id("GHSA-xxxx")
    assert not vi.is_cve_id("")


def test_nvd_lookup_rejects_non_cve():
    with pytest.raises(ValueError):
        vi.nvd_lookup("not-a-cve")


def test_nvd_lookup_uses_stubbed_http(monkeypatch):
    monkeypatch.setattr(vi, "_http_json",
                        lambda *a, **k: {"vulnerabilities": [NVD_FIXTURE]})
    monkeypatch.setattr(vi, "_nvd_throttle", lambda: None)
    f = vi.nvd_lookup("CVE-2021-44228")
    assert f is not None and f.cvss_score == 10.0


def test_nvd_lookup_returns_none_when_unknown(monkeypatch):
    monkeypatch.setattr(vi, "_http_json", lambda *a, **k: {"vulnerabilities": []})
    monkeypatch.setattr(vi, "_nvd_throttle", lambda: None)
    assert vi.nvd_lookup("CVE-1999-0001") is None


# ---------------------------------------------------------------------------
# OSV parsing
# ---------------------------------------------------------------------------

OSV_FIXTURE = {
    "id": "GHSA-462w-v97r-4m45",
    "aliases": ["CVE-2019-10906", "PYSEC-2019-217"],
    "summary": "Jinja2 sandbox escape via str.format_map",
    "published": "2019-04-10T00:00:00Z",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
    "database_specific": {"severity": "HIGH"},
    "affected": [{
        "package": {"name": "jinja2", "ecosystem": "PyPI"},
        "ranges": [{"type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "2.10.1"}]}],
    }],
    "references": [
        {"type": "ADVISORY", "url": "https://nvd.nist.gov/vuln/detail/CVE-2019-10906"},
        {"type": "EVIDENCE", "url": "https://www.exploit-db.com/exploits/99999"},
    ],
}


def test_parse_osv_vuln_prefers_cve_identifier():
    f = vi.parse_osv_vuln(OSV_FIXTURE, package="jinja2", ecosystem="PyPI",
                          version="2.4.1", location="requirements.txt")
    assert f.identifier == "CVE-2019-10906"          # CVE preferred over GHSA
    assert "GHSA-462w-v97r-4m45" in f.aliases
    assert "PYSEC-2019-217" in f.aliases
    assert f.severity == "HIGH"
    assert f.fixed_versions == ["2.10.1"]
    assert f.package == "jinja2"
    assert f.installed_version == "2.4.1"
    assert f.location == "requirements.txt"
    assert f.cvss_vector.startswith("CVSS:3.1/")
    assert f.exploitdb_refs == ["https://www.exploit-db.com/exploits/99999"]


def test_parse_osv_falls_back_to_osv_id_without_cve():
    vuln = dict(OSV_FIXTURE, aliases=[])
    f = vi.parse_osv_vuln(vuln, package="jinja2", ecosystem="PyPI", version="2.4.1")
    assert f.identifier == "GHSA-462w-v97r-4m45"


def test_parse_osv_skips_git_commit_hashes_as_fix_versions():
    """OSV GIT ranges carry commit SHAs. "Upgrade to 9b53045c34e6..." is
    useless remediation advice, so only ecosystem versions are kept."""
    vuln = dict(OSV_FIXTURE)
    vuln["affected"] = [{
        "package": {"name": "jinja2", "ecosystem": "PyPI"},
        "ranges": [
            {"type": "GIT", "repo": "https://github.com/pallets/jinja",
             "events": [{"introduced": "0"},
                        {"fixed": "9b53045c34e61013dc8f09b7e52a555fa16bed16"}]},
            {"type": "ECOSYSTEM",
             "events": [{"introduced": "0"}, {"fixed": "2.8.1"}]},
        ],
    }]
    finding = vi.parse_osv_vuln(vuln, package="jinja2", ecosystem="PyPI",
                                version="2.4.1")
    assert finding.fixed_versions == ["2.8.1"]


def test_parse_osv_ignores_other_packages_fixed_versions():
    vuln = dict(OSV_FIXTURE)
    vuln["affected"] = [
        {"package": {"name": "somethingelse", "ecosystem": "PyPI"},
         "ranges": [{"events": [{"fixed": "9.9.9"}]}]},
        OSV_FIXTURE["affected"][0],
    ]
    f = vi.parse_osv_vuln(vuln, package="jinja2", ecosystem="PyPI", version="2.4.1")
    assert f.fixed_versions == ["2.10.1"]


# ---------------------------------------------------------------------------
# CISA KEV
# ---------------------------------------------------------------------------

KEV_FIXTURE = {
    "dateReleased": "2026-01-01T00:00:00.000Z",
    "vulnerabilities": [
        {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j2",
         "vulnerabilityName": "Apache Log4j2 RCE", "dateAdded": "2021-12-10",
         "dueDate": "2021-12-24", "requiredAction": "Patch.",
         "knownRansomwareCampaignUse": "Known"},
        {"cveID": "CVE-2019-10906", "vendorProject": "Palletsprojects",
         "product": "Jinja2", "dueDate": "2022-05-03",
         "knownRansomwareCampaignUse": "Unknown"},
    ],
}


def test_kev_index_keys_on_cve():
    index = vi.kev_index(KEV_FIXTURE)
    assert set(index) == {"CVE-2021-44228", "CVE-2019-10906"}


def test_apply_kev_flags_and_promotes_severity():
    index = vi.kev_index(KEV_FIXTURE)
    findings = [
        vi.Finding(identifier="CVE-2021-44228", severity="UNKNOWN"),
        vi.Finding(identifier="CVE-2020-0000", severity="LOW"),
    ]
    vi.apply_kev(findings, index)

    assert findings[0].kev is True
    assert findings[0].ransomware is True
    assert findings[0].kev_due_date == "2021-12-24"
    assert findings[0].severity == "CRITICAL"   # exploited -> treat as critical

    assert findings[1].kev is False
    assert findings[1].severity == "LOW"         # untouched


def test_apply_kev_matches_via_alias():
    index = vi.kev_index(KEV_FIXTURE)
    f = vi.Finding(identifier="GHSA-xxxx", aliases=["CVE-2019-10906"], severity="HIGH")
    vi.apply_kev([f], index)
    assert f.kev is True
    assert f.ransomware is False
    assert f.severity == "HIGH"   # already known, not overwritten


# ---------------------------------------------------------------------------
# Merging duplicate advisories for one CVE
# ---------------------------------------------------------------------------

def test_merge_collapses_duplicate_advisories_for_one_cve():
    """OSV returns a GHSA record AND a PYSEC record for the same CVE. Without
    merging, every such CVE is counted twice and the thin record invents an
    'unknown severity' entry beside the real one."""
    rich = vi.Finding(
        identifier="CVE-2019-10906", severity="HIGH", package="jinja2",
        installed_version="2.4.1", ecosystem="PyPI",
        summary="Sandbox escape", cvss_score=8.6, cwe="CWE-74",
        fixed_versions=["2.10.1"], aliases=["GHSA-462w-v97r-4m45"],
        references=["https://a.invalid"], published="2019-04-10",
    )
    thin = vi.Finding(
        identifier="CVE-2019-10906", severity="UNKNOWN", package="jinja2",
        installed_version="2.4.1", ecosystem="PyPI",
        summary="A much longer description of the very same issue, as OSV's "
                "details field tends to be",
        fixed_versions=["2.10.1"], aliases=["PYSEC-2019-217"],
        references=["https://b.invalid"],
    )

    merged = vi.merge_findings([rich, thin])
    assert len(merged) == 1

    finding = merged[0]
    assert finding.severity == "HIGH"              # best severity wins
    assert finding.cvss_score == 8.6
    assert finding.cwe == "CWE-74"
    assert finding.summary == "Sandbox escape"     # the concise one
    assert finding.aliases == ["GHSA-462w-v97r-4m45", "PYSEC-2019-217"]
    assert finding.fixed_versions == ["2.10.1"]    # unioned, not duplicated
    assert sorted(finding.references) == ["https://a.invalid",
                                          "https://b.invalid"]
    assert finding.published == "2019-04-10"


def test_merge_is_order_independent():
    def pair():
        return [
            vi.Finding(identifier="CVE-1", severity="UNKNOWN", package="p",
                       installed_version="1", ecosystem="PyPI",
                       summary="a longer summary here"),
            vi.Finding(identifier="CVE-1", severity="CRITICAL", package="p",
                       installed_version="1", ecosystem="PyPI", summary="short"),
        ]

    forward = vi.merge_findings(pair())
    backward = vi.merge_findings(list(reversed(pair())))
    assert forward[0].severity == backward[0].severity == "CRITICAL"
    assert forward[0].summary == backward[0].summary == "short"


def test_merge_preserves_kev_from_either_record():
    findings = [
        vi.Finding(identifier="CVE-1", package="p", installed_version="1",
                   ecosystem="PyPI", kev=False),
        vi.Finding(identifier="CVE-1", package="p", installed_version="1",
                   ecosystem="PyPI", kev=True),
    ]
    assert vi.merge_findings(findings)[0].kev is True


def test_merge_keeps_distinct_packages_and_versions_apart():
    findings = [
        vi.Finding(identifier="CVE-1", package="a", installed_version="1",
                   ecosystem="PyPI"),
        vi.Finding(identifier="CVE-1", package="b", installed_version="1",
                   ecosystem="PyPI"),
        vi.Finding(identifier="CVE-1", package="a", installed_version="2",
                   ecosystem="PyPI"),
        vi.Finding(identifier="CVE-2", package="a", installed_version="1",
                   ecosystem="PyPI"),
    ]
    assert len(vi.merge_findings(findings)) == 4


def test_scan_merges_duplicate_advisories(monkeypatch, tmp_path):
    (tmp_path / "requirements.txt").write_text("jinja2==2.4.1\n")

    ghsa = dict(OSV_FIXTURE)
    pysec = {
        "id": "PYSEC-2019-217",
        "aliases": ["CVE-2019-10906"],
        "details": "The same issue, described at length by a second database.",
        "affected": [{
            "package": {"name": "jinja2", "ecosystem": "PyPI"},
            "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.10.1"}]}],
        }],
        "references": [],
    }
    monkeypatch.setattr(vi, "osv_query", lambda n, v, e: [ghsa, pysec])

    result = vi.scan_dependencies(tmp_path, workers=1)
    assert len(result.findings) == 1               # not 2
    assert result.findings[0].identifier == "CVE-2019-10906"
    assert result.findings[0].severity == "HIGH"   # not UNKNOWN


# ---------------------------------------------------------------------------
# Prioritisation / gating
# ---------------------------------------------------------------------------

def test_sort_puts_kev_first_then_severity():
    findings = [
        vi.Finding(identifier="C", severity="LOW"),
        vi.Finding(identifier="A", severity="CRITICAL"),
        vi.Finding(identifier="B", severity="MEDIUM", kev=True),
        vi.Finding(identifier="D", severity="HIGH"),
    ]
    order = [f.identifier for f in vi.sort_findings(findings)]
    assert order == ["B", "A", "D", "C"]   # KEV wins even at MEDIUM


def test_sort_breaks_severity_ties_on_cvss():
    findings = [
        vi.Finding(identifier="low-score", severity="HIGH", cvss_score=7.1),
        vi.Finding(identifier="high-score", severity="HIGH", cvss_score=8.9),
    ]
    assert [f.identifier for f in vi.sort_findings(findings)] == [
        "high-score", "low-score",
    ]


def test_meets_threshold():
    findings = [vi.Finding(identifier="x", severity="MEDIUM")]
    assert vi.meets_threshold(findings, "medium")
    assert vi.meets_threshold(findings, "low")
    assert not vi.meets_threshold(findings, "high")
    with pytest.raises(ValueError):
        vi.meets_threshold(findings, "bogus")


def test_severity_counts_normalises_case():
    findings = [
        vi.Finding(identifier="a", severity="high"),
        vi.Finding(identifier="b", severity="HIGH"),
        vi.Finding(identifier="c", severity=""),
    ]
    counts = vi.severity_counts(findings)
    assert counts["HIGH"] == 2
    assert counts["UNKNOWN"] == 1


# ---------------------------------------------------------------------------
# Full dependency scan (OSV stubbed)
# ---------------------------------------------------------------------------

def test_scan_dependencies_end_to_end(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text(
        "jinja2==2.4.1\nrequests==2.31.0\nflask>=1.0\n"
    )

    calls = []

    def fake_osv_query(name, version, ecosystem):
        calls.append((name, version, ecosystem))
        return [OSV_FIXTURE] if name == "jinja2" else []

    monkeypatch.setattr(vi, "osv_query", fake_osv_query)

    result = vi.scan_dependencies(tmp_path, workers=2)

    assert result.packages_checked == 2          # unpinned flask excluded
    assert ("jinja2", "2.4.1", "PyPI") in calls
    assert len(result.findings) == 1
    assert result.findings[0].identifier == "CVE-2019-10906"
    assert result.errors == []
    assert len(result.manifests) == 1


def test_scan_dependencies_dedupes_across_manifests(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("jinja2==2.4.1\n")
    sub = tmp_path / "service"
    sub.mkdir()
    (sub / "requirements.txt").write_text("jinja2==2.4.1\n")

    seen = []
    monkeypatch.setattr(vi, "osv_query",
                        lambda n, v, e: seen.append((n, v, e)) or [])

    result = vi.scan_dependencies(tmp_path, workers=1)
    assert len(seen) == 1                   # same package+version queried once
    assert len(result.manifests) == 2


def test_scan_dependencies_survives_lookup_errors(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("jinja2==2.4.1\nrequests==2.31.0\n")

    def flaky(name, version, ecosystem):
        if name == "jinja2":
            raise vi.VulnIntelError("network down")
        return []

    monkeypatch.setattr(vi, "osv_query", flaky)
    result = vi.scan_dependencies(tmp_path, workers=1)

    assert len(result.errors) == 1
    assert "network down" in result.errors[0]
    assert result.packages_checked == 2     # scan still completed


def test_scan_dependencies_reports_bad_manifest(tmp_path, monkeypatch):
    (tmp_path / "package-lock.json").write_text("{ not json")
    monkeypatch.setattr(vi, "osv_query", lambda n, v, e: [])
    result = vi.scan_dependencies(tmp_path)
    assert result.errors and "package-lock.json" in result.errors[0]


def test_scan_dependencies_on_empty_tree(tmp_path):
    result = vi.scan_dependencies(tmp_path)
    assert result.findings == []
    assert result.manifests == []
    assert "No dependency manifests found" in vi.text_report(result)


# ---------------------------------------------------------------------------
# SBOM scanning (shares the OSV lookup path with manifest scanning)
# ---------------------------------------------------------------------------

CYCLONEDX_DOC = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "metadata": {
        "component": {"name": "vendor-appliance"},
        "tools": {"components": [{"name": "syft", "version": "1.4.1"}]},
    },
    "components": [
        {"name": "jinja2", "version": "2.4.1", "purl": "pkg:pypi/jinja2@2.4.1"},
        {"name": "lodash", "version": "4.17.11",
         "purl": "pkg:npm/lodash@4.17.11"},
        # Not checkable: no purl, so the ecosystem is unknown.
        {"name": "mystery-blob", "version": "1.0"},
        # Not checkable: OS package with no distro version.
        {"name": "bash", "version": "5.1", "purl": "pkg:deb/debian/bash@5.1"},
    ],
}


def _write_bom(tmp_path, doc=None):
    path = tmp_path / "bom.json"
    path.write_text(json.dumps(doc or CYCLONEDX_DOC), encoding="utf-8")
    return path


def test_scan_sbom_checks_only_mappable_components(tmp_path, monkeypatch):
    queried = []

    def fake_osv_query(name, version, ecosystem):
        queried.append((name, version, ecosystem))
        return [OSV_FIXTURE] if name == "jinja2" else []

    monkeypatch.setattr(vi, "osv_query", fake_osv_query)

    result, sbom = vi.scan_sbom(_write_bom(tmp_path), workers=2)

    assert sorted(queried) == [
        ("jinja2", "2.4.1", "PyPI"),
        ("lodash", "4.17.11", "npm"),
    ]
    assert result.packages_checked == 2
    assert len(result.findings) == 1
    assert sbom.fmt == "CycloneDX"


def test_scan_sbom_reports_what_it_could_not_check(tmp_path, monkeypatch):
    """The safety property: unmappable components surface as NOT CHECKED
    rather than being silently dropped and implied clean."""
    monkeypatch.setattr(vi, "osv_query", lambda n, v, e: [])

    result, _ = vi.scan_sbom(_write_bom(tmp_path), workers=1)

    assert result.not_checked == 2
    assert sum(result.not_checked_reasons.values()) == 2

    report = vi.text_report(result)
    assert "NOT CHECKED" in report
    assert "UNKNOWN, not as clean" in report


def test_scan_sbom_labels_its_source(tmp_path, monkeypatch):
    monkeypatch.setattr(vi, "osv_query", lambda n, v, e: [])
    result, _ = vi.scan_sbom(_write_bom(tmp_path), workers=1)

    assert result.source_label.startswith("SBOM: CycloneDX 1.5")
    assert "syft" in result.source_label

    report = vi.text_report(result)
    assert "source" in report
    assert "manifests scanned" not in report   # it's an SBOM, not a tree


def test_scan_sbom_json_report_carries_the_gap(tmp_path, monkeypatch):
    monkeypatch.setattr(vi, "osv_query", lambda n, v, e: [])
    result, _ = vi.scan_sbom(_write_bom(tmp_path), workers=1)

    report = vi.json_report(result)
    assert report["not_checked"] == 2
    assert report["not_checked_reasons"]
    assert report["inventory_source"].startswith("SBOM:")
    json.dumps(report)


def test_scan_sbom_propagates_a_bad_file(tmp_path):
    import coldlight_sbom

    path = tmp_path / "junk.json"
    path.write_text("not an sbom at all", encoding="utf-8")
    with pytest.raises(coldlight_sbom.SbomError):
        vi.scan_sbom(path)


def test_scan_components_dedupes_and_counts(monkeypatch):
    seen = []
    monkeypatch.setattr(vi, "osv_query",
                        lambda n, v, e: seen.append((n, v, e)) or [])

    jobs = [
        ("jinja2", "2.4.1", "PyPI", "a"),
        ("Jinja2", "2.4.1", "PyPI", "b"),   # same package, different case
        ("lodash", "4.17.11", "npm", "a"),
    ]
    result = vi.scan_components(jobs, workers=1)
    assert result.packages_checked == 2
    assert len(seen) == 2


def test_scan_components_handles_an_empty_inventory():
    result = vi.scan_components([], workers=1)
    assert result.packages_checked == 0
    assert result.findings == []


# ---------------------------------------------------------------------------
# Enrichment and reporting
# ---------------------------------------------------------------------------

def test_enrich_with_nvd_fills_missing_scores(monkeypatch):
    findings = [
        vi.Finding(identifier="CVE-2021-44228", severity="UNKNOWN"),
        vi.Finding(identifier="GHSA-nope", severity="HIGH"),      # not a CVE: skipped
        vi.Finding(identifier="CVE-2020-1", severity="HIGH", cvss_score=5.0),  # has one
    ]
    monkeypatch.setattr(vi, "nvd_lookup", lambda cid: vi.parse_nvd_cve(NVD_FIXTURE))

    assert vi.enrich_with_nvd(findings) == 1
    assert findings[0].cvss_score == 10.0
    assert findings[0].cwe == "CWE-502"
    assert findings[0].severity == "CRITICAL"
    assert findings[2].cvss_score == 5.0      # untouched


def test_enrich_respects_limit(monkeypatch):
    findings = [vi.Finding(identifier=f"CVE-2021-{i:05d}") for i in range(10)]
    monkeypatch.setattr(vi, "nvd_lookup", lambda cid: vi.parse_nvd_cve(NVD_FIXTURE))
    assert vi.enrich_with_nvd(findings, limit=3) == 3


def test_format_finding_surfaces_kev_and_exploit_reference():
    f = vi.Finding(
        identifier="CVE-2021-44228", severity="CRITICAL", cvss_score=10.0,
        cwe="CWE-502", package="log4j-core", installed_version="2.14.1",
        ecosystem="Maven", fixed_versions=["2.15.0"], kev=True,
        kev_due_date="2021-12-24", ransomware=True,
        exploitdb_refs=["https://www.exploit-db.com/exploits/50592"],
    )
    text = vi.format_finding(f)
    assert "[KEV]" in text
    assert "KNOWN EXPLOITED" in text
    assert "2021-12-24" in text
    assert "ransomware" in text
    assert "fixed in 2.15.0" in text
    assert "exploit-db.com" in text


def test_json_report_shape():
    result = vi.ScanResult(
        findings=[vi.Finding(identifier="CVE-1", severity="HIGH", kev=True)],
        manifests=["requirements.txt"],
        packages_checked=1,
    )
    report = vi.json_report(result)
    assert report["known_exploited"] == 1
    assert report["severity_counts"] == {"HIGH": 1}
    assert report["findings"][0]["identifier"] == "CVE-1"
    assert "osv.dev" in report["sources"]
    json.dumps(report)   # must be serialisable


def test_http_errors_become_vulnintel_errors(monkeypatch):
    import urllib.error

    def boom(*a, **k):
        raise urllib.error.URLError("no route to host")

    monkeypatch.setattr(vi.urllib.request, "urlopen", boom)
    monkeypatch.setattr(vi.time, "sleep", lambda s: None)
    with pytest.raises(vi.VulnIntelError):
        vi._http_json("https://example.invalid/x")


# ---------------------------------------------------------------------------
# TLS trust (verification must never be weakened)
# ---------------------------------------------------------------------------

def test_ssl_context_always_verifies():
    import ssl

    ctx = vi.ssl_context()
    assert ctx.check_hostname is True
    assert ctx.verify_mode == ssl.CERT_REQUIRED


def test_ca_bundle_prefers_explicit_env(tmp_path, monkeypatch):
    bundle = tmp_path / "cacert.pem"
    bundle.write_text("# not a real bundle, just a path check")
    monkeypatch.setenv("COLDLIGHT_CA_BUNDLE", str(bundle))
    assert vi.ca_bundle() == str(bundle)


def test_ca_bundle_ignores_missing_path(tmp_path, monkeypatch):
    monkeypatch.setenv("COLDLIGHT_CA_BUNDLE", str(tmp_path / "nope.pem"))
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    # Falls through to certifi or the system default -- never to "no bundle
    # because the configured one was bad".
    assert vi.ca_bundle() != str(tmp_path / "nope.pem")


def test_cert_verification_failure_is_actionable_and_not_retried(monkeypatch):
    import ssl
    import urllib.error

    attempts = []

    def boom(*a, **k):
        attempts.append(1)
        raise urllib.error.URLError(
            ssl.SSLCertVerificationError("certificate has expired")
        )

    monkeypatch.setattr(vi.urllib.request, "urlopen", boom)
    monkeypatch.setattr(vi.time, "sleep", lambda s: None)

    with pytest.raises(vi.VulnIntelError) as excinfo:
        vi._http_json("https://services.nvd.nist.gov/x")

    message = str(excinfo.value)
    assert "TLS verification failed" in message
    assert "COLDLIGHT_CA_BUNDLE" in message          # tells the operator the fix
    assert "Do not disable certificate verification" in message
    assert len(attempts) == 1                      # no pointless retries


# ---------------------------------------------------------------------------
# Recognising the advisory page
#
# GHSA records in OSV type every reference WEB or PACKAGE and never ADVISORY,
# so on a real Next.js scan 11 of 33 findings listed their own GitHub advisory
# among the unlabelled links. Five more advisory-shaped URLs on that same scan
# belonged to OTHER projects, which is why the shape alone is not enough.
# ---------------------------------------------------------------------------

NEXT_ADVISORY = ("https://github.com/vercel/next.js"
                 "/security/advisories/GHSA-2xp9-vwfh-vxw4")
OTHER_ADVISORY = ("https://github.com/strukturag/libheif"
                  "/security/advisories/GHSA-g89c-p67h-r497")


def _osv(refs, *, vid="GHSA-2xp9-vwfh-vxw4", aliases=()):
    """One OSV record whose references carry only the types OSV really uses."""
    return {
        "id": vid,
        "aliases": list(aliases),
        "summary": "Something in Middleware",
        "references": [{"type": t, "url": u} for u, t in refs],
    }


def _kind_of(finding, url):
    for kind, urls in finding.reference_kinds.items():
        if url in urls:
            return kind
    return None


def test_a_repo_advisory_page_naming_this_finding_is_recognised():
    finding = vi.parse_osv_vuln(
        _osv([(NEXT_ADVISORY, "WEB")]),
        package="next", ecosystem="npm", version="14.2.21")

    assert _kind_of(finding, NEXT_ADVISORY) == vi.KIND_ADVISORY_LIKELY


def test_an_advisory_page_for_another_project_is_left_alone():
    """The shape matches but the identifier does not. Labelling this
    "Advisory" would send the reader to a different component's write-up --
    the single worst outcome for a link in a report."""
    finding = vi.parse_osv_vuln(
        _osv([(OTHER_ADVISORY, "WEB")]),
        package="next", ecosystem="npm", version="14.2.21")

    assert _kind_of(finding, OTHER_ADVISORY) == vi.KIND_OTHER


def test_the_right_advisory_is_picked_out_of_a_mixed_list():
    """Both URLs are advisory-shaped; only one is this finding's."""
    finding = vi.parse_osv_vuln(
        _osv([(OTHER_ADVISORY, "WEB"), (NEXT_ADVISORY, "WEB")]),
        package="next", ecosystem="npm", version="14.2.21")

    assert finding.reference_kinds[vi.KIND_ADVISORY_LIKELY] == [NEXT_ADVISORY]
    assert finding.reference_kinds[vi.KIND_OTHER] == [OTHER_ADVISORY]


def test_an_alias_names_the_advisory_too():
    """A CVE-numbered finding links its GHSA page: the GHSA id is the alias,
    not the identifier, so matching only the identifier would miss it."""
    url = ("https://github.com/vercel/next.js"
           "/security/advisories/GHSA-m99w-x7hq-7vfj")
    finding = vi.parse_osv_vuln(
        _osv([(url, "WEB")], vid="GHSA-m99w-x7hq-7vfj",
             aliases=["CVE-2026-64641"]),
        package="next", ecosystem="npm", version="14.2.21")

    assert finding.identifier == "CVE-2026-64641"       # display id is the CVE
    assert _kind_of(finding, url) == vi.KIND_ADVISORY_LIKELY


def test_the_central_advisory_database_page_is_recognised():
    url = "https://github.com/advisories/GHSA-2xp9-vwfh-vxw4"
    finding = vi.parse_osv_vuln(
        _osv([(url, "WEB")]),
        package="next", ecosystem="npm", version="14.2.21")

    assert _kind_of(finding, url) == vi.KIND_ADVISORY_LIKELY


def test_a_stated_advisory_is_not_downgraded_to_the_inference():
    """When the database typed it ADVISORY, that is what the report says --
    the inference never overwrites a statement."""
    finding = vi.parse_osv_vuln(
        _osv([(NEXT_ADVISORY, "ADVISORY")]),
        package="next", ecosystem="npm", version="14.2.21")

    assert _kind_of(finding, NEXT_ADVISORY) == vi.KIND_ADVISORY


def test_an_nvd_reference_is_matched_on_the_cve_id():
    url = ("https://github.com/vercel/next.js"
           "/security/advisories/GHSA-2xp9-vwfh-vxw4")
    own = "https://github.com/acme/widget/security/advisories/CVE-2026-64641"
    finding = vi.parse_nvd_cve({"cve": {
        "id": "CVE-2026-64641",
        "descriptions": [{"lang": "en", "value": "x"}],
        "references": [{"url": url}, {"url": own}],
    }})

    assert _kind_of(finding, own) == vi.KIND_ADVISORY_LIKELY
    assert _kind_of(finding, url) == vi.KIND_OTHER


def test_a_commit_url_is_still_read_as_the_patch():
    """The advisory check must not have displaced the patch inference."""
    url = "https://github.com/vercel/next.js/commit/abc123def456"
    finding = vi.parse_osv_vuln(
        _osv([(url, "WEB")]),
        package="next", ecosystem="npm", version="14.2.21")

    assert _kind_of(finding, url) == vi.KIND_PATCH_LIKELY


@pytest.mark.parametrize("identifiers", [(), ("",), ("GHSA",), ("CVE-1",)])
def test_nothing_is_promoted_without_a_usable_identifier(identifiers):
    """No identifiers, or ones too short to be a vulnerability id. A string of
    four characters would match far too much of any URL."""
    assert not vi.infer_advisory_reference(NEXT_ADVISORY, identifiers)


@pytest.mark.parametrize("url", [
    "https://mirror.invalid/vuln/GHSA-2xp9-vwfh-vxw4",
    "https://nvd.nist.gov/vuln/detail/GHSA-2xp9-vwfh-vxw4",
    "https://github.com/vercel/next.js/issues/GHSA-2xp9-vwfh-vxw4",
    "https://github.com/vercel/next.js/releases/GHSA-2xp9-vwfh-vxw4",
])
def test_naming_the_finding_does_not_make_a_page_the_advisory(url):
    """Each of these carries the identifier, so the identifier check alone
    would accept it. Only the URL shape separates the advisory page from a
    mirror, a database record or an issue that merely cites the id."""
    assert not vi.infer_advisory_reference(url, ["GHSA-2xp9-vwfh-vxw4"])


def test_the_advisory_kind_has_a_place_in_the_priority_order():
    """Every kind must be orderable or _group_references silently drops it."""
    assert vi.KIND_ADVISORY_LIKELY in vi.KIND_PRIORITY
    assert (vi.KIND_PRIORITY.index(vi.KIND_ADVISORY)
            < vi.KIND_PRIORITY.index(vi.KIND_ADVISORY_LIKELY)
            < vi.KIND_PRIORITY.index(vi.KIND_OTHER))
