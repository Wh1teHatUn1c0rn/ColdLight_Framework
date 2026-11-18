"""Tests for severity provenance.

The point of the feature: a NIST CVSS 9.8 and a ColdLight opinion must never be
indistinguishable in a report. These tests pin down where each severity claims
to come from, and that the report shows the split.
"""

import json

import pytest

import coldlight_codescan as cs
import coldlight_engagement as eng
import coldlight_mail as rm
import coldlight_vulnintel as vi


# ---------------------------------------------------------------------------
# The vocabulary, and the guard against drift
# ---------------------------------------------------------------------------

def test_modules_that_judge_declare_a_canonical_source():
    """coldlight_codescan and coldlight_mail set literals rather than importing the
    constants. This is the test that stops the two drifting apart."""
    assert cs.SEVERITY_SOURCE in vi.SEVERITY_SOURCES
    assert rm.SEVERITY_SOURCE in vi.SEVERITY_SOURCES


def test_our_own_sources_are_not_claimed_as_measurements():
    assert not vi.is_measured(cs.SEVERITY_SOURCE)
    assert not vi.is_measured(rm.SEVERITY_SOURCE)
    assert not vi.is_measured(vi.SEV_SRC_KEV)
    assert not vi.is_measured(vi.SEV_SRC_UNSCORED)


def test_external_authorities_are_measurements():
    assert vi.is_measured(vi.SEV_SRC_NVD)
    assert vi.is_measured(vi.SEV_SRC_OSV)


def test_every_source_has_a_human_label():
    for source in vi.SEVERITY_SOURCES:
        assert vi.SEVERITY_SOURCE_LABELS.get(source)
        assert eng.severity_source_label(source) != "unrecorded"


def test_report_layer_agrees_with_the_intel_layer():
    """engagement keeps its own label map for presentation; it must cover the
    canonical set and classify measurement the same way."""
    for source in vi.SEVERITY_SOURCES:
        assert source in eng.SEVERITY_SOURCE_LABELS
        assert eng.is_measured(source) == vi.is_measured(source)


# ---------------------------------------------------------------------------
# Where each severity comes from
# ---------------------------------------------------------------------------

NVD_SCORED = {
    "cve": {
        "id": "CVE-2021-44228",
        "descriptions": [{"lang": "en", "value": "x"}],
        "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {
            "baseScore": 10.0, "baseSeverity": "CRITICAL",
            "vectorString": "CVSS:3.1/AV:N"}}]},
        "references": [],
    }
}


def test_nvd_cvss_severity_is_recorded_as_measured():
    finding = vi.parse_nvd_cve(NVD_SCORED)
    assert finding.severity == "CRITICAL"
    assert finding.severity_source == vi.SEV_SRC_NVD
    assert vi.is_measured(finding.severity_source)


def test_nvd_record_without_cvss_is_unscored():
    record = {"cve": {"id": "CVE-1", "descriptions": [], "metrics": {},
                      "references": []}}
    finding = vi.parse_nvd_cve(record)
    assert finding.severity == "UNKNOWN"
    assert finding.severity_source == vi.SEV_SRC_UNSCORED


OSV_RATED = {
    "id": "GHSA-x",
    "aliases": ["CVE-2024-1"],
    "summary": "s",
    "database_specific": {"severity": "HIGH"},
    "affected": [{"package": {"name": "p", "ecosystem": "PyPI"},
                  "ranges": [{"type": "ECOSYSTEM",
                              "events": [{"introduced": "0"}]}]}],
    "references": [],
}


def test_osv_rating_is_attributed_to_the_database_not_to_nvd():
    """GHSA's curator rating is not a CVSS base score, and must not be
    presented as one."""
    finding = vi.parse_osv_vuln(OSV_RATED, package="p", ecosystem="PyPI",
                                version="1.0")
    assert finding.severity == "HIGH"
    assert finding.severity_source == vi.SEV_SRC_OSV
    assert finding.severity_source != vi.SEV_SRC_NVD


def test_osv_record_without_a_rating_is_unscored():
    vuln = dict(OSV_RATED)
    vuln.pop("database_specific")
    vuln["affected"] = [{"package": {"name": "p", "ecosystem": "PyPI"},
                         "ranges": []}]
    finding = vi.parse_osv_vuln(vuln, package="p", ecosystem="PyPI",
                                version="1.0")
    assert finding.severity_source == vi.SEV_SRC_UNSCORED


# ---------------------------------------------------------------------------
# The KEV promotion is ours, and says so
# ---------------------------------------------------------------------------

KEV_FIXTURE = {"vulnerabilities": [
    {"cveID": "CVE-2021-44228", "dueDate": "2021-12-24",
     "knownRansomwareCampaignUse": "Known"},
]}


def test_kev_promotion_is_attributed_to_coldlight():
    """apply_kev raises an unscored finding to CRITICAL. That is our call --
    nothing published that rating -- so the provenance must not imply CVSS."""
    finding = vi.Finding(identifier="CVE-2021-44228", severity="UNKNOWN",
                         severity_source=vi.SEV_SRC_UNSCORED)
    vi.apply_kev([finding], vi.kev_index(KEV_FIXTURE))

    assert finding.severity == "CRITICAL"
    assert finding.severity_source == vi.SEV_SRC_KEV
    assert not vi.is_measured(finding.severity_source)


def test_kev_does_not_overwrite_a_measured_severity():
    finding = vi.Finding(identifier="CVE-2021-44228", severity="HIGH",
                         severity_source=vi.SEV_SRC_NVD)
    vi.apply_kev([finding], vi.kev_index(KEV_FIXTURE))
    assert finding.severity == "HIGH"
    assert finding.severity_source == vi.SEV_SRC_NVD


# ---------------------------------------------------------------------------
# Merging and enrichment keep provenance honest
# ---------------------------------------------------------------------------

def test_the_winning_severity_carries_its_own_provenance():
    weak = vi.Finding(identifier="CVE-1", package="p", installed_version="1",
                      ecosystem="PyPI", severity="LOW",
                      severity_source=vi.SEV_SRC_OSV)
    strong = vi.Finding(identifier="CVE-1", package="p", installed_version="1",
                        ecosystem="PyPI", severity="CRITICAL",
                        severity_source=vi.SEV_SRC_NVD)

    merged = vi.merge_findings([weak, strong])[0]
    assert merged.severity == "CRITICAL"
    assert merged.severity_source == vi.SEV_SRC_NVD


def test_enrichment_from_nvd_records_the_measurement(monkeypatch):
    finding = vi.Finding(identifier="CVE-2021-44228", severity="UNKNOWN",
                         severity_source=vi.SEV_SRC_UNSCORED)
    monkeypatch.setattr(vi, "nvd_lookup",
                        lambda cve: vi.parse_nvd_cve(NVD_SCORED))
    vi.enrich_with_nvd([finding])
    assert finding.severity == "CRITICAL"
    assert finding.severity_source == vi.SEV_SRC_NVD


# ---------------------------------------------------------------------------
# Our own findings
# ---------------------------------------------------------------------------

def test_code_findings_declare_the_rule_table():
    finding = cs.CodeFinding("CMD-OS-SYSTEM", "HIGH", "CWE-78", "t",
                             "a.py", 1, "os.system(x)")
    assert finding.severity_source == "coldlight-rule"
    assert finding.to_dict()["severity_source"] == "coldlight-rule"


def test_mail_findings_declare_a_judgement():
    finding = rm.MailFinding("DMARC", "HIGH", "No DMARC record")
    assert finding.severity_source == "coldlight-judgement"
    assert finding.to_dict()["severity_source"] == "coldlight-judgement"


def test_a_real_code_scan_carries_provenance(tmp_path):
    (tmp_path / "app.py").write_text("import os\nos.system(x)\n",
                                     encoding="utf-8")
    result = cs.scan_code(tmp_path)
    assert result.findings
    assert all(f.severity_source == "coldlight-rule" for f in result.findings)
    payload = cs.json_report(result)
    assert payload["findings"][0]["severity_source"] == "coldlight-rule"


def test_a_real_mail_audit_carries_provenance():
    def query(name, rtype="TXT"):
        return rm.DnsAnswer(status=3, records=[])

    audit = rm.audit_domain("example.com", query=query, fetch_policy=False,
                            selectors=())
    assert audit.findings
    assert all(f.severity_source == "coldlight-judgement"
               for f in audit.findings)
    assert all(entry["severity_source"] == "coldlight-judgement"
               for entry in audit.to_dict()["findings"])


# ---------------------------------------------------------------------------
# The report: the split has to be visible
# ---------------------------------------------------------------------------

def write(tmp_path, name, payload):
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


def mixed_report(tmp_path):
    vuln = {"findings": [
        {"identifier": "CVE-1", "severity": "CRITICAL", "package": "p",
         "installed_version": "1", "ecosystem": "PyPI",
         "severity_source": "nvd-cvss", "fixed_versions": ["2"]},
        {"identifier": "CVE-2", "severity": "CRITICAL", "package": "q",
         "installed_version": "1", "ecosystem": "PyPI",
         "severity_source": "cisa-kev", "kev": True, "fixed_versions": []},
    ]}
    code = {"files_scanned": 1, "findings": [
        {"rule_id": "R1", "severity": "CRITICAL", "cwe": "CWE-798",
         "title": "Hardcoded credential", "file": "a.py", "line": 1,
         "snippet": "x", "remediation": "fix",
         "severity_source": "coldlight-rule"},
    ]}
    return eng.build_report(
        engagement=eng.Engagement(client="Acme"),
        vuln_paths=[write(tmp_path, "v.json", vuln)],
        code_paths=[write(tmp_path, "c.json", code)],
    )


def test_report_counts_measured_against_assessed(tmp_path):
    report = mixed_report(tmp_path)
    assert len(report.findings) == 3
    # Only the NVD one is an external measurement.
    assert report.measured_count == 1
    assert report.assessed_count == 2


def test_report_breaks_down_by_source(tmp_path):
    counts = mixed_report(tmp_path).provenance_counts()
    assert counts["nvd-cvss"] == 1
    assert counts["cisa-kev"] == 1
    assert counts["coldlight-rule"] == 1


def test_markdown_shows_the_split_not_just_a_total(tmp_path):
    """Three criticals from three different authorities must not read as one
    undifferentiated '3 critical'."""
    text = eng.render_markdown(mixed_report(tmp_path))
    assert "| Severity | Findings | Measured | Assessed by ColdLight |" in text
    assert "severities are an external measurement" in text
    assert "Severity source" in text
    assert "NVD CVSS base score" in text
    assert "ColdLight rule table" in text


def test_markdown_labels_each_finding(tmp_path):
    text = eng.render_markdown(mixed_report(tmp_path))
    assert "*(NVD CVSS base score)*" in text
    assert "*(ColdLight rule table)*" in text


def test_html_shows_the_split(tmp_path):
    out = eng.render_html(mixed_report(tmp_path))
    assert "<th>Measured</th>" in out
    assert "Assessed by ColdLight" in out
    assert "NVD CVSS base score" in out


def test_json_report_exposes_provenance(tmp_path):
    payload = json.loads(eng.render(mixed_report(tmp_path), "json"))
    assert payload["severities_measured"] == 1
    assert payload["severities_assessed_by_coldlight"] == 2
    assert payload["severity_provenance"]["nvd-cvss"] == 1
    sources = {f["severity_source"] for f in payload["findings"]}
    assert sources == {"nvd-cvss", "cisa-kev", "coldlight-rule"}


def test_grouped_findings_report_mixed_provenance(tmp_path):
    vuln = {"findings": [
        {"identifier": f"CVE-{i}", "severity": "MEDIUM", "package": "p",
         "installed_version": "1", "ecosystem": "PyPI",
         "severity_source": ("nvd-cvss" if i % 2 else "osv-database"),
         "fixed_versions": ["2"]}
        for i in range(6)
    ]}
    report = eng.build_report(engagement=eng.Engagement(client="Acme"),
                              vuln_paths=[write(tmp_path, "v.json", vuln)])
    grouped = next(f for f in report.findings
                   if "Known-vulnerable" in f.title)
    assert grouped.severity_source == eng.SEV_SRC_MIXED
    assert eng.severity_source_label(grouped.severity_source) == "mixed sources"


def test_grouped_findings_keep_a_single_source_when_unanimous(tmp_path):
    vuln = {"findings": [
        {"identifier": f"CVE-{i}", "severity": "MEDIUM", "package": "p",
         "installed_version": "1", "ecosystem": "PyPI",
         "severity_source": "osv-database", "fixed_versions": ["2"]}
        for i in range(6)
    ]}
    report = eng.build_report(engagement=eng.Engagement(client="Acme"),
                              vuln_paths=[write(tmp_path, "v.json", vuln)])
    grouped = next(f for f in report.findings
                   if "Known-vulnerable" in f.title)
    assert grouped.severity_source == "osv-database"


def test_awareness_findings_are_marked_as_our_assessment(tmp_path):
    import coldlight_report as rr

    db = tmp_path / "hits.db"
    connection = rr.connect(str(db))
    rr.insert_hit(connection, {
        "engagement_id": "E", "run_id": "r1",
        "timestamp_utc": "2026-11-17T14:30:00Z",
        "received_utc": "2026-11-17T14:30:01Z",
        "hostname": "H", "username": "u", "os": "Windows",
        "ran_from": "E:\\",
    }, vector="usb")

    _summary, findings, _notes = eng.load_awareness(str(db))
    assert findings
    assert all(f.severity_source == "coldlight-judgement" for f in findings)


def test_unrecorded_provenance_degrades_gracefully():
    finding = eng.Finding(title="x", severity="HIGH", category="c")
    assert finding.severity_source == ""
    assert eng.severity_source_label("") == "unrecorded"
    assert eng.is_measured("") is False
