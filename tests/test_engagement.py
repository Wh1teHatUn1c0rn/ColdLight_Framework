"""Tests for coldlight_engagement (the deliverable assembler)."""

import json

import pytest

import coldlight_engagement as eng


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def write(tmp_path, name, payload):
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


def vuln_finding(identifier, severity="HIGH", *, package="pkg", kev=False,
                 fixes=("1.1",), cwe=""):
    return {
        "identifier": identifier,
        "severity": severity,
        "package": package,
        "installed_version": "1.0",
        "ecosystem": "PyPI",
        "fixed_versions": list(fixes),
        "summary": f"Summary for {identifier}",
        "kev": kev,
        "cwe": cwe,
        "references": ["https://example.invalid/a"],
    }


def vuln_report(findings, **over):
    payload = {
        "tool": "coldlight vulnintel",
        "inventory_source": "dependency manifests",
        "findings": findings,
        "not_checked": 0,
        "not_checked_reasons": {},
        "errors": [],
    }
    payload.update(over)
    return payload


def code_report(findings, files=10, errors=()):
    return {
        "tool": "coldlight codescan",
        "files_scanned": files,
        "findings": findings,
        "errors": list(errors),
    }


def code_finding(rule_id, severity="HIGH", *, file="app.py", line=1,
                 cwe="CWE-78", title=None):
    return {
        "rule_id": rule_id,
        "severity": severity,
        "cwe": cwe,
        "title": title or f"Title for {rule_id}",
        "file": file,
        "line": line,
        "snippet": "os.system(cmd)",
        "remediation": "Use an argument list.",
    }


def mail_report(**over):
    payload = {
        "domain": "example.com",
        "spoofable": True,
        "protection_level": "none",
        "verdict": "SPOOFABLE -- no DMARC record",
        "subdomains_spoofable": True,
        "dkim": {"found": False},
        "mta_sts": {"fetch_attempted": True},
        "findings": [{
            "check": "DMARC", "severity": "HIGH", "title": "No DMARC record",
            "detail": "No policy.", "remediation": "Publish a record.",
        }],
    }
    payload.update(over)
    return payload


def basic_engagement():
    return eng.Engagement(engagement_id="ENG-1", client="Acme",
                          assessor="Offensive Unicorn Crew")


# ---------------------------------------------------------------------------
# Severity normalisation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("given,expected", [
    ("CRITICAL", "CRITICAL"), ("critical", "CRITICAL"),
    ("MODERATE", "MEDIUM"),                 # OSV wording folds into MEDIUM
    ("moderate", "MEDIUM"),
    ("", "UNKNOWN"), ("UNKNOWN", "UNKNOWN"),
    ("OK", "INFO"), ("nonsense", "UNKNOWN"),
])
def test_severity_normalisation(given, expected):
    assert eng.normalise_severity(given) == expected


def test_unknown_outranks_info():
    """An unscored CVE is untriaged, not harmless."""
    assert eng.SEVERITY_ORDER["UNKNOWN"] > eng.SEVERITY_ORDER["INFO"]
    assert eng.SEVERITY_ORDER["LOW"] > eng.SEVERITY_ORDER["UNKNOWN"]


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def test_load_vulnerability_findings(tmp_path):
    path = write(tmp_path, "v.json", vuln_report([
        vuln_finding("CVE-2021-1", kev=True, cwe="CWE-502"),
    ]))
    findings, notes = eng.load_vulnerability_findings(path)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.kev is True
    assert "CVE-2021-1" in finding.title
    assert "CVE-2021-1" in finding.identifiers
    assert "CWE-502" in finding.identifiers
    assert "Upgrade pkg to 1.1." == finding.remediation
    assert notes == []


def test_unfixable_vulnerability_gets_different_remediation(tmp_path):
    path = write(tmp_path, "v.json",
                 vuln_report([vuln_finding("CVE-1", fixes=())]))
    findings, _ = eng.load_vulnerability_findings(path)
    assert "no fixed version" in findings[0].remediation.lower()


def test_not_checked_components_become_a_limitation(tmp_path):
    """The SBOM gap must survive into the report's limitations section."""
    path = write(tmp_path, "v.json", vuln_report(
        [], not_checked=3,
        not_checked_reasons={"unsupported purl type: 'docker'": 3},
        inventory_source="SBOM: CycloneDX 1.5"))
    _findings, notes = eng.load_vulnerability_findings(path)
    assert any("UNKNOWN rather than clean" in n for n in notes)
    assert any("docker" in n for n in notes)


def test_load_code_findings_groups_by_rule(tmp_path):
    path = write(tmp_path, "c.json", code_report([
        code_finding("CMD-OS-SYSTEM", file="a.py", line=1),
        code_finding("CMD-OS-SYSTEM", file="b.py", line=9),
        code_finding("CODE-EVAL", file="c.py", line=3, cwe="CWE-95"),
    ]))
    findings, _notes = eng.load_code_findings(path)
    assert len(findings) == 2            # two rules, not three occurrences

    grouped = next(f for f in findings if "CMD-OS-SYSTEM" in f.identifiers)
    assert grouped.count == 2
    assert "2 occurrences" in grouped.title
    assert any("a.py:1" in e for e in grouped.evidence)
    assert any("b.py:9" in e for e in grouped.evidence)


def test_code_evidence_is_capped_with_a_tail_note(tmp_path):
    path = write(tmp_path, "c.json", code_report([
        code_finding("R", file=f"f{i}.py", line=i) for i in range(30)
    ]))
    findings, _ = eng.load_code_findings(path)
    finding = findings[0]
    assert finding.count == 30
    assert len(finding.evidence) == 21            # 20 shown + the tail note
    assert "further occurrence" in finding.evidence[-1]


def test_code_scan_limitation_is_recorded(tmp_path):
    path = write(tmp_path, "c.json", code_report([], files=42))
    _findings, notes = eng.load_code_findings(path)
    assert any("42 file(s)" in n for n in notes)
    assert any("not proof of absence" in n for n in notes)


def test_load_mail_findings(tmp_path):
    path = write(tmp_path, "m.json", mail_report())
    findings, summary, notes = eng.load_mail_findings(path)
    assert summary.domain == "example.com"
    assert summary.spoofable is True
    assert summary.protection_level == "none"
    assert len(findings) == 1
    assert "example.com" in findings[0].title
    assert any("inconclusive" in n for n in notes)       # DKIM caveat


def test_mail_no_fetch_becomes_a_limitation(tmp_path):
    path = write(tmp_path, "m.json",
                 mail_report(mta_sts={"fetch_attempted": False}))
    _findings, _summary, notes = eng.load_mail_findings(path)
    assert any("was not fetched" in n for n in notes)


def test_missing_file_raises():
    with pytest.raises(eng.EngagementError, match="no such file"):
        eng.load_vulnerability_findings("nope.json")


def test_bad_json_raises(tmp_path):
    path = tmp_path / "x.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(eng.EngagementError, match="not valid JSON"):
        eng.load_vulnerability_findings(path)


def test_non_object_json_raises(tmp_path):
    path = tmp_path / "x.json"
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(eng.EngagementError, match="expected a JSON object"):
        eng.load_vulnerability_findings(path)


# ---------------------------------------------------------------------------
# Awareness
# ---------------------------------------------------------------------------

def seed_hits(tmp_path, vectors=("usb", "usb", "link")):
    import coldlight_report as rr

    db = tmp_path / "hits.db"
    connection = rr.connect(str(db))
    for index, vector in enumerate(vectors):
        rr.insert_hit(connection, {
            "engagement_id": "ENG-1",
            "run_id": f"r{index}",
            "timestamp_utc": "2026-11-17T14:30:00Z",
            "received_utc": "2026-11-17T14:30:01Z",
            "hostname": f"HOST-{index}",
            "username": f"user{index}",
            "os": "Windows 10",
            "ran_from": "E:\\",
        }, vector=vector)
    return str(db)


def test_awareness_summary_and_findings(tmp_path):
    summary, findings, notes = eng.load_awareness(seed_hits(tmp_path))
    assert summary.total_runs == 3
    assert summary.by_vector == {"usb": 2, "link": 1}

    usb = next(f for f in findings if "removable media" in f.title)
    assert usb.severity == "HIGH"
    assert usb.count == 2
    assert "T1091" in usb.identifiers
    # Remediation must offer a technical control, not only training.
    assert "AppLocker" in usb.remediation or "policy" in usb.remediation

    link = next(f for f in findings if "untrusted link" in f.title)
    assert link.severity == "MEDIUM"
    assert "T1566.002" in link.identifiers

    assert any("detection coverage" in n for n in notes)


def test_awareness_with_no_hits_yields_no_findings(tmp_path):
    summary, findings, _notes = eng.load_awareness(seed_hits(tmp_path, ()))
    assert summary.total_runs == 0
    assert findings == []


def test_awareness_missing_db_raises():
    with pytest.raises(eng.EngagementError, match="no such database"):
        eng.load_awareness("nope.db")


# ---------------------------------------------------------------------------
# VEX suppression
# ---------------------------------------------------------------------------

def vex_file(tmp_path, statements):
    return write(tmp_path, "triage.json", {
        "product": {"name": "app"},
        "statements": statements,
    })


def test_vex_suppresses_not_affected_and_fixed(tmp_path):
    decisions = eng.load_vex_decisions(vex_file(tmp_path, [
        {"vulnerability": "CVE-1", "status": "not_affected",
         "justification": "vulnerable_code_not_in_execute_path"},
        {"vulnerability": "CVE-2", "status": "fixed"},
        {"vulnerability": "CVE-3", "status": "affected",
         "action_statement": "Upgrade."},
        {"vulnerability": "CVE-4", "status": "under_investigation"},
    ]))

    findings = [eng.Finding(title=f"CVE-{i}", severity="HIGH",
                            category=eng.CATEGORY_DEPENDENCY,
                            identifiers=[f"CVE-{i}"]) for i in range(1, 5)]
    reportable, suppressed = eng.apply_vex(findings, decisions)

    assert {f.identifiers[0] for f in suppressed} == {"CVE-1", "CVE-2"}
    assert {f.identifiers[0] for f in reportable} == {"CVE-3", "CVE-4"}
    assert suppressed[0].vex_justification == "vulnerable_code_not_in_execute_path"


def test_vex_affected_stays_reportable_with_status(tmp_path):
    decisions = eng.load_vex_decisions(vex_file(tmp_path, [
        {"vulnerability": "CVE-9", "status": "affected",
         "action_statement": "Patch now."},
    ]))
    findings = [eng.Finding(title="x", severity="HIGH", category="c",
                            identifiers=["CVE-9"])]
    reportable, suppressed = eng.apply_vex(findings, decisions)
    assert suppressed == []
    assert reportable[0].vex_status == "affected"


def test_vex_matches_via_alias(tmp_path):
    decisions = eng.load_vex_decisions(vex_file(tmp_path, [
        {"vulnerability": "CVE-1", "status": "not_affected",
         "justification": "component_not_present",
         "aliases": ["GHSA-abcd"]},
    ]))
    findings = [eng.Finding(title="x", severity="HIGH", category="c",
                            identifiers=["GHSA-abcd"])]
    _reportable, suppressed = eng.apply_vex(findings, decisions)
    assert len(suppressed) == 1


def test_vex_ignores_statements_without_ids(tmp_path):
    decisions = eng.load_vex_decisions(vex_file(tmp_path, [
        {"status": "not_affected"}, "junk", {"vulnerability": "CVE-1"},
    ]))
    assert decisions == {}


# ---------------------------------------------------------------------------
# Grouping: the editorial core
# ---------------------------------------------------------------------------

def _dep(identifier, severity="MEDIUM", kev=False):
    return eng.Finding(
        title=identifier, severity=severity,
        category=eng.CATEGORY_DEPENDENCY, identifiers=[identifier],
        evidence=["pkg 1.0 (PyPI)"], remediation="Upgrade pkg to 1.1.",
        kev=kev,
    )


def test_grouping_promotes_kev_and_critical_and_groups_the_tail():
    findings = (
        [_dep("CVE-KEV", "HIGH", kev=True), _dep("CVE-CRIT", "CRITICAL")]
        + [_dep(f"CVE-T{i}", "MEDIUM") for i in range(10)]
    )
    grouped = eng.group_dependency_findings(findings)

    titles = [f.title for f in grouped]
    assert "CVE-KEV" in titles          # promoted: it's an action item
    assert "CVE-CRIT" in titles         # promoted
    assert len(grouped) == 3            # 2 promoted + 1 grouped tail

    tail = next(f for f in grouped if "Known-vulnerable third-party" in f.title)
    assert tail.count == 10
    assert tail.severity == "MEDIUM"
    assert len(tail.evidence) == 10     # nothing lost, just not headlined
    assert "CVE-T0" in tail.identifiers


def test_small_tail_is_not_grouped():
    findings = [_dep("CVE-1"), _dep("CVE-2")]
    grouped = eng.group_dependency_findings(findings)
    assert {f.title for f in grouped} == {"CVE-1", "CVE-2"}


def test_grouping_leaves_other_categories_alone():
    findings = [
        eng.Finding(title="code thing", severity="HIGH",
                    category=eng.CATEGORY_CODE),
        eng.Finding(title="mail thing", severity="HIGH",
                    category=eng.CATEGORY_EMAIL),
    ] + [_dep(f"CVE-{i}") for i in range(5)]
    grouped = eng.group_dependency_findings(findings)
    assert "code thing" in [f.title for f in grouped]
    assert "mail thing" in [f.title for f in grouped]


def test_grouped_tail_takes_the_worst_severity():
    findings = ([_dep(f"CVE-L{i}", "LOW") for i in range(4)]
                + [_dep("CVE-H", "HIGH")])
    grouped = eng.group_dependency_findings(findings)
    tail = next(f for f in grouped if "Known-vulnerable" in f.title)
    assert tail.severity == "HIGH"


def test_huge_tail_evidence_is_capped():
    findings = [_dep(f"CVE-{i}", "LOW") for i in range(60)]
    tail = next(f for f in eng.group_dependency_findings(findings)
                if "Known-vulnerable" in f.title)
    assert tail.count == 60
    assert len(tail.evidence) == 41               # 40 + tail note
    assert "further advisor" in tail.evidence[-1]


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------

def test_build_report_combines_every_source(tmp_path):
    report = eng.build_report(
        engagement=basic_engagement(),
        vuln_paths=[write(tmp_path, "v.json", vuln_report([
            vuln_finding("CVE-2021-44228", "CRITICAL", kev=True),
        ]))],
        code_paths=[write(tmp_path, "c.json",
                          code_report([code_finding("CMD-OS-SYSTEM")]))],
        mail_paths=[write(tmp_path, "m.json", mail_report())],
        hits_db=seed_hits(tmp_path),
    )

    categories = {f.category for f in report.findings}
    assert categories == {
        eng.CATEGORY_DEPENDENCY, eng.CATEGORY_CODE,
        eng.CATEGORY_EMAIL, eng.CATEGORY_AWARENESS,
    }
    assert len(report.sources) == 4
    assert report.awareness is not None and report.mail is not None


def test_findings_are_ranked_kev_first_and_given_ids(tmp_path):
    report = eng.build_report(
        engagement=basic_engagement(),
        vuln_paths=[write(tmp_path, "v.json", vuln_report([
            vuln_finding("CVE-LOW", "LOW"),
            vuln_finding("CVE-KEV", "MEDIUM", kev=True),
            vuln_finding("CVE-CRIT", "CRITICAL"),
        ]))],
    )
    assert [f.finding_id for f in report.findings][:3] == [
        "RO-001", "RO-002", "RO-003"]
    assert report.findings[0].kev is True          # KEV outranks CRITICAL


def test_exploitation_caveat_is_always_present(tmp_path):
    report = eng.build_report(
        engagement=basic_engagement(),
        vuln_paths=[write(tmp_path, "v.json", vuln_report([vuln_finding("CVE-1")]))],
    )
    assert any("No exploitation was attempted" in n
               for n in report.not_assessed)


def test_vex_suppression_flows_through_build(tmp_path):
    report = eng.build_report(
        engagement=basic_engagement(),
        vuln_paths=[write(tmp_path, "v.json", vuln_report([
            vuln_finding("CVE-1"), vuln_finding("CVE-2"),
        ]))],
        vex_path=vex_file(tmp_path, [
            {"vulnerability": "CVE-1", "status": "not_affected",
             "justification": "component_not_present"},
        ]),
    )
    assert len(report.suppressed) == 1
    assert all("CVE-1" not in f.identifiers for f in report.findings)


def test_raw_item_count_reflects_grouping(tmp_path):
    report = eng.build_report(
        engagement=basic_engagement(),
        vuln_paths=[write(tmp_path, "v.json", vuln_report(
            [vuln_finding(f"CVE-{i}", "MEDIUM") for i in range(10)]))],
    )
    assert len(report.findings) == 1           # grouped
    assert report.raw_item_count == 10         # but the count is honest


def test_no_group_lists_everything(tmp_path):
    report = eng.build_report(
        engagement=basic_engagement(),
        vuln_paths=[write(tmp_path, "v.json", vuln_report(
            [vuln_finding(f"CVE-{i}", "MEDIUM") for i in range(10)]))],
        group=False,
    )
    assert len(report.findings) == 10


# ---------------------------------------------------------------------------
# Executive summary
# ---------------------------------------------------------------------------

def test_summary_leads_with_kev(tmp_path):
    report = eng.build_report(
        engagement=basic_engagement(),
        vuln_paths=[write(tmp_path, "v.json", vuln_report([
            vuln_finding("CVE-2021-44228", "CRITICAL", kev=True)]))],
    )
    text = " ".join(eng.executive_summary(report))
    assert "known to be exploited in the wild" in text
    assert "CVE-2021-44228" in text


def test_summary_mentions_spoofability(tmp_path):
    report = eng.build_report(
        engagement=basic_engagement(),
        mail_paths=[write(tmp_path, "m.json", mail_report())],
    )
    text = " ".join(eng.executive_summary(report))
    assert "appears to come from" in text
    assert "example.com" in text


def test_summary_frames_awareness_constructively(tmp_path):
    report = eng.build_report(engagement=basic_engagement(),
                              hits_db=seed_hits(tmp_path))
    text = " ".join(eng.executive_summary(report))
    # Must not read as blaming staff.
    assert "not that individuals failed" in text
    assert "technical control" in text


def test_summary_reports_clean_result_plainly(tmp_path):
    report = eng.build_report(
        engagement=basic_engagement(),
        vuln_paths=[write(tmp_path, "v.json", vuln_report([
            vuln_finding("CVE-1", "LOW")]))],
    )
    assert "None are rated high or critical" in " ".join(
        eng.executive_summary(report))


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def full_report(tmp_path):
    return eng.build_report(
        engagement=eng.Engagement(
            engagement_id="ENG-2026-11", authorization_reference="RoE-77",
            client="Acme Corp", assessor="Offensive Unicorn Crew",
            title="Acme Security Assessment", period="2026-11-01 to 11-14",
            scope=["corp.example.com", "vendor-appliance 4.2.1"],
        ),
        vuln_paths=[write(tmp_path, "v.json", vuln_report([
            vuln_finding("CVE-2021-44228", "CRITICAL", kev=True),
        ] + [vuln_finding(f"CVE-T{i}", "MEDIUM") for i in range(6)]))],
        code_paths=[write(tmp_path, "c.json",
                          code_report([code_finding("CMD-OS-SYSTEM")]))],
        mail_paths=[write(tmp_path, "m.json", mail_report())],
        hits_db=seed_hits(tmp_path),
        vex_path=vex_file(tmp_path, [
            {"vulnerability": "CVE-T0", "status": "not_affected",
             "justification": "vulnerable_code_not_in_execute_path"},
        ]),
    )


def test_markdown_has_every_section(tmp_path):
    text = eng.render_markdown(full_report(tmp_path))
    for heading in ("# Acme Security Assessment", "## Executive summary",
                    "## Findings at a glance", "## Findings",
                    "## Awareness campaign results",
                    "## Email authentication posture",
                    "## Appendix A", "## Appendix B", "## Appendix C"):
        assert heading in text, heading
    assert "ENG-2026-11" in text and "RoE-77" in text
    assert "RO-001" in text


def test_markdown_flags_kev_findings(tmp_path):
    text = eng.render_markdown(full_report(tmp_path))
    assert "KNOWN EXPLOITED" in text


def test_html_is_self_contained(tmp_path):
    out = eng.render_html(full_report(tmp_path))
    assert out.startswith("<!doctype html>")
    assert out.rstrip().endswith("</html>")
    # No external resources at all.
    for marker in ("http://", "cdn.", "<script", "@import", "googleapis"):
        assert marker not in out.replace("https://example.invalid", ""), marker


def test_html_supports_dark_mode_and_print(tmp_path):
    out = eng.render_html(full_report(tmp_path))
    assert "prefers-color-scheme: dark" in out
    assert '[data-theme="dark"]' in out
    assert "@media print" in out


def test_html_escapes_content(tmp_path):
    """Snippets come from scanned code and must not inject markup."""
    report = eng.build_report(
        engagement=eng.Engagement(title="<script>alert(1)</script>"),
        code_paths=[write(tmp_path, "c.json", code_report([{
            "rule_id": "R", "severity": "HIGH", "cwe": "CWE-79",
            "title": "<img src=x onerror=alert(1)>",
            "file": "a.py", "line": 1,
            "snippet": '</div><script>alert("xss")</script>',
            "remediation": "Fix & escape <it>.",
        }]))],
    )
    out = eng.render_html(report)
    assert "<script>alert(1)</script>" not in out
    assert "<img src=x onerror" not in out
    assert "&lt;script&gt;" in out
    assert "Fix &amp; escape" in out


def test_json_render_round_trips(tmp_path):
    payload = json.loads(eng.render(full_report(tmp_path), "json"))
    assert payload["engagement"]["client"] == "Acme Corp"
    assert payload["finding_count"] == len(payload["findings"])
    assert payload["known_exploited"] >= 1
    assert payload["suppressed"]
    assert payload["not_assessed"]


def test_unknown_format_raises(tmp_path):
    with pytest.raises(eng.EngagementError, match="unknown report format"):
        eng.render(full_report(tmp_path), "pdf")


def test_limitations_appendix_carries_every_caveat(tmp_path):
    text = eng.render_markdown(full_report(tmp_path))
    section = text.split("## Appendix B")[1]
    assert "No exploitation was attempted" in section
    assert "pattern matching" in section
    assert "inconclusive" in section          # DKIM
    assert "detection coverage" in section    # awareness


def test_suppressed_appendix_shows_justifications(tmp_path):
    text = eng.render_markdown(full_report(tmp_path))
    section = text.split("## Appendix A")[1].split("## Appendix B")[0]
    assert "CVE-T0" in section
    assert "not_affected" in section
    assert "vulnerable_code_not_in_execute_path" in section


def test_text_summary(tmp_path):
    text = eng.text_summary(full_report(tmp_path))
    assert "findings" in text
    assert "KNOWN EXPLOITED" in text
    assert "suppressed by VEX triage" in text


def test_empty_report_still_renders(tmp_path):
    report = eng.build_report(engagement=basic_engagement())
    assert report.findings == []
    for fmt in ("md", "html", "json"):
        assert eng.render(report, fmt)


# ---------------------------------------------------------------------------
# AI/ML findings
# ---------------------------------------------------------------------------

def ai_finding(rule_id, severity="HIGH", *, file="a.py", line=1,
               owasp="LLM03", owasp_name="Supply Chain", cwe="CWE-502",
               atlas="AML.T0010", atlas_name="ML Supply Chain Compromise"):
    return {
        "rule_id": rule_id,
        "severity": severity,
        "title": f"Title for {rule_id}",
        "file": file,
        "line": line,
        "snippet": "the offending line",
        "remediation": "Do the safe thing instead.",
        "owasp": owasp,
        "owasp_name": owasp_name,
        "cwe": cwe,
        "atlas": atlas,
        "atlas_name": atlas_name,
        "severity_source": "coldlight-rule",
    }


def ai_report(findings, **over):
    payload = {
        "tool": "coldlight aisec",
        "files_scanned": 3,
        "notebooks_scanned": 0,
        "severity_counts": {},
        "owasp_llm_counts": {},
        "model_artifacts": [],
        "unsafe_artifact_count": 0,
        "findings": findings,
        "errors": [],
    }
    payload.update(over)
    return payload


def test_load_ai_findings_groups_by_rule(tmp_path):
    path = write(tmp_path, "ai.json", ai_report([
        ai_finding("AI-TORCH-LOAD-UNSAFE", file="a.py", line=3),
        ai_finding("AI-TORCH-LOAD-UNSAFE", file="b.py", line=7),
        ai_finding("AI-OUTPUT-TO-EVAL", severity="CRITICAL", file="c.py",
                   owasp="LLM05", owasp_name="Improper Output Handling",
                   cwe="CWE-95", atlas="", atlas_name=""),
    ]))
    findings, _notes = eng.load_ai_findings(path)
    assert len(findings) == 2            # two rules, not three occurrences

    grouped = next(f for f in findings
                   if "AI-TORCH-LOAD-UNSAFE" in f.identifiers)
    assert grouped.count == 2
    assert grouped.category == eng.CATEGORY_AI
    assert "2 occurrences" in grouped.title
    assert any("a.py:3" in e for e in grouped.evidence)
    assert any("b.py:7" in e for e in grouped.evidence)


def test_ai_findings_carry_owasp_and_atlas_references(tmp_path):
    """The reader must be able to look the weakness class up for themselves."""
    path = write(tmp_path, "ai.json",
                 ai_report([ai_finding("AI-PICKLE-MODEL-LOAD")]))
    identifiers = eng.load_ai_findings(path)[0][0].identifiers
    assert "AI-PICKLE-MODEL-LOAD" in identifiers
    assert "CWE-502" in identifiers
    assert "OWASP LLM03 Supply Chain" in identifiers
    assert "ATLAS AML.T0010 ML Supply Chain Compromise" in identifiers


def test_ai_finding_without_atlas_omits_it(tmp_path):
    """No ATLAS id is reported where we would be guessing at one."""
    path = write(tmp_path, "ai.json", ai_report(
        [ai_finding("AI-NO-TOKEN-LIMIT", atlas="", atlas_name="")]))
    identifiers = eng.load_ai_findings(path)[0][0].identifiers
    assert not any(i.startswith("ATLAS") for i in identifiers)


def test_ai_severity_provenance_is_our_rule_table(tmp_path):
    path = write(tmp_path, "ai.json",
                 ai_report([ai_finding("AI-TRUST-REMOTE-CODE")]))
    finding = eng.load_ai_findings(path)[0][0]
    assert finding.severity_source == "coldlight-rule"
    assert not eng.is_measured(finding.severity_source)


def test_ai_notes_state_that_no_model_was_tested(tmp_path):
    """A static pass must never read as a model that was actually tested."""
    path = write(tmp_path, "ai.json", ai_report([]))
    _findings, notes = eng.load_ai_findings(path)
    blob = " ".join(notes)
    assert "static only" in blob
    assert "NOT established" in blob
    assert "prompt injection" in blob
    assert "without being deserialised" in blob


def test_ai_notes_report_unsafe_artifacts(tmp_path):
    path = write(tmp_path, "ai.json", ai_report(
        [],
        model_artifacts=[{"path": "m.pkl", "extension": ".pkl",
                          "format_note": "pickle", "bytes": 10,
                          "safe_format": False, "pickle_detected": True}],
        unsafe_artifact_count=1,
    ))
    _findings, notes = eng.load_ai_findings(path)
    blob = " ".join(notes)
    assert "1 model artifact(s)" in blob
    assert "code-executing" in blob


def test_ai_findings_reach_the_assembled_report(tmp_path):
    path = write(tmp_path, "ai.json", ai_report([
        ai_finding("AI-TRUST-REMOTE-CODE", cwe="CWE-494"),
    ]))
    report = eng.build_report(engagement=basic_engagement(), ai_paths=[path])
    assert [f.category for f in report.findings] == [eng.CATEGORY_AI]
    assert any("ai.json" in s for s in report.sources)
    assert any("NOT established" in n for n in report.not_assessed)


def test_ai_scan_errors_surface_as_limitations(tmp_path):
    path = write(tmp_path, "ai.json",
                 ai_report([], errors=["weights.bin: permission denied"]))
    _findings, notes = eng.load_ai_findings(path)
    assert any("permission denied" in n for n in notes)


# ---------------------------------------------------------------------------
# Live probe findings
# ---------------------------------------------------------------------------

def probe_finding(probe_id="CANARY-INDIRECT-DOCUMENT", severity="HIGH",
                  channel="retrieved document", owasp="LLM01"):
    return {
        "probe_id": probe_id,
        "severity": severity,
        "title": f"Title for {probe_id}",
        "channel": channel,
        "owasp": owasp,
        "detail": "the reply contained the canary, so content in this "
                  "channel was treated as an instruction",
        "remediation": "Keep retrieved content in an untrusted role.",
        "evidence": "Certainly. COLDLIGHT-CANARY-AAAAAAAA",
        "severity_source": "coldlight-judgement",
    }


def probe_report(findings, *, established=True, **over):
    payload = {
        "tool": "coldlight canary",
        "target": "http://localhost:8765/api/chat",
        "authorization_reference": "TICKET-4417",
        "dry_run": False,
        "verdict_established": established,
        "counts": {"probes": 6, "susceptible": len(findings),
                   "resisted": 6 - len(findings), "inconclusive": 0},
        "results": [],
        "findings": findings,
        "scope_decisions": [],
        "limitations": ["Benign canary probing only: no jailbreak corpus."],
    }
    payload.update(over)
    return payload


def test_probe_findings_are_their_own_category(tmp_path):
    """Observed behaviour and static review must not be conflated."""
    path = write(tmp_path, "p.json", probe_report([probe_finding()]))
    findings, _notes = eng.load_probe_findings(path)
    assert len(findings) == 1
    assert findings[0].category == eng.CATEGORY_AI_RUNTIME
    assert eng.CATEGORY_AI_RUNTIME != eng.CATEGORY_AI


def test_probe_finding_says_it_was_observed_and_names_the_channel(tmp_path):
    path = write(tmp_path, "p.json", probe_report([probe_finding()]))
    finding = eng.load_probe_findings(path)[0][0]
    assert finding.description.startswith("Observed against the live endpoint")
    assert "retrieved document channel" in finding.description
    assert "OWASP LLM01" in finding.identifiers


def test_probe_description_reads_as_sentences(tmp_path):
    """It is a client deliverable, not terminal output."""
    path = write(tmp_path, "p.json", probe_report([probe_finding()]))
    description = eng.load_probe_findings(path)[0][0].description
    assert ". The reply contained" in description


def test_probe_evidence_is_carried(tmp_path):
    path = write(tmp_path, "p.json", probe_report([probe_finding()]))
    finding = eng.load_probe_findings(path)[0][0]
    assert finding.evidence == ["Certainly. COLDLIGHT-CANARY-AAAAAAAA"]


def test_probe_severity_provenance_is_our_judgement(tmp_path):
    """The outcome is observed; how much it matters is our assessment."""
    path = write(tmp_path, "p.json", probe_report([probe_finding()]))
    finding = eng.load_probe_findings(path)[0][0]
    assert finding.severity_source == "coldlight-judgement"
    assert not eng.is_measured(finding.severity_source)


def test_probe_notes_record_the_target_and_authorization(tmp_path):
    path = write(tmp_path, "p.json", probe_report([probe_finding()]))
    notes = " ".join(eng.load_probe_findings(path)[1])
    assert "localhost:8765" in notes
    assert "TICKET-4417" in notes


def test_no_susceptibility_is_not_reported_as_robustness(tmp_path):
    path = write(tmp_path, "p.json", probe_report([]))
    findings, notes = eng.load_probe_findings(path)
    assert findings == []
    blob = " ".join(notes)
    assert "not evidence that the model is robust" in blob


def test_a_probe_run_with_no_verdict_is_stated_loudly(tmp_path):
    """All-inconclusive must never read as a model that held the line."""
    path = write(tmp_path, "p.json", probe_report(
        [], established=False,
        counts={"probes": 6, "susceptible": 0, "resisted": 0,
                "inconclusive": 6}))
    _findings, notes = eng.load_probe_findings(path)
    blob = " ".join(notes)
    assert "NO verdict" in blob
    assert "UNKNOWN, not acceptable" in blob


def test_partial_inconclusive_count_is_reported(tmp_path):
    path = write(tmp_path, "p.json", probe_report(
        [probe_finding()],
        counts={"probes": 6, "susceptible": 1, "resisted": 3,
                "inconclusive": 2}))
    notes = " ".join(eng.load_probe_findings(path)[1])
    assert "2 of 6 live probe(s) were inconclusive" in notes


def test_probe_limitations_reach_the_report(tmp_path):
    path = write(tmp_path, "p.json", probe_report([probe_finding()]))
    report = eng.build_report(engagement=basic_engagement(),
                              probe_paths=[path])
    assert [f.category for f in report.findings] == [eng.CATEGORY_AI_RUNTIME]
    assert any("jailbreak" in n for n in report.not_assessed)
    assert any("p.json" in s for s in report.sources)


def test_static_and_runtime_findings_coexist(tmp_path):
    ai = write(tmp_path, "ai.json", ai_report([ai_finding("AI-TORCH-LOAD")]))
    probe = write(tmp_path, "p.json", probe_report([probe_finding()]))
    report = eng.build_report(engagement=basic_engagement(),
                              ai_paths=[ai], probe_paths=[probe])
    categories = {f.category for f in report.findings}
    assert categories == {eng.CATEGORY_AI, eng.CATEGORY_AI_RUNTIME}


# ---------------------------------------------------------------------------
# Secrets in version history
# ---------------------------------------------------------------------------

def history_finding(rule_id="SECRET-AWS-AKID", severity="CRITICAL",
                    recoverable=True, commit_count=1, file="config.py"):
    return {
        "rule_id": rule_id,
        "severity": severity,
        "title": "AWS access key id committed to source",
        "cwe": "CWE-798",
        "file": file,
        "snippet": 'AWS_KEY = "***REDACTED***"',
        "fingerprint": "a" * 64,
        "first_commit": "44aa4b99f802abc",
        "first_commit_at": "2026-11-18T13:00:25+01:00",
        "first_author": "Fixture Author <fixture@example.invalid>",
        "commit_count": commit_count,
        "present_in_head": not recoverable,
        "recoverable_only": recoverable,
        "severity_source": "coldlight-rule",
    }


def history_report(findings, *, assessed=True, recoverable=1, commits=8,
                   **over):
    payload = {
        "tool": "coldlight history",
        "repository": {"path": "/repo", "shallow": not assessed, "error": ""},
        "assessed": assessed,
        "commits_scanned": commits,
        "files_seen": 3,
        "truncated": "",
        "counts": {"findings": len(findings),
                   "recoverable_only": recoverable,
                   "still_in_head": len(findings) - recoverable},
        "findings": findings,
        "errors": [],
        "remediation": "Rotate the credential at the provider.",
        "limitations": ["History reachable from refs only."],
    }
    payload.update(over)
    return payload


def test_history_findings_are_their_own_category(tmp_path):
    path = write(tmp_path, "h.json", history_report([history_finding()]))
    findings, _notes = eng.load_history_findings(path)
    assert len(findings) == 1
    assert findings[0].category == eng.CATEGORY_HISTORY


def test_a_deleted_secret_says_deleting_the_line_did_not_help(tmp_path):
    """The sentence a reader needs: the credential is still out there."""
    path = write(tmp_path, "h.json", history_report([history_finding()]))
    finding = eng.load_history_findings(path)[0][0]
    assert "in git history" in finding.title
    assert "still recoverable from history" in finding.description
    assert "Deleting the line did not remove it" in finding.description
    assert "every clone" in finding.description


def test_a_secret_still_in_head_is_titled_differently(tmp_path):
    path = write(tmp_path, "h.json",
                 history_report([history_finding(recoverable=False)],
                                recoverable=0))
    finding = eng.load_history_findings(path)[0][0]
    assert "still present" in finding.title
    assert "still present in the working tree" in finding.description
    assert "Deleting the line" not in finding.description


def test_history_finding_names_the_commit_and_author(tmp_path):
    path = write(tmp_path, "h.json", history_report([history_finding()]))
    finding = eng.load_history_findings(path)[0][0]
    assert "44aa4b99f" in finding.description
    assert "Fixture Author" in finding.description
    assert "commit 44aa4b99f" in finding.identifiers
    assert "CWE-798" in finding.identifiers


def test_repeated_commits_are_mentioned(tmp_path):
    path = write(tmp_path, "h.json",
                 history_report([history_finding(commit_count=14)]))
    finding = eng.load_history_findings(path)[0][0]
    assert "appears in 14 commits" in finding.description


def test_history_remediation_is_rotation(tmp_path):
    path = write(tmp_path, "h.json", history_report([history_finding()]))
    finding = eng.load_history_findings(path)[0][0]
    assert "Rotate the credential" in finding.remediation


def test_history_evidence_carries_the_redacted_line(tmp_path):
    path = write(tmp_path, "h.json", history_report([history_finding()]))
    finding = eng.load_history_findings(path)[0][0]
    assert finding.evidence
    assert "config.py" in finding.evidence[0]
    assert "REDACTED" in finding.evidence[0]


def test_history_notes_report_the_recoverable_count(tmp_path):
    path = write(tmp_path, "h.json",
                 history_report([history_finding()], recoverable=1))
    notes = " ".join(eng.load_history_findings(path)[1])
    assert "1 credential(s) are no longer in the working tree" in notes
    assert "Rotation is the only effective remediation" in notes


def test_an_unassessed_history_is_stated_loudly(tmp_path):
    """A shallow clone must not let the finding count read as a clean one."""
    path = write(tmp_path, "h.json", history_report(
        [], assessed=False, recoverable=0,
        repository={"path": "/repo", "shallow": True,
                    "error": "this is a SHALLOW clone."}))
    _findings, notes = eng.load_history_findings(path)
    blob = " ".join(notes)
    assert "NOT assessed" in blob
    assert "SHALLOW" in blob
    assert "UNKNOWN rather than clean" in blob


def test_history_findings_reach_the_report(tmp_path):
    path = write(tmp_path, "h.json", history_report([history_finding()]))
    report = eng.build_report(engagement=basic_engagement(),
                              history_paths=[path])
    assert [f.category for f in report.findings] == [eng.CATEGORY_HISTORY]
    assert any("h.json" in s for s in report.sources)
    assert any("reachable from refs only" in n for n in report.not_assessed)


def test_history_severity_provenance_is_the_rule_table(tmp_path):
    path = write(tmp_path, "h.json", history_report([history_finding()]))
    finding = eng.load_history_findings(path)[0][0]
    assert finding.severity_source == "coldlight-rule"
