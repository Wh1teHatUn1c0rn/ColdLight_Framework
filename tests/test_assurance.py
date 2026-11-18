"""Tests for coldlight_assurance (the coverage ledger).

The ledger's value is entirely in its honesty, so most of these assert that it
refuses to flatter: classes it cannot assess are listed, emitted Sigma rules
do not count as detection coverage, and no figure can be read as overall
coverage when it isn't.
"""

import json

import pytest

import coldlight_assurance as asr


def artifacts(tmp_path, **files):
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    for name, payload in files.items():
        path = out / f"{name}.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
    return out


def entry_for(ledger, key):
    return next(e for e in ledger.entries if e.key == key)


def deps_payload(findings=3, checked=10):
    return {"findings": [{"identifier": f"CVE-{i}"} for i in range(findings)],
            "packages_checked": checked}


def code_payload(findings=2, scanned=8):
    return {"findings": [{"rule_id": f"R{i}"} for i in range(findings)],
            "files_scanned": scanned}


def mail_payload(domain="example.com", findings=3, dkim_found=True):
    return {"domain": domain,
            "findings": [{"check": "DMARC"} for _ in range(findings)],
            "dkim": {"found": dkim_found}}


def sbom_payload(findings=5, checked=20, not_checked=0, reasons=None):
    return {"findings": [{"identifier": f"CVE-{i}"} for i in range(findings)],
            "packages_checked": checked,
            "not_checked": not_checked,
            "not_checked_reasons": reasons or {}}


# ---------------------------------------------------------------------------
# The class catalogue
# ---------------------------------------------------------------------------

def test_catalogue_covers_both_tiers():
    tiers = {c.tier for c in asr.CLASSES}
    assert tiers == {asr.TIER_COVERED, asr.TIER_EXTERNAL}


def test_classes_the_tool_cannot_assess_are_listed():
    """Showing only our own classes would let 'all assessed' read as full
    coverage when nobody tested the network or the web app."""
    external = {c.key for c in asr.CLASSES if c.tier == asr.TIER_EXTERNAL}
    assert {"network", "web_app", "cloud_config", "identity"} <= external


def test_class_keys_are_unique():
    keys = [c.key for c in asr.CLASSES]
    assert len(keys) == len(set(keys))


# ---------------------------------------------------------------------------
# Building the ledger
# ---------------------------------------------------------------------------

def test_missing_directory_raises(tmp_path):
    with pytest.raises(asr.AssuranceError, match="no such directory"):
        asr.build_ledger(tmp_path / "nope")


def test_empty_directory_assesses_nothing(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    ledger = asr.build_ledger(out)
    assert ledger.examined_classes == 0
    assert all(not e.examined for e in ledger.entries)


def test_dependencies_are_recorded(tmp_path):
    ledger = asr.build_ledger(artifacts(tmp_path, deps=deps_payload(3, 10)))
    entry = entry_for(ledger, "dependencies")
    assert entry.status == asr.STATUS_ASSESSED
    assert entry.findings == 3
    assert entry.ratio == "10/10"


def test_several_artifacts_of_one_class_are_summed(tmp_path):
    out = artifacts(tmp_path)
    (out / "deps-1.json").write_text(json.dumps(deps_payload(2, 5)),
                                     encoding="utf-8")
    (out / "deps-2.json").write_text(json.dumps(deps_payload(3, 7)),
                                     encoding="utf-8")
    entry = entry_for(asr.build_ledger(out), "dependencies")
    assert entry.findings == 5
    assert entry.ratio == "12/12"


def test_code_is_recorded(tmp_path):
    entry = entry_for(asr.build_ledger(artifacts(tmp_path, code=code_payload())),
                      "source_code")
    assert entry.status == asr.STATUS_ASSESSED
    assert entry.findings == 2
    assert entry.ratio == "8/8"


def test_absent_class_says_why(tmp_path):
    ledger = asr.build_ledger(artifacts(tmp_path, code=code_payload()))
    entry = entry_for(ledger, "dependencies")
    assert entry.status == asr.STATUS_NOT_ASSESSED
    assert "no dependency scan was run" in entry.reason


# ---------------------------------------------------------------------------
# PARTIAL: checked, but not completely
# ---------------------------------------------------------------------------

def test_sbom_with_unmappable_components_is_partial(tmp_path):
    out = artifacts(tmp_path, sbom=sbom_payload(
        findings=5, checked=20, not_checked=45,
        reasons={"unsupported purl type: 'docker'": 45}))
    entry = entry_for(asr.build_ledger(out), "sbom")

    assert entry.status == asr.STATUS_PARTIAL
    assert entry.ratio == "20/65"          # the gap is visible in the ratio
    assert "45 component(s)" in entry.reason
    assert "docker" in entry.reason


def test_sbom_with_everything_mapped_is_assessed(tmp_path):
    out = artifacts(tmp_path, sbom=sbom_payload(checked=20, not_checked=0))
    assert entry_for(asr.build_ledger(out), "sbom").status == asr.STATUS_ASSESSED


def test_inconclusive_dkim_makes_email_partial(tmp_path):
    out = artifacts(tmp_path, mail=mail_payload(dkim_found=False))
    entry = entry_for(asr.build_ledger(out), "email_auth")
    assert entry.status == asr.STATUS_PARTIAL
    assert "DKIM inconclusive" in entry.reason
    assert "example.com" in entry.reason


def test_conclusive_dkim_is_fully_assessed(tmp_path):
    out = artifacts(tmp_path, mail=mail_payload(dkim_found=True))
    assert entry_for(asr.build_ledger(out),
                     "email_auth").status == asr.STATUS_ASSESSED


# ---------------------------------------------------------------------------
# The honesty rules
# ---------------------------------------------------------------------------

def test_emitting_sigma_rules_is_not_detection_coverage(tmp_path):
    """Shipping a rule says nothing about whether anyone would notice. A tool
    counting its own deliverables as coverage would be grading its own
    homework."""
    out = artifacts(tmp_path, code=code_payload())
    (out / "sigma").mkdir()
    (out / "sigma" / "rule.yml").write_text("title: x", encoding="utf-8")

    entry = entry_for(asr.build_ledger(out), "detection")
    assert entry.status == asr.STATUS_NOT_ASSESSED
    assert "no detection outcomes were recorded" in entry.reason
    assert "detect validate" in entry.reason


def test_detection_without_rules_says_nothing_was_attempted(tmp_path):
    entry = entry_for(asr.build_ledger(artifacts(tmp_path)), "detection")
    assert entry.status == asr.STATUS_NOT_ASSESSED
    assert "no detection validation" in entry.reason


def test_secrets_history_is_not_assessed_without_a_history_scan(tmp_path):
    """A code scan does not cover history, and the ledger says which one is
    missing rather than implying the area was looked at."""
    entry = entry_for(asr.build_ledger(artifacts(tmp_path, code=code_payload())),
                      "secrets_history")
    assert entry.status == asr.STATUS_NOT_ASSESSED
    assert "no history scan was run" in entry.reason
    assert "later deleted would not have been seen" in entry.reason


def test_external_classes_are_always_unassessed(tmp_path):
    ledger = asr.build_ledger(artifacts(tmp_path, deps=deps_payload(),
                                        code=code_payload(),
                                        mail=mail_payload()))
    assert ledger.external
    for entry in ledger.external:
        assert entry.status == asr.STATUS_NOT_ASSESSED
        assert "separate assessment" in entry.reason


def test_a_failed_stage_shows_as_failed_not_absent(tmp_path):
    out = artifacts(tmp_path)
    manifest = {"stages": [{"name": "email posture", "status": "failed",
                            "error": "MailAuditError: DNS unreachable"}]}
    entry = entry_for(asr.build_ledger(out, manifest=manifest), "email_auth")
    assert entry.status == asr.STATUS_FAILED
    assert "DNS unreachable" in entry.reason


def test_manifest_is_read_from_disk_when_not_supplied(tmp_path):
    out = artifacts(tmp_path)
    (out / "run.json").write_text(json.dumps({
        "stages": [{"name": "source code", "status": "failed",
                    "error": "boom"}]}), encoding="utf-8")
    assert entry_for(asr.build_ledger(out), "source_code").status == (
        asr.STATUS_FAILED)


# ---------------------------------------------------------------------------
# Aggregates
# ---------------------------------------------------------------------------

def test_examined_count_ignores_unassessed_classes(tmp_path):
    ledger = asr.build_ledger(artifacts(tmp_path, deps=deps_payload(),
                                        code=code_payload()))
    assert ledger.examined_classes == 2
    assert len(ledger.covered) > 2
    assert len(ledger.unexamined) > 0


def test_findings_are_totalled(tmp_path):
    ledger = asr.build_ledger(artifacts(tmp_path, deps=deps_payload(3),
                                        code=code_payload(2),
                                        mail=mail_payload(findings=4)))
    assert ledger.total_findings == 9


def test_unit_coverage_only_counts_classes_with_a_denominator(tmp_path):
    ledger = asr.build_ledger(artifacts(tmp_path, deps=deps_payload(checked=10),
                                        code=code_payload(scanned=8)))
    assert ledger.unit_coverage() == (18, 18)


def test_json_view_is_serialisable_and_complete(tmp_path):
    ledger = asr.build_ledger(artifacts(tmp_path, deps=deps_payload(),
                                        code=code_payload()))
    payload = ledger.to_dict()
    assert payload["classes_examined"] == 2
    assert payload["classes_in_tool_scope"] >= 7
    assert payload["unexamined"]
    assert payload["entries"]
    json.dumps(payload)


# ---------------------------------------------------------------------------
# Rendering -- must not read as reassurance
# ---------------------------------------------------------------------------

def test_text_ledger_states_both_denominators(tmp_path):
    ledger = asr.build_ledger(artifacts(tmp_path, deps=deps_payload(),
                                        code=code_payload()))
    text = asr.text_ledger(ledger)
    assert "what nobody looked at" in text
    assert "class(es) in this tool's scope" in text
    assert "outside it" in text
    assert "NOT examined" in text


def test_no_bare_coverage_percentage_is_printed(tmp_path):
    """A '100%' beside a 2-of-7 assessment would be exactly the false
    reassurance this ledger exists to prevent."""
    ledger = asr.build_ledger(artifacts(tmp_path, deps=deps_payload(),
                                        code=code_payload()))
    assert ledger.examined_classes < len(ledger.covered)

    for text in (asr.text_ledger(ledger), asr.markdown_ledger(ledger)):
        assert "100%" not in text
        assert "%)" not in text


def test_unit_figure_is_explicitly_scoped(tmp_path):
    ledger = asr.build_ledger(artifacts(tmp_path, deps=deps_payload()))
    assert "Within those examined classes" in asr.text_ledger(ledger)
    markdown = asr.markdown_ledger(ledger)
    assert "not** an overall coverage figure" in markdown


def test_findings_count_is_qualified(tmp_path):
    ledger = asr.build_ledger(artifacts(tmp_path, deps=deps_payload(3)))
    text = asr.text_ledger(ledger)
    assert "reflects ONLY the classes marked ASSESSED" in text


def test_labels_are_not_truncated_mid_word(tmp_path):
    ledger = asr.build_ledger(artifacts(tmp_path))
    text = asr.text_ledger(ledger)
    for entry in ledger.covered:
        assert entry.label in text, f"{entry.label!r} was cut off"


def test_markdown_lists_external_classes(tmp_path):
    markdown = asr.markdown_ledger(asr.build_ledger(artifacts(tmp_path)))
    assert "Outside this assessment entirely" in markdown
    assert "Network and host infrastructure" in markdown


def test_markdown_surfaces_partial_reasons(tmp_path):
    out = artifacts(tmp_path, sbom=sbom_payload(not_checked=12,
                                                reasons={"no purl": 12}))
    markdown = asr.markdown_ledger(asr.build_ledger(out))
    assert "Partial coverage" in markdown
    assert "no purl" in markdown


# ---------------------------------------------------------------------------
# AI model runtime behaviour
# ---------------------------------------------------------------------------

def probe_payload(susceptible=2, resisted=4, inconclusive=0,
                  established=True):
    return {
        "tool": "coldlight canary",
        "target": "http://localhost:8765/api/chat",
        "verdict_established": established,
        "counts": {"probes": susceptible + resisted + inconclusive,
                   "susceptible": susceptible, "resisted": resisted,
                   "inconclusive": inconclusive},
        "findings": [{"probe_id": f"P{i}"} for i in range(susceptible)],
    }


def test_runtime_behaviour_is_not_assessed_without_a_probe(tmp_path):
    """A static scan must not let a live model read as checked."""
    ledger = asr.build_ledger(artifacts(tmp_path, ai=code_payload()))
    entry = entry_for(ledger, "ai_runtime")
    assert entry.status == asr.STATUS_NOT_ASSESSED
    assert "no live probe" in entry.reason
    assert "unknown rather than acceptable" in entry.reason


def test_runtime_behaviour_is_assessed_after_a_probe(tmp_path):
    ledger = asr.build_ledger(artifacts(tmp_path, probe=probe_payload()))
    entry = entry_for(ledger, "ai_runtime")
    assert entry.status == asr.STATUS_ASSESSED
    assert entry.findings == 2
    assert entry.checked == 6
    assert entry.total == 6


def test_all_inconclusive_probes_are_a_failure_not_a_pass(tmp_path):
    """Probes that reached no verdict establish nothing."""
    ledger = asr.build_ledger(artifacts(tmp_path, probe=probe_payload(
        susceptible=0, resisted=0, inconclusive=6, established=False)))
    entry = entry_for(ledger, "ai_runtime")
    assert entry.status == asr.STATUS_FAILED
    assert entry.findings == 0
    assert entry.checked == 0
    assert "none reached a verdict" in entry.reason


def test_partially_inconclusive_probe_run_says_so(tmp_path):
    ledger = asr.build_ledger(artifacts(tmp_path, probe=probe_payload(
        susceptible=1, resisted=2, inconclusive=3)))
    entry = entry_for(ledger, "ai_runtime")
    assert entry.status == asr.STATUS_ASSESSED
    assert entry.checked == 3
    assert entry.total == 6
    assert "3 probe(s) reached no verdict" in entry.reason


def test_runtime_class_refuses_to_claim_robustness(tmp_path):
    ledger = asr.build_ledger(artifacts(tmp_path, probe=probe_payload(
        susceptible=0, resisted=6)))
    entry = entry_for(ledger, "ai_runtime")
    assert "never disproved" in entry.note


def test_static_ai_class_points_at_the_runtime_class(tmp_path):
    """The static note must stay true now that probing exists."""
    ledger = asr.build_ledger(artifacts(tmp_path, ai=code_payload()))
    note = entry_for(ledger, "ai_ml").note
    assert "runtime behaviour" in note
    assert "NOT established" not in note


def test_failed_probe_stage_is_reported_as_failed(tmp_path):
    ledger = asr.build_ledger(
        artifacts(tmp_path),
        manifest={"stages": [{"name": "AI runtime behaviour",
                              "status": "failed",
                              "error": "endpoint refused the connection"}]})
    entry = entry_for(ledger, "ai_runtime")
    assert entry.status == asr.STATUS_FAILED
    assert "refused the connection" in entry.reason


# ---------------------------------------------------------------------------
# Ledger structure
# ---------------------------------------------------------------------------

def test_every_class_appears_exactly_once(tmp_path):
    """Regression: a new history branch was added alongside the old one, so
    "Secrets in version history" was listed twice -- once ASSESSED and once
    NOT ASSESSED. entry_for() returns the first match, so every per-class
    test still passed while the printed ledger contradicted itself.
    """
    import collections
    ledger = asr.build_ledger(artifacts(tmp_path, code=code_payload(),
                                        history=history_payload()))
    counts = collections.Counter(e.key for e in ledger.entries)
    assert [key for key, n in counts.items() if n > 1] == []
    assert len(ledger.entries) == len(asr.CLASSES)


def test_every_declared_class_reaches_the_ledger(tmp_path):
    ledger = asr.build_ledger(artifacts(tmp_path))
    assert {e.key for e in ledger.entries} == {c.key for c in asr.CLASSES}


# ---------------------------------------------------------------------------
# Secrets in version history
# ---------------------------------------------------------------------------

def history_payload(findings=3, recoverable=2, commits=8, assessed=True,
                    error=""):
    return {
        "tool": "coldlight history",
        "assessed": assessed,
        "commits_scanned": commits,
        "repository": {"shallow": not assessed, "error": error},
        "counts": {"findings": findings, "recoverable_only": recoverable,
                   "still_in_head": findings - recoverable},
        "findings": [{"rule_id": f"SECRET-{i}"} for i in range(findings)],
    }


def test_history_is_assessed_when_a_scan_ran(tmp_path):
    ledger = asr.build_ledger(artifacts(tmp_path, history=history_payload()))
    entry = entry_for(ledger, "secrets_history")
    assert entry.status == asr.STATUS_ASSESSED
    assert entry.findings == 3
    assert entry.checked == 8
    assert "2 secret(s) no longer in HEAD" in entry.reason


def test_a_shallow_history_scan_is_a_failure_not_a_pass(tmp_path):
    """The whole point: a truncated history finds nothing and looks clean."""
    ledger = asr.build_ledger(artifacts(tmp_path, history=history_payload(
        findings=0, recoverable=0, commits=1, assessed=False,
        error="this is a SHALLOW clone")))
    entry = entry_for(ledger, "secrets_history")
    assert entry.status == asr.STATUS_FAILED
    assert "SHALLOW" in entry.reason


def test_history_note_states_what_is_out_of_reach(tmp_path):
    ledger = asr.build_ledger(artifacts(tmp_path, history=history_payload()))
    note = entry_for(ledger, "secrets_history").note
    assert "reflog" in note
    assert "rotated" in note
