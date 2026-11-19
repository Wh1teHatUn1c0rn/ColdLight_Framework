"""Tests for coldlight_assess (the one-command orchestrator).

The property that matters most: a stage that FAILED must never read as a stage
that found nothing. Several tests below inject failures and assert that the
report says so and the exit code reflects it.
"""

import json

import pytest

import coldlight_assess as ra


# ---------------------------------------------------------------------------
# Profile loading
# ---------------------------------------------------------------------------

FULL_PROFILE = '''
[assessment]
client = "Acme Corp"
title = "Acme Security Assessment"
period = "2026-11-01 to 2026-11-14"
engagement_id = "ENG-1"
authorization_reference = "RoE-7"
assessor = "Offensive Unicorn Crew"
scope = ["portal 1.0", "corp.example.com"]

[stages.deps]
paths = ["."]

[stages.sbom]
files = ["bom.json"]

[stages.code]
paths = ["src"]
exclude = ["tests/*"]

[stages.mail]
domains = ["corp.example.com"]
fetch_policy = false

[stages.awareness]
db = "hits.db"

[stages.detect]
enabled = true

[vex]
triage = "triage.json"

[gates]
fail_on = "high"
baseline = ".coldlight/baseline.json"

[output]
dir = "out"
formats = ["html", "md"]
'''


def write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_load_full_profile(tmp_path):
    profile = ra.load_profile(write(tmp_path, "a.toml", FULL_PROFILE))

    assert profile.client == "Acme Corp"
    assert profile.engagement_id == "ENG-1"
    assert profile.scope == ["portal 1.0", "corp.example.com"]
    assert profile.deps_paths == ["."]
    assert profile.sbom_files == ["bom.json"]
    assert profile.code_paths == ["src"]
    assert profile.code_exclude == ["tests/*"]
    assert profile.mail_domains == ["corp.example.com"]
    assert profile.mail_fetch_policy is False
    assert profile.awareness_db == "hits.db"
    assert profile.detect_enabled is True
    assert profile.vex_triage == "triage.json"
    assert profile.fail_on == "high"
    assert profile.baseline == ".coldlight/baseline.json"
    assert profile.out_dir == "out"
    assert profile.formats == ["html", "md"]


def test_minimal_profile_gets_defaults(tmp_path):
    profile = ra.load_profile(
        write(tmp_path, "a.toml", '[stages.code]\npaths = ["."]\n'))
    assert profile.code_paths == ["."]
    assert profile.formats == ["html"]
    assert profile.out_dir == "assessment"
    assert profile.mail_fetch_policy is True
    assert profile.configured_stages == ["source code"]


def test_scalars_are_accepted_where_lists_are_expected(tmp_path):
    """A single string should work as well as a one-item list."""
    profile = ra.load_profile(
        write(tmp_path, "a.toml", '[stages.code]\npaths = "."\n'))
    assert profile.code_paths == ["."]


def test_missing_profile_raises():
    with pytest.raises(ra.AssessError, match="no such profile"):
        ra.load_profile("nope.toml")


def test_bad_toml_raises(tmp_path):
    with pytest.raises(ra.AssessError, match="not valid TOML"):
        ra.load_profile(write(tmp_path, "a.toml", "this is [not toml"))


def test_configured_stages_lists_only_what_is_set(tmp_path):
    profile = ra.load_profile(write(tmp_path, "a.toml", FULL_PROFILE))
    assert profile.configured_stages == [
        "dependencies", "sbom", "source code", "email posture",
        "awareness", "detection artifacts",
    ]


# ---------------------------------------------------------------------------
# CLI overrides
# ---------------------------------------------------------------------------

class Args:
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


def test_cli_overrides_the_profile(tmp_path):
    profile = ra.load_profile(write(tmp_path, "a.toml", FULL_PROFILE))
    merged = ra.merge_args(profile, Args(code=["other"], client="Other Co",
                                         fail_on="critical"))
    assert merged.code_paths == ["other"]
    assert merged.client == "Other Co"
    assert merged.fail_on == "critical"
    assert merged.deps_paths == ["."]      # untouched


def test_absent_cli_flags_do_not_clobber(tmp_path):
    profile = ra.load_profile(write(tmp_path, "a.toml", FULL_PROFILE))
    merged = ra.merge_args(profile, Args(code=None, client=None))
    assert merged.code_paths == ["src"]
    assert merged.client == "Acme Corp"


def test_flags_work_with_no_profile_at_all():
    merged = ra.merge_args(ra.Profile(), Args(code=["."], domain=["x.com"]))
    assert merged.configured_stages == ["source code", "email posture"]


def test_detect_and_no_fetch_flags():
    merged = ra.merge_args(ra.Profile(), Args(detect=True, no_fetch=True,
                                              code=["."]))
    assert merged.detect_enabled is True
    assert merged.mail_fetch_policy is False


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def test_no_stages_is_an_error():
    errors, _ = ra.validate_profile(ra.Profile())
    assert any("no stages configured" in e for e in errors)


def test_unknown_format_is_an_error():
    errors, _ = ra.validate_profile(
        ra.Profile(code_paths=["."], formats=["pdf"]))
    assert any("unknown output format" in e for e in errors)


def test_bad_fail_on_is_an_error():
    errors, _ = ra.validate_profile(
        ra.Profile(code_paths=["."], fail_on="extremely-bad"))
    assert any("is not a severity" in e for e in errors)


def test_placeholders_and_missing_authorization_warn():
    _errors, warnings = ra.validate_profile(
        ra.Profile(code_paths=["."], engagement_id="CHANGE-ME-X"))
    assert any("CHANGE-ME" in w for w in warnings)
    assert any("authorization_reference" in w for w in warnings)


def test_a_good_profile_validates_clean():
    errors, warnings = ra.validate_profile(ra.Profile(
        code_paths=["."], client="Acme", engagement_id="ENG-1",
        authorization_reference="RoE-7", formats=["html"], fail_on="high"))
    assert errors == []
    assert warnings == []


# ---------------------------------------------------------------------------
# Running: the happy path
# ---------------------------------------------------------------------------

def sample_tree(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text("import os\nos.system('ping ' + t)\n",
                                encoding="utf-8")
    return src


def test_code_only_run(tmp_path):
    src = sample_tree(tmp_path)
    profile = ra.Profile(code_paths=[str(src)], client="Acme",
                         out_dir=str(tmp_path / "out"), formats=["json"])
    result = ra.run(profile)

    assert [s.name for s in result.stages] == ["source code", "report"]
    assert all(s.ok for s in result.stages)
    assert result.exit_code == 0
    assert result.failed == []

    code_json = tmp_path / "out" / "code.json"
    assert code_json.is_file()
    assert json.loads(code_json.read_text(encoding="utf-8"))["findings"]
    assert (tmp_path / "out" / "report.json").is_file()


def test_artifacts_are_written_for_traceability(tmp_path):
    src = sample_tree(tmp_path)
    profile = ra.Profile(code_paths=[str(src)], out_dir=str(tmp_path / "out"),
                         formats=["md"], client="Acme")
    result = ra.run(profile)
    stage = next(s for s in result.stages if s.name == "source code")
    assert stage.artifacts and stage.artifacts[0].endswith("code.json")


def test_multiple_targets_get_numbered_artifacts(tmp_path):
    first = sample_tree(tmp_path)
    second = tmp_path / "src2"
    second.mkdir()
    (second / "b.py").write_text("eval(x)\n", encoding="utf-8")

    profile = ra.Profile(code_paths=[str(first), str(second)],
                         out_dir=str(tmp_path / "out"), formats=["json"],
                         client="Acme")
    ra.run(profile)
    assert (tmp_path / "out" / "code-1.json").is_file()
    assert (tmp_path / "out" / "code-2.json").is_file()


def test_detect_stage_emits_deliverables(tmp_path):
    profile = ra.Profile(code_paths=[str(sample_tree(tmp_path))],
                         detect_enabled=True, client="Acme",
                         out_dir=str(tmp_path / "out"), formats=["json"])
    ra.run(profile)
    out = tmp_path / "out"
    assert (out / "sigma").is_dir()
    assert list((out / "sigma").glob("*.yml"))
    assert (out / "attack_layer.json").is_file()
    assert (out / "blue_team_checklist.md").is_file()


def test_report_is_rendered_in_every_requested_format(tmp_path):
    profile = ra.Profile(code_paths=[str(sample_tree(tmp_path))],
                         client="Acme", out_dir=str(tmp_path / "out"),
                         formats=["html", "md", "json"])
    result = ra.run(profile)
    for extension in ("html", "md", "json"):
        assert (tmp_path / "out" / f"report.{extension}").is_file()
    assert len(result.report_paths) == 3


def test_progress_callback_is_invoked(tmp_path):
    seen = []
    profile = ra.Profile(code_paths=[str(sample_tree(tmp_path))],
                         client="Acme", out_dir=str(tmp_path / "out"),
                         formats=["json"])
    ra.run(profile, progress=lambda i, t, name, stage: seen.append(
        (name, stage is None)))
    assert ("source code", True) in seen        # starting
    assert ("source code", False) in seen       # finished
    assert ("report", False) in seen


# ---------------------------------------------------------------------------
# Failure honesty -- the core requirement
# ---------------------------------------------------------------------------

def test_a_failed_stage_does_not_abort_the_run(tmp_path, monkeypatch):
    def boom(profile, out_dir):
        raise RuntimeError("DNS unreachable")

    monkeypatch.setattr(ra, "STAGES", [
        ("source code", lambda p: bool(p.code_paths), ra.stage_code),
        ("email posture", lambda p: bool(p.mail_domains), boom),
    ])

    profile = ra.Profile(code_paths=[str(sample_tree(tmp_path))],
                         mail_domains=["example.com"], client="Acme",
                         out_dir=str(tmp_path / "out"), formats=["md"])
    result = ra.run(profile)

    names = [s.name for s in result.stages]
    assert names == ["source code", "email posture", "report"]
    code_stage = next(s for s in result.stages if s.name == "source code")
    assert code_stage.ok                       # unaffected by the failure
    assert next(s for s in result.stages
                if s.name == "report").ok      # the report still got built


def test_a_failed_stage_is_recorded_with_its_error(tmp_path, monkeypatch):
    def boom(profile, out_dir):
        raise RuntimeError("DNS unreachable")

    monkeypatch.setattr(ra, "STAGES", [
        ("email posture", lambda p: bool(p.mail_domains), boom)])

    profile = ra.Profile(mail_domains=["example.com"], client="Acme",
                         out_dir=str(tmp_path / "out"), formats=["md"])
    result = ra.run(profile)

    failed = result.failed
    assert len(failed) == 1
    assert failed[0].name == "email posture"
    assert "DNS unreachable" in failed[0].error
    assert "RuntimeError" in failed[0].error


def test_failed_stage_becomes_a_report_limitation(tmp_path, monkeypatch):
    """The headline property: the report must say the area was NOT assessed,
    never imply it was clean."""
    def boom(profile, out_dir):
        raise RuntimeError("DNS unreachable")

    monkeypatch.setattr(ra, "STAGES", [
        ("source code", lambda p: bool(p.code_paths), ra.stage_code),
        ("email posture", lambda p: bool(p.mail_domains), boom)])

    profile = ra.Profile(code_paths=[str(sample_tree(tmp_path))],
                         mail_domains=["example.com"], client="Acme",
                         out_dir=str(tmp_path / "out"), formats=["md"])
    result = ra.run(profile)

    limitations = " ".join(result.limitations())
    assert "email posture stage FAILED" in limitations
    assert "UNKNOWN, not as clean" in limitations

    rendered = (tmp_path / "out" / "report.md").read_text(encoding="utf-8")
    assert "email posture stage FAILED" in rendered
    assert "UNKNOWN, not as clean" in rendered


def test_failed_stage_forces_exit_code_two(tmp_path, monkeypatch):
    def boom(profile, out_dir):
        raise RuntimeError("nope")

    monkeypatch.setattr(ra, "STAGES", [
        ("email posture", lambda p: bool(p.mail_domains), boom)])

    profile = ra.Profile(mail_domains=["x.com"], client="Acme",
                         out_dir=str(tmp_path / "out"), formats=["md"])
    assert ra.run(profile).exit_code == 2


def test_incomplete_outranks_the_findings_gate(tmp_path, monkeypatch):
    """A run that did not finish cannot be summarised as 'found N problems'."""
    def boom(profile, out_dir):
        raise RuntimeError("nope")

    monkeypatch.setattr(ra, "STAGES", [
        ("source code", lambda p: bool(p.code_paths), ra.stage_code),
        ("email posture", lambda p: bool(p.mail_domains), boom)])

    profile = ra.Profile(code_paths=[str(sample_tree(tmp_path))],
                         mail_domains=["x.com"], fail_on="high",
                         client="Acme", out_dir=str(tmp_path / "out"),
                         formats=["md"])
    result = ra.run(profile)
    assert result.gate_tripped is True         # the code scan found a HIGH
    assert result.exit_code == 2               # but incompleteness wins


def test_summary_warns_loudly_about_incompleteness(tmp_path, monkeypatch):
    def boom(profile, out_dir):
        raise RuntimeError("nope")

    monkeypatch.setattr(ra, "STAGES", [
        ("email posture", lambda p: bool(p.mail_domains), boom)])

    profile = ra.Profile(mail_domains=["x.com"], client="Acme",
                         out_dir=str(tmp_path / "out"), formats=["md"])
    text = ra.summary_report(ra.run(profile))
    assert "FAILED" in text
    assert "NOT ASSESSED" in text
    assert "do not read them as a clean result" in text


def test_failed_awareness_stage_is_not_fed_to_the_report(tmp_path, monkeypatch):
    """If the awareness DB could not be read, the report must not try to use
    it -- otherwise the failure would surface as a second, confusing error."""
    def boom(profile, out_dir):
        raise RuntimeError("db locked")

    monkeypatch.setattr(ra, "STAGES", [
        ("awareness", lambda p: bool(p.awareness_db), boom)])

    profile = ra.Profile(awareness_db=str(tmp_path / "missing.db"),
                         client="Acme", out_dir=str(tmp_path / "out"),
                         formats=["md"])
    result = ra.run(profile)
    assert result.failed[0].name == "awareness"
    report_stage = next(s for s in result.stages if s.name == "report")
    assert report_stage.ok
    assert result.report.awareness is None


def test_a_failed_stage_removes_its_stale_artifact(tmp_path, monkeypatch):
    """A stale artifact from a previous run is a trap: this run's report would
    not use it, but anyone globbing out/*.json afterwards would mix in data
    from a different assessment."""
    out = tmp_path / "out"
    out.mkdir()
    stale = out / "mail.json"
    stale.write_text('{"domain": "from-yesterday.example"}', encoding="utf-8")

    def boom(profile, out_dir):
        raise RuntimeError("DNS unreachable")

    monkeypatch.setattr(ra, "STAGES", [
        ("email posture", lambda p: bool(p.mail_domains), boom)])

    profile = ra.Profile(mail_domains=["x.com"], client="Acme",
                         out_dir=str(out), formats=["md"])
    ra.run(profile)

    assert not stale.exists(), "stale artifact survived a failed stage"


def test_a_successful_stage_replaces_its_stale_artifact(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    (out / "code.json").write_text('{"findings": [{"rule_id": "OLD"}]}',
                                   encoding="utf-8")

    profile = ra.Profile(code_paths=[str(sample_tree(tmp_path))],
                         client="Acme", out_dir=str(out), formats=["md"])
    ra.run(profile)

    payload = json.loads((out / "code.json").read_text(encoding="utf-8"))
    rules = {f["rule_id"] for f in payload["findings"]}
    assert "OLD" not in rules


def test_reducing_the_target_count_clears_extra_artifacts(tmp_path):
    """Two targets write code-1/code-2; dropping to one must not leave
    code-2 behind to be read as part of the run."""
    first = sample_tree(tmp_path)
    second = tmp_path / "src2"
    second.mkdir()
    (second / "b.py").write_text("eval(x)\n", encoding="utf-8")
    out = tmp_path / "out"

    ra.run(ra.Profile(code_paths=[str(first), str(second)], client="Acme",
                      out_dir=str(out), formats=["md"]))
    assert (out / "code-2.json").is_file()

    ra.run(ra.Profile(code_paths=[str(first)], client="Acme",
                      out_dir=str(out), formats=["md"]))
    assert (out / "code.json").is_file()
    assert not (out / "code-2.json").exists()


# ---------------------------------------------------------------------------
# Run manifest
# ---------------------------------------------------------------------------

def test_manifest_describes_the_run(tmp_path):
    profile = ra.Profile(code_paths=[str(sample_tree(tmp_path))],
                         fail_on="high", client="Acme",
                         out_dir=str(tmp_path / "out"), formats=["md"])
    result = ra.run(profile)

    manifest = json.loads(
        (tmp_path / "out" / "run.json").read_text(encoding="utf-8"))
    assert manifest["tool"] == "coldlight assess"
    assert manifest["exit_code"] == result.exit_code == 1
    assert manifest["gate_tripped"] is True
    assert manifest["incomplete"] is False
    assert manifest["stages_ok"] == 2
    assert manifest["stages_failed"] == 0
    assert [s["name"] for s in manifest["stages"]] == ["source code", "report"]
    assert manifest["profile"]["client"] == "Acme"


def test_manifest_marks_an_incomplete_run(tmp_path, monkeypatch):
    def boom(profile, out_dir):
        raise RuntimeError("nope")

    monkeypatch.setattr(ra, "STAGES", [
        ("email posture", lambda p: bool(p.mail_domains), boom)])

    profile = ra.Profile(mail_domains=["x.com"], client="Acme",
                         out_dir=str(tmp_path / "out"), formats=["md"])
    ra.run(profile)

    manifest = json.loads(
        (tmp_path / "out" / "run.json").read_text(encoding="utf-8"))
    assert manifest["incomplete"] is True
    assert manifest["exit_code"] == 2
    assert manifest["stages_failed"] == 1
    failed = next(s for s in manifest["stages"] if s["status"] == "failed")
    assert "nope" in failed["error"]


# ---------------------------------------------------------------------------
# Gating
# ---------------------------------------------------------------------------

def test_gate_trips_without_a_baseline(tmp_path):
    profile = ra.Profile(code_paths=[str(sample_tree(tmp_path))],
                         fail_on="high", client="Acme",
                         out_dir=str(tmp_path / "out"), formats=["md"])
    result = ra.run(profile)
    assert result.gate_tripped is True
    assert result.exit_code == 1
    assert "HIGH" in result.gate_detail


def test_no_gate_configured_means_no_failure(tmp_path):
    profile = ra.Profile(code_paths=[str(sample_tree(tmp_path))],
                         client="Acme", out_dir=str(tmp_path / "out"),
                         formats=["md"])
    result = ra.run(profile)
    assert result.gate_tripped is False
    assert result.exit_code == 0


def test_gate_below_findings_does_not_trip(tmp_path):
    profile = ra.Profile(code_paths=[str(sample_tree(tmp_path))],
                         fail_on="critical", client="Acme",
                         out_dir=str(tmp_path / "out"), formats=["md"])
    # The sample has a HIGH, not a CRITICAL.
    assert ra.run(profile).exit_code == 0


def test_baseline_suppresses_the_accepted_backlog(tmp_path):
    src = sample_tree(tmp_path)
    baseline = tmp_path / "baseline.json"

    first = ra.Profile(code_paths=[str(src)], fail_on="high", client="Acme",
                       out_dir=str(tmp_path / "out"), formats=["md"])
    assert ra.run(first).exit_code == 1            # fails on the backlog

    # Accept it, then re-run with the baseline in place.
    import coldlight_baseline as bl
    import coldlight_codescan as cs
    scan = cs.scan_code(str(src))
    bl.save_baseline(bl.build_baseline("code", scan.findings, root=str(src)),
                     baseline)

    second = ra.Profile(code_paths=[str(src)], fail_on="high",
                        baseline=str(baseline), client="Acme",
                        out_dir=str(tmp_path / "out2"), formats=["md"])
    result = ra.run(second)
    assert result.exit_code == 0
    stage = next(s for s in result.stages if s.name == "source code")
    assert stage.findings == 1
    assert stage.new_findings == 0
    assert "0 new" in stage.summary


# ---------------------------------------------------------------------------
# Summary and the profile template
# ---------------------------------------------------------------------------

def test_summary_lists_every_stage(tmp_path):
    profile = ra.Profile(code_paths=[str(sample_tree(tmp_path))],
                         detect_enabled=True, client="Acme",
                         out_dir=str(tmp_path / "out"), formats=["md"])
    text = ra.summary_report(ra.run(profile))
    assert "Stages: 3 ok, 0 failed" in text
    assert "source code" in text
    assert "detection artifacts" in text
    assert "report.md" in text
    assert "Report:" in text


def test_summary_reports_findings_and_counts(tmp_path):
    profile = ra.Profile(code_paths=[str(sample_tree(tmp_path))],
                         client="Acme", out_dir=str(tmp_path / "out"),
                         formats=["md"])
    text = ra.summary_report(ra.run(profile))
    assert "finding(s) covering" in text
    assert "high=" in text


def test_profile_template_is_valid_and_loadable(tmp_path):
    path = ra.write_profile_template(tmp_path / "assessment.toml")
    assert path.is_file()

    profile = ra.load_profile(path)
    assert profile.configured_stages          # the template configures stages
    assert profile.formats == ["html", "md"]

    # It ships with placeholders, so validation should warn rather than pass.
    _errors, warnings = ra.validate_profile(profile)
    assert any("CHANGE-ME" in w for w in warnings)


def test_profile_template_refuses_to_overwrite(tmp_path):
    path = ra.write_profile_template(tmp_path / "a.toml")
    with pytest.raises(ra.AssessError, match="already exists"):
        ra.write_profile_template(path)


# ---------------------------------------------------------------------------
# AI/ML stage
# ---------------------------------------------------------------------------

def ai_tree(tmp_path):
    src = tmp_path / "aisrc"
    src.mkdir()
    (src / "agent.py").write_text(
        'm = torch.load("x.pt")\nout = eval(completion)\n', encoding="utf-8")
    # Pickle magic followed by invalid pickle bytes: detectable by its header,
    # and unloadable by anything that tried (nothing does).
    (src / "legacy.joblib").write_bytes(b"\x80\x04not-a-valid-pickle")
    return src


def test_ai_stage_runs_and_writes_its_artifact(tmp_path):
    profile = ra.Profile(ai_paths=[str(ai_tree(tmp_path))], client="Acme",
                         out_dir=str(tmp_path / "out"), formats=["json"])
    result = ra.run(profile)

    assert [s.name for s in result.stages] == ["AI/ML systems", "report"]
    assert all(s.ok for s in result.stages)
    assert result.exit_code == 0

    ai_json = tmp_path / "out" / "ai.json"
    assert ai_json.is_file()
    payload = json.loads(ai_json.read_text(encoding="utf-8"))
    assert payload["tool"] == "coldlight aisec"
    assert payload["findings"]
    assert payload["unsafe_artifact_count"] == 1


def test_ai_stage_reports_code_executing_artifacts_in_its_summary(tmp_path):
    profile = ra.Profile(ai_paths=[str(ai_tree(tmp_path))], client="Acme",
                         out_dir=str(tmp_path / "out"), formats=["json"])
    result = ra.run(profile)
    stage = next(s for s in result.stages if s.name == "AI/ML systems")
    assert "code-executing model artifact" in stage.summary


def test_ai_stage_is_configured_from_the_profile():
    assert "AI/ML systems" in ra.Profile(ai_paths=["."]).configured_stages
    assert "AI/ML systems" not in ra.Profile(code_paths=["."]).configured_stages


def test_ai_stage_inherits_the_code_exclude_list(tmp_path):
    """An AI scan with no exclude list of its own would re-read everything
    the code scan was told to skip."""
    src = ai_tree(tmp_path)
    profile = ra.Profile(ai_paths=[str(src)], code_exclude=["agent.py"],
                         client="Acme", out_dir=str(tmp_path / "out"),
                         formats=["json"])
    ra.run(profile)
    payload = json.loads(
        (tmp_path / "out" / "ai.json").read_text(encoding="utf-8"))
    assert payload["files_scanned"] == 0


def test_ai_gate_trips_on_severity(tmp_path):
    profile = ra.Profile(ai_paths=[str(ai_tree(tmp_path))], client="Acme",
                         out_dir=str(tmp_path / "out"), formats=["json"],
                         fail_on="critical")
    result = ra.run(profile)
    stage = next(s for s in result.stages if s.name == "AI/ML systems")
    assert stage.gate_tripped is True
    assert result.exit_code == 1


def test_ai_findings_appear_in_the_assess_report(tmp_path):
    profile = ra.Profile(ai_paths=[str(ai_tree(tmp_path))], client="Acme",
                         out_dir=str(tmp_path / "out"), formats=["json"])
    result = ra.run(profile)
    categories = {f.category for f in result.report.findings}
    assert categories == {"AI/ML systems"}


def test_multiple_ai_targets_get_numbered_artifacts(tmp_path):
    first = ai_tree(tmp_path)
    second = tmp_path / "ai2"
    second.mkdir()
    (second / "b.py").write_text("x = joblib.load(p)\n", encoding="utf-8")

    profile = ra.Profile(ai_paths=[str(first), str(second)], client="Acme",
                         out_dir=str(tmp_path / "out"), formats=["json"])
    ra.run(profile)
    assert (tmp_path / "out" / "ai-1.json").is_file()
    assert (tmp_path / "out" / "ai-2.json").is_file()


def test_ai_stage_artifacts_are_cleared_between_runs(tmp_path):
    """A stale ai.json from a previous run must not survive into this one."""
    out = tmp_path / "out"
    out.mkdir(parents=True)
    stale = out / "ai.json"
    stale.write_text('{"tool": "from a different assessment"}',
                     encoding="utf-8")

    profile = ra.Profile(ai_paths=[str(ai_tree(tmp_path))], client="Acme",
                         out_dir=str(out), formats=["json"])
    ra.run(profile)
    payload = json.loads(stale.read_text(encoding="utf-8"))
    assert payload["tool"] == "coldlight aisec"


# ---------------------------------------------------------------------------
# AI runtime probe stage
# ---------------------------------------------------------------------------

def probe_scope_file(tmp_path, url="http://localhost:8099/api/chat"):
    path = tmp_path / "scope.toml"
    path.write_text(
        '[scope]\n'
        'authorization_reference = "TEST-1"\n'
        'targets = ["http://localhost:8099/api"]\n'
        '\n'
        '[probe]\n'
        f'url = "{url}"\n'
        'response_path = "reply"\n'
        'delay_ms = 0\n',
        encoding="utf-8")
    return path


def test_probe_stage_is_configured_from_the_profile(tmp_path):
    assert "AI runtime behaviour" in ra.Profile(
        probe_scope="scope.toml").configured_stages
    assert "AI runtime behaviour" not in ra.Profile(
        code_paths=["."]).configured_stages


def test_probe_stage_without_a_scope_file_does_not_run(tmp_path):
    """Deny by default: no scope means the stage is not even configured."""
    profile = ra.Profile(code_paths=[str(sample_tree(tmp_path))],
                         out_dir=str(tmp_path / "out"), formats=["json"],
                         client="Acme")
    result = ra.run(profile)
    assert "AI runtime behaviour" not in [s.name for s in result.stages]


@pytest.fixture
def unreachable_endpoint(monkeypatch):
    """Make every probe fail at the transport, without opening a socket.

    These tests are about how the stage HANDLES a run that established
    nothing; letting them dial a dead port just bought a 20-second timeout
    each.
    """
    import coldlight_canary as cn

    def refuse(config, prompt, opener=None):
        return None, "", "could not reach the endpoint: connection refused"

    monkeypatch.setattr(cn, "_send", refuse)


def test_probe_stage_fails_when_nothing_can_be_established(
        tmp_path, unreachable_endpoint):
    profile = ra.Profile(probe_scope=str(probe_scope_file(tmp_path)),
                         out_dir=str(tmp_path / "out"), formats=["json"],
                         client="Acme")
    result = ra.run(profile)
    stage = next(s for s in result.stages if s.name == "AI runtime behaviour")
    assert stage.status == ra.STAGE_FAILED
    assert "nothing about the model" in stage.error
    assert result.exit_code == 2


def test_failed_probe_stage_keeps_its_diagnostic_artifact(
        tmp_path, unreachable_endpoint):
    """The JSON is genuine output of this run, and says why nothing landed."""
    profile = ra.Profile(probe_scope=str(probe_scope_file(tmp_path)),
                         out_dir=str(tmp_path / "out"), formats=["json"],
                         client="Acme")
    ra.run(profile)
    payload = json.loads(
        (tmp_path / "out" / "probe.json").read_text(encoding="utf-8"))
    assert payload["tool"] == "coldlight canary"
    assert payload["verdict_established"] is False
    assert payload["counts"]["inconclusive"] == payload["counts"]["probes"]


def test_probe_stage_refuses_an_out_of_scope_endpoint(tmp_path):
    path = probe_scope_file(tmp_path, url="http://evil.example.com/api/chat")
    profile = ra.Profile(probe_scope=str(path),
                         out_dir=str(tmp_path / "out"), formats=["json"],
                         client="Acme")
    result = ra.run(profile)
    stage = next(s for s in result.stages if s.name == "AI runtime behaviour")
    assert stage.status == ra.STAGE_FAILED
    assert "scope" in stage.error.lower() or "listed" in stage.error.lower()


def test_probe_stage_reports_a_missing_scope_file_clearly(tmp_path):
    profile = ra.Profile(probe_scope=str(tmp_path / "absent.toml"),
                         out_dir=str(tmp_path / "out"), formats=["json"],
                         client="Acme")
    result = ra.run(profile)
    stage = next(s for s in result.stages if s.name == "AI runtime behaviour")
    assert stage.status == ra.STAGE_FAILED
    assert "scope" in stage.error.lower()


# ---------------------------------------------------------------------------
# Git history stage
# ---------------------------------------------------------------------------

import shutil as _shutil
import subprocess as _subprocess

_GIT = _shutil.which("git")
_needs_git = pytest.mark.skipif(_GIT is None, reason="git is not installed")

_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


def _git(repo, *args):
    _subprocess.run(["git", *args], cwd=str(repo), check=True,
                    capture_output=True, text=True)


def leaky_repo(tmp_path, name="repo"):
    """A repo whose secret was committed and then deleted."""
    repo = tmp_path / name
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "fixture@example.invalid")
    _git(repo, "config", "user.name", "Fixture Author")
    _git(repo, "config", "commit.gpgsign", "false")
    (repo / "config.py").write_text(f'K = "{_AWS_KEY}"\n', encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "leak")
    (repo / "config.py").write_text('K = "env"\n', encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "fix")
    return repo


def test_history_stage_is_configured_from_the_profile():
    assert "git history" in ra.Profile(history_paths=["."]).configured_stages
    assert "git history" not in ra.Profile(code_paths=["."]).configured_stages


@_needs_git
def test_history_stage_finds_what_the_code_stage_misses(tmp_path):
    repo = leaky_repo(tmp_path)
    profile = ra.Profile(code_paths=[str(repo)], history_paths=[str(repo)],
                         out_dir=str(tmp_path / "out"), formats=["json"],
                         client="Acme")
    result = ra.run(profile)

    code = next(s for s in result.stages if s.name == "source code")
    history = next(s for s in result.stages if s.name == "git history")
    assert code.findings == 0            # deleted, so the tree is clean
    assert history.findings == 1         # still recoverable
    assert "gone from HEAD but recoverable" in history.summary
    assert result.exit_code == 0


@_needs_git
def test_history_stage_writes_its_artifact(tmp_path):
    repo = leaky_repo(tmp_path)
    profile = ra.Profile(history_paths=[str(repo)],
                         out_dir=str(tmp_path / "out"), formats=["json"],
                         client="Acme")
    ra.run(profile)
    payload = json.loads(
        (tmp_path / "out" / "history.json").read_text(encoding="utf-8"))
    assert payload["tool"] == "coldlight history"
    assert payload["assessed"] is True
    assert payload["counts"]["recoverable_only"] == 1
    assert _AWS_KEY not in json.dumps(payload)


@_needs_git
def test_history_stage_fails_on_a_shallow_clone(tmp_path):
    source = leaky_repo(tmp_path, name="source")
    shallow = tmp_path / "shallow"
    _subprocess.run(["git", "clone", "-q", "--depth", "1",
                     source.as_uri(), str(shallow)],
                    check=True, capture_output=True, text=True)

    profile = ra.Profile(history_paths=[str(shallow)],
                         out_dir=str(tmp_path / "out"), formats=["json"],
                         client="Acme")
    result = ra.run(profile)
    stage = next(s for s in result.stages if s.name == "git history")
    assert stage.status == ra.STAGE_FAILED
    assert "SHALLOW" in stage.error
    assert result.exit_code == 2


def test_history_stage_reports_a_missing_repo_clearly(tmp_path):
    profile = ra.Profile(history_paths=[str(tmp_path / "absent")],
                         out_dir=str(tmp_path / "out"), formats=["json"],
                         client="Acme")
    result = ra.run(profile)
    stage = next(s for s in result.stages if s.name == "git history")
    assert stage.status == ra.STAGE_FAILED


# ---------------------------------------------------------------------------
# Indicator stage
# ---------------------------------------------------------------------------

def _iso(days=0):
    """A date relative to today, so no pack in these tests goes stale with
    the calendar. A hard-coded `retrieved` would have the suite start
    reporting PARTIAL coverage ninety days after it was written."""
    from datetime import date, timedelta
    return (date.today() + timedelta(days=days)).isoformat()


def ioc_pack(tmp_path, *, name="testpack", valid_until=None,
             retrieved=None):
    """A two-surface pack: a distinctive filename and a port that is not."""
    valid = f'valid_until = "{valid_until}"' if valid_until else ""
    path = tmp_path / f"{name}.toml"
    path.write_text(
        "[pack]\n"
        f'name = "{name}"\n'
        'version = "1.0"\n'
        'source = "https://example.invalid/testpack"\n'
        'license = "CC0-1.0"\n'
        f'retrieved = "{retrieved or _iso()}"\n'
        "\n[[indicator]]\n"
        'id = "TP-DROPPED"\n'
        'kind = "file_name"\n'
        'value = "/var/tmp/.testtool-agent"\n'
        'uniqueness = "A"\n'
        'verification = "V1"\n'
        'tier = "T1"\n'
        'title = "Test tool agent on disk"\n'
        f"{valid}\n"
        "\n[[indicator]]\n"
        'id = "TP-PORT"\n'
        'kind = "listening_port"\n'
        'value = "18999"\n'
        'uniqueness = "C"\n'
        'verification = "V3"\n'
        'tier = "T3"\n'
        'title = "Test tool callback port"\n'
        f"{valid}\n",
        encoding="utf-8")
    return str(path)


def ioc_tree(tmp_path, *, dropped=True, port=True, name="iocroot"):
    root = tmp_path / name
    (root / "var" / "tmp").mkdir(parents=True, exist_ok=True)
    if dropped:
        (root / "var" / "tmp" / ".testtool-agent").write_text(
            "payload placeholder\n", encoding="utf-8")
    if port:
        (root / "app.yml").write_text("port: 18999\n", encoding="utf-8")
    (root / "readme.md").write_text("nothing to see\n", encoding="utf-8")
    return str(root)


def ioc_profile(tmp_path, **kwargs):
    # Built only when the caller did not pass one: setdefault would evaluate
    # its default eagerly, and ioc_pack/ioc_tree WRITE -- the default pack
    # would overwrite the caller's expired one at the same path.
    if "ioc_packs" not in kwargs:
        kwargs["ioc_packs"] = [ioc_pack(tmp_path)]
    if "ioc_paths" not in kwargs:
        kwargs["ioc_paths"] = [ioc_tree(tmp_path)]
    kwargs.setdefault("client", "Acme")
    kwargs.setdefault("out_dir", str(tmp_path / "out"))
    kwargs.setdefault("formats", ["json"])
    return ra.Profile(**kwargs)


def ioc_stage_of(result):
    return next(s for s in result.stages if s.name == "indicators")


def test_ioc_stage_runs_and_writes_its_artifact(tmp_path):
    result = ra.run(ioc_profile(tmp_path))

    assert [s.name for s in result.stages] == ["indicators", "report"]
    assert all(s.ok for s in result.stages)
    assert result.exit_code == 0

    payload = json.loads(
        (tmp_path / "out" / "ioc.json").read_text(encoding="utf-8"))
    assert payload["tool"] == "coldlight ioc"
    # The filename marker stands alone and promotes the port with it.
    assert {f["indicator_id"] for f in payload["findings"]} == {
        "TP-DROPPED", "TP-PORT"}


def test_ioc_stage_needs_both_a_pack_and_a_path(tmp_path):
    """Either half alone searches nothing, and the output of searching
    nothing is the output of finding nothing."""
    pack_only = ra.Profile(ioc_packs=[ioc_pack(tmp_path)], client="Acme")
    path_only = ra.Profile(ioc_paths=[ioc_tree(tmp_path)], client="Acme")

    assert pack_only.configured_stages == []
    assert path_only.configured_stages == []
    assert any("nothing to scan" in e
               for e in ra.validate_profile(pack_only)[0])
    assert any("nothing would be looked for" in e
               for e in ra.validate_profile(path_only)[0])


def test_ioc_stage_is_configured_from_the_profile(tmp_path):
    profile = ra.Profile(ioc_packs=["p.toml"], ioc_paths=["."])
    assert "indicators" in profile.configured_stages
    assert "indicators" not in ra.Profile(code_paths=["."]).configured_stages


def test_the_ioc_stage_is_loadable_from_a_profile_file(tmp_path):
    profile = ra.load_profile(write(tmp_path, "p.toml", (
        "[assessment]\nclient = \"Acme\"\n\n"
        "[stages.ioc]\n"
        "paths = [\"src\"]\n"
        "packs = [\"packs/a.toml\"]\n"
        "exclude = [\"vendor/*\"]\n"
        "stale_after = 30\n"
    )))
    assert profile.ioc_paths == ["src"]
    assert profile.ioc_packs == ["packs/a.toml"]
    assert profile.ioc_exclude == ["vendor/*"]
    assert profile.ioc_stale_after == 30
    assert ra.Profile().ioc_stale_after is None
    assert "indicators" in profile.configured_stages


def test_a_pack_that_will_not_load_fails_the_stage(tmp_path):
    """Not a warning. Without the pack nothing is searched for, and a stage
    that searched for nothing still prints zero findings."""
    bad = tmp_path / "bad.toml"
    bad.write_text('[pack]\nname = "x"\n', encoding="utf-8")
    result = ra.run(ioc_profile(tmp_path, ioc_packs=[str(bad)]))

    stage = ioc_stage_of(result)
    assert stage.status == ra.STAGE_FAILED
    assert "bad.toml" in stage.error
    assert result.exit_code == 2


def test_the_stage_fails_when_every_indicator_has_expired(tmp_path):
    """The scan runs and the artifact is kept -- it says what the pack would
    once have flagged -- but nothing current was looked for, so this must not
    be presented as a clean tree."""
    result = ra.run(ioc_profile(
        tmp_path, ioc_packs=[ioc_pack(tmp_path, valid_until=_iso(-1))]))

    stage = ioc_stage_of(result)
    assert stage.status == ra.STAGE_FAILED
    assert "expired" in stage.error
    assert result.exit_code == 2

    payload = json.loads(
        (tmp_path / "out" / "ioc.json").read_text(encoding="utf-8"))
    assert payload["indicators_active"] == 0
    assert payload["findings"] == []
    assert payload["expired"], "the diagnostic artifact was not kept"


def test_a_failed_ioc_stage_is_stated_in_the_report(tmp_path):
    result = ra.run(ioc_profile(
        tmp_path, ioc_packs=[ioc_pack(tmp_path, valid_until=_iso(-1))]))
    assert any("indicators stage FAILED" in note
               for note in result.limitations())


def test_ioc_findings_reach_the_assess_report(tmp_path):
    result = ra.run(ioc_profile(tmp_path))
    assert {f.category for f in result.report.findings} == {
        "Known-tool indicators"}
    assert all(f.severity_source == "indicator-pack"
               for f in result.report.findings)


def test_the_ioc_stage_does_not_inherit_the_code_exclude_list(tmp_path):
    """Unlike the AI stage. An exclude list is tuned to quieten a code scan,
    and the same pattern would hide a planted artifact."""
    result = ra.run(ioc_profile(tmp_path,
                                code_exclude=["*agent*", "*.yml"]))
    stage = ioc_stage_of(result)
    assert stage.status == ra.STAGE_OK
    assert stage.findings == 2


def test_the_ioc_stage_has_its_own_exclude_list(tmp_path):
    result = ra.run(ioc_profile(tmp_path, ioc_exclude=["*agent*"]))
    stage = ioc_stage_of(result)
    # The filename marker is gone, so the port has nothing to corroborate it
    # and is reported as pending rather than as a finding.
    assert stage.findings == 0
    assert "awaiting corroboration" in stage.summary


def test_a_weak_marker_alone_does_not_trip_the_gate(tmp_path):
    """The rule the whole module exists for, at the pipeline level: a port
    number on its own must not fail somebody's build."""
    result = ra.run(ioc_profile(
        tmp_path, ioc_paths=[ioc_tree(tmp_path, dropped=False)],
        fail_on="low"))
    stage = ioc_stage_of(result)
    assert stage.findings == 0
    assert stage.gate_tripped is False
    assert result.exit_code == 0


def test_a_standalone_marker_trips_the_gate(tmp_path):
    result = ra.run(ioc_profile(tmp_path, fail_on="high"))
    assert ioc_stage_of(result).gate_tripped is True
    assert result.exit_code == 1


def test_the_stage_says_when_a_baseline_was_not_applied(tmp_path):
    """Every other stage gates on what is new since the baseline. A reader
    who configured one would otherwise assume this stage honoured it."""
    result = ra.run(ioc_profile(tmp_path, baseline=str(tmp_path / "b.json")))
    stage = ioc_stage_of(result)
    assert "baseline not applied" in stage.summary
    assert stage.new_findings is None


def test_a_stale_after_of_zero_is_not_read_as_unset(tmp_path):
    """`--stale-after 0` means every pack retrieved before today is stale.
    An int field defaulting to 0 cannot tell that apart from an absent
    setting, and `or` would hand the operator the ninety-day default they
    were explicitly narrowing."""
    pack = ioc_pack(tmp_path, retrieved=_iso(-1))
    wide = ra.run(ioc_profile(tmp_path, ioc_packs=[pack]))
    narrow = ra.run(ioc_profile(tmp_path, ioc_packs=[pack],
                                ioc_stale_after=0,
                                out_dir=str(tmp_path / "narrow")))

    assert "not fully current" not in ioc_stage_of(wide).summary
    assert "not fully current" in ioc_stage_of(narrow).summary
    payload = json.loads(
        (tmp_path / "narrow" / "ioc.json").read_text(encoding="utf-8"))
    assert payload["stale_packs"] == ["testpack"]


def test_a_negative_stale_after_is_refused(tmp_path):
    profile = ioc_profile(tmp_path, ioc_stale_after=-1)
    assert any("cannot be negative" in e
               for e in ra.validate_profile(profile)[0])


def test_the_stage_counts_surfaces_no_indicator_covered(tmp_path):
    result = ra.run(ioc_profile(tmp_path))
    assert "2 surface(s) NOT COVERED" in ioc_stage_of(result).summary


def test_multiple_ioc_targets_get_numbered_artifacts(tmp_path):
    first = ioc_tree(tmp_path, name="one")
    second = ioc_tree(tmp_path, dropped=False, name="two")
    ra.run(ioc_profile(tmp_path, ioc_paths=[first, second]))

    out = tmp_path / "out"
    assert (out / "ioc-1.json").is_file()
    assert (out / "ioc-2.json").is_file()
    assert not (out / "ioc.json").exists()


def test_a_stale_ioc_artifact_is_cleared_before_the_stage_runs(tmp_path):
    """The artifact prefix is `ioc` while the stage is called `indicators`.
    Without that mapping, yesterday's report would survive a failing stage
    and anyone globbing the output directory would mix two runs."""
    out = tmp_path / "out"
    out.mkdir()
    stale = out / "ioc.json"
    stale.write_text('{"tool": "from a different run"}', encoding="utf-8")

    bad = tmp_path / "bad.toml"
    bad.write_text("not even toml ===\n", encoding="utf-8")
    ra.run(ioc_profile(tmp_path, ioc_packs=[str(bad)], out_dir=str(out)))

    assert not stale.exists()


def test_a_pack_with_no_usable_indicator_does_not_reach_the_report(tmp_path):
    """A failed stage contributes no findings, and its artifact must not be
    read back in as if the stage had succeeded."""
    result = ra.run(ioc_profile(
        tmp_path, ioc_packs=[ioc_pack(tmp_path, valid_until=_iso(-1))]))
    assert result.report.findings == []
    assert not any("Known-tool indicator scan" in s
                   for s in result.report.sources)
