"""Tests for coldlight_baseline.

The headline property: a fingerprint must survive changes that are irrelevant
to whether the finding is the same real problem.
"""

import json

import pytest

import coldlight_baseline as bl
from coldlight_codescan import CodeFinding
from coldlight_mail import MailFinding
from coldlight_vulnintel import Finding


def code(rule="CMD-OS-SYSTEM", file="app.py", line=10,
         snippet="os.system(cmd)", severity="HIGH", cwe="CWE-78",
         title="os.system invokes a shell"):
    return CodeFinding(rule_id=rule, severity=severity, cwe=cwe, title=title,
                       file=file, line=line, snippet=snippet)


def dep(identifier="CVE-2019-10906", package="jinja2", version="2.4.1",
        ecosystem="PyPI", severity="HIGH"):
    return Finding(identifier=identifier, package=package,
                   installed_version=version, ecosystem=ecosystem,
                   severity=severity)


def mail(check="DMARC", title="No DMARC record", severity="HIGH"):
    return MailFinding(check=check, severity=severity, title=title)


# ---------------------------------------------------------------------------
# Fingerprint stability -- the whole feature rests on this
# ---------------------------------------------------------------------------

def test_code_fingerprint_survives_a_line_number_change():
    """A line number shifts whenever anything above it is edited. Keying on
    it would make every refactor look like a wave of new findings."""
    assert bl.code_fingerprint(code(line=10)) == bl.code_fingerprint(code(line=400))


def test_code_fingerprint_survives_indentation_changes():
    """Re-indenting a block (the common reformat) must not invent findings."""
    assert (bl.code_fingerprint(code(snippet="os.system(cmd)"))
            == bl.code_fingerprint(code(snippet="        os.system(cmd)")))
    assert (bl.code_fingerprint(code(snippet="os.system(cmd)"))
            == bl.code_fingerprint(code(snippet="  os.system(cmd)\t")))


def test_code_fingerprint_collapses_whitespace_runs():
    assert (bl.code_fingerprint(code(snippet="a  =   1"))
            == bl.code_fingerprint(code(snippet="a = 1")))


def test_interior_reformatting_does_change_the_fingerprint():
    """An honest limitation, asserted rather than glossed over.

    Normalisation collapses whitespace runs, so indentation and trailing
    space are absorbed -- but adding space inside an expression
    (`f(cmd)` -> `f( cmd )`) yields a different snippet and therefore a new
    fingerprint. Stripping all whitespace instead would risk merging
    genuinely different code, so this trade-off is deliberate: a reformat of
    that kind shows up as resolved+new, which is noisy but never silently
    hides a finding.
    """
    assert (bl.code_fingerprint(code(snippet="os.system(cmd)"))
            != bl.code_fingerprint(code(snippet="os.system( cmd )")))


def test_code_fingerprint_changes_with_rule_file_or_code():
    base = bl.code_fingerprint(code())
    assert bl.code_fingerprint(code(rule="CODE-EVAL")) != base
    assert bl.code_fingerprint(code(file="other.py")) != base
    assert bl.code_fingerprint(code(snippet="os.system(other)")) != base


def test_code_fingerprint_normalises_absolute_paths(tmp_path):
    """CI and a developer laptop must agree on identity."""
    nested = tmp_path / "src" / "app.py"
    nested.parent.mkdir(parents=True)
    nested.write_text("x", encoding="utf-8")

    absolute = bl.code_fingerprint(code(file=str(nested)), root=tmp_path)
    relative = bl.code_fingerprint(code(file="src/app.py"))
    assert absolute == relative


def test_code_fingerprint_normalises_windows_separators():
    assert (bl.code_fingerprint(code(file=r"src\app.py"))
            == bl.code_fingerprint(code(file="src/app.py")))


def test_dependency_fingerprint_ignores_the_installed_version():
    """A version bump that does not fix the CVE is still the same finding;
    one that does fix it disappears from the scan on its own."""
    assert (bl.vuln_fingerprint(dep(version="2.4.1"))
            == bl.vuln_fingerprint(dep(version="2.5.0")))


def test_dependency_fingerprint_distinguishes_cve_package_ecosystem():
    base = bl.vuln_fingerprint(dep())
    assert bl.vuln_fingerprint(dep(identifier="CVE-2020-1")) != base
    assert bl.vuln_fingerprint(dep(package="flask")) != base
    assert bl.vuln_fingerprint(dep(ecosystem="npm")) != base


def test_dependency_fingerprint_is_case_insensitive():
    assert (bl.vuln_fingerprint(dep(package="Jinja2", identifier="cve-2019-10906"))
            == bl.vuln_fingerprint(dep(package="jinja2",
                                       identifier="CVE-2019-10906")))


def test_mail_fingerprint_includes_the_domain():
    assert (bl.mail_fingerprint(mail(), "a.com")
            != bl.mail_fingerprint(mail(), "b.com"))
    assert (bl.mail_fingerprint(mail(), "A.com")
            == bl.mail_fingerprint(mail(), "a.com"))


def test_fingerprints_are_readable_and_namespaced():
    """The baseline is meant to be committed and reviewed in a PR."""
    assert bl.vuln_fingerprint(dep()).startswith("dep:PyPI/jinja2/CVE-")
    assert bl.code_fingerprint(code()).startswith("code:CMD-OS-SYSTEM@app.py")
    assert bl.mail_fingerprint(mail(), "x.com") == (
        "mail:x.com/DMARC/No DMARC record")


def test_unknown_source_raises():
    with pytest.raises(bl.BaselineError, match="unknown baseline source"):
        bl.fingerprint_for("telepathy", code())


# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------

def test_normalise_snippet():
    assert bl.normalise_snippet("  a   b\t\nc ") == "a b c"
    assert bl.normalise_snippet("") == ""
    assert bl.normalise_snippet(None) == ""


def test_normalise_path_strips_leading_dot_slash():
    assert bl.normalise_path("./src/app.py") == "src/app.py"


# ---------------------------------------------------------------------------
# Baseline file I/O
# ---------------------------------------------------------------------------

def test_missing_baseline_is_not_an_error(tmp_path):
    baseline = bl.load_baseline(tmp_path / "nope.json")
    assert baseline.exists is False
    assert baseline.entries == {}


def test_round_trip(tmp_path):
    path = tmp_path / "baseline.json"
    built = bl.build_baseline("code", [code(), code(file="b.py")])
    bl.save_baseline(built, path)

    loaded = bl.load_baseline(path)
    assert loaded.exists is True
    assert set(loaded.entries) == set(built.entries)
    assert loaded.created and loaded.updated

    entry = next(iter(loaded.entries.values()))
    assert entry.severity == "HIGH"
    assert entry.source == "code"
    assert entry.first_seen
    assert entry.label


def test_saved_baseline_is_sorted_for_reviewable_diffs(tmp_path):
    path = tmp_path / "baseline.json"
    bl.save_baseline(
        bl.build_baseline("code", [code(file=f) for f in "cab"]), path)
    keys = list(json.loads(path.read_text(encoding="utf-8"))["entries"])
    assert keys == sorted(keys)


def test_bad_json_raises(tmp_path):
    path = tmp_path / "baseline.json"
    path.write_text("{nope", encoding="utf-8")
    with pytest.raises(bl.BaselineError, match="not valid JSON"):
        bl.load_baseline(path)


def test_non_object_raises(tmp_path):
    path = tmp_path / "baseline.json"
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(bl.BaselineError, match="expected a JSON object"):
        bl.load_baseline(path)


def test_future_version_is_refused_with_guidance(tmp_path):
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps({"coldlight_baseline_version": "99",
                                "entries": {}}), encoding="utf-8")
    with pytest.raises(bl.BaselineError, match="--update-baseline"):
        bl.load_baseline(path)


def test_counts_accumulate_for_identical_occurrences():
    built = bl.build_baseline("code", [code(line=1), code(line=50)])
    assert len(built.entries) == 1              # same fingerprint
    assert next(iter(built.entries.values())).count == 2


def test_build_keeps_the_worst_severity_for_a_fingerprint():
    built = bl.build_baseline("code", [code(severity="LOW"),
                                       code(severity="CRITICAL")])
    assert next(iter(built.entries.values())).severity == "CRITICAL"


def test_first_seen_is_carried_over(tmp_path):
    path = tmp_path / "b.json"
    first = bl.build_baseline("code", [code()])
    for entry in first.entries.values():
        entry.first_seen = "2020-01-01"
    bl.save_baseline(first, path)

    previous = bl.load_baseline(path)
    refreshed = bl.build_baseline("code", [code(), code(file="new.py")],
                                 previous=previous)
    old = refreshed.entries[bl.code_fingerprint(code())]
    assert old.first_seen == "2020-01-01"       # history not rewritten
    new = refreshed.entries[bl.code_fingerprint(code(file="new.py"))]
    assert new.first_seen != "2020-01-01"


# ---------------------------------------------------------------------------
# Merging: one file, several sources
# ---------------------------------------------------------------------------

def test_merge_preserves_other_sources(tmp_path):
    """Updating the code baseline must not discard dependency entries living
    in the same file."""
    combined = bl.Baseline()
    combined.entries.update(bl.build_baseline("dep", [dep()]).entries)
    combined.entries.update(bl.build_baseline("code", [code()]).entries)
    assert len(combined.entries) == 2

    merged = bl.merge_baseline(combined, "code", [code(file="other.py")])
    fingerprints = set(merged.entries)
    assert bl.vuln_fingerprint(dep()) in fingerprints          # kept
    assert bl.code_fingerprint(code(file="other.py")) in fingerprints
    assert bl.code_fingerprint(code()) not in fingerprints     # replaced


def test_merge_keeps_created_date():
    existing = bl.Baseline(created="2020-01-01T00:00:00Z")
    merged = bl.merge_baseline(existing, "code", [code()])
    assert merged.created == "2020-01-01T00:00:00Z"


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------

def test_everything_is_new_without_a_baseline():
    diff = bl.diff_findings("code", [code(), code(file="b.py")], bl.Baseline())
    assert len(diff.new) == 2
    assert diff.existing == []
    assert diff.baseline_exists is False

    report = bl.diff_report(diff)
    assert "No baseline found" in report
    assert "--update-baseline" in report


def test_baselined_findings_are_not_new(tmp_path):
    path = tmp_path / "b.json"
    bl.save_baseline(bl.build_baseline("code", [code()]), path)
    baseline = bl.load_baseline(path)

    diff = bl.diff_findings("code", [code()], baseline)
    assert diff.new == []
    assert len(diff.existing) == 1
    assert "0 new since baseline" in bl.diff_report(diff)


def test_a_genuinely_new_finding_is_reported(tmp_path):
    path = tmp_path / "b.json"
    bl.save_baseline(bl.build_baseline("code", [code()]), path)

    diff = bl.diff_findings("code", [code(), code(file="new.py")],
                            bl.load_baseline(path))
    assert len(diff.new) == 1
    assert len(diff.existing) == 1
    assert "1 NEW since baseline" in bl.diff_report(diff)


def test_extra_occurrences_of_a_baselined_pattern_are_new(tmp_path):
    """One accepted occurrence does not license three."""
    path = tmp_path / "b.json"
    bl.save_baseline(bl.build_baseline("code", [code()]), path)

    diff = bl.diff_findings("code", [code(line=1), code(line=2), code(line=3)],
                            bl.load_baseline(path))
    assert len(diff.existing) == 1
    assert len(diff.new) == 2


def test_resolved_findings_are_reported(tmp_path):
    path = tmp_path / "b.json"
    bl.save_baseline(bl.build_baseline("code", [code(), code(file="gone.py")]),
                     path)

    diff = bl.diff_findings("code", [code()], bl.load_baseline(path))
    assert len(diff.resolved) == 1
    assert diff.resolved[0][1].label.startswith("os.system")

    report = bl.diff_report(diff)
    assert "1 RESOLVED since baseline" in report


def test_resolved_only_considers_the_same_source(tmp_path):
    """A code scan must not claim the dependency findings were resolved."""
    combined = bl.Baseline()
    combined.entries.update(bl.build_baseline("dep", [dep()]).entries)
    combined.entries.update(bl.build_baseline("code", [code()]).entries)
    combined.exists = True

    diff = bl.diff_findings("code", [code()], combined)
    assert diff.resolved == []


def test_diff_total_counts_everything(tmp_path):
    path = tmp_path / "b.json"
    bl.save_baseline(bl.build_baseline("code", [code()]), path)
    diff = bl.diff_findings("code", [code(), code(file="n.py")],
                            bl.load_baseline(path))
    assert diff.total == 2


# ---------------------------------------------------------------------------
# Gating on new findings only
# ---------------------------------------------------------------------------

def test_gate_ignores_the_accepted_backlog(tmp_path):
    """The point of the feature: a backlog of criticals must not fail the
    build once accepted."""
    backlog = [code(rule=f"R{i}", severity="CRITICAL") for i in range(5)]
    path = tmp_path / "b.json"
    bl.save_baseline(bl.build_baseline("code", backlog), path)

    diff = bl.diff_findings("code", backlog, bl.load_baseline(path))
    assert diff.new_meets("critical") is False
    assert len(diff.existing) == 5


def test_gate_trips_on_a_new_high(tmp_path):
    path = tmp_path / "b.json"
    bl.save_baseline(bl.build_baseline("code", [code(severity="CRITICAL")]),
                     path)

    diff = bl.diff_findings(
        "code",
        [code(severity="CRITICAL"), code(rule="NEW", severity="HIGH")],
        bl.load_baseline(path))
    assert diff.new_meets("high") is True
    assert diff.new_meets("critical") is False     # the new one is only HIGH


def test_gate_rejects_an_unknown_threshold():
    diff = bl.diff_findings("code", [code()], bl.Baseline())
    with pytest.raises(ValueError, match="unknown severity threshold"):
        diff.new_meets("extremely-bad")


def test_moderate_folds_into_medium_for_gating():
    diff = bl.diff_findings("dep", [dep(severity="MODERATE")], bl.Baseline())
    assert diff.new_meets("medium") is True


# ---------------------------------------------------------------------------
# Cross-source behaviour
# ---------------------------------------------------------------------------

def test_dependency_diff_end_to_end(tmp_path):
    path = tmp_path / "b.json"
    bl.save_baseline(bl.build_baseline("dep", [dep()]), path)

    diff = bl.diff_findings(
        "dep",
        [dep(version="2.5.0"), dep(identifier="CVE-2024-1")],
        bl.load_baseline(path))
    # The version bump is the same finding; the new CVE is not.
    assert len(diff.existing) == 1
    assert len(diff.new) == 1
    assert diff.new[0].identifier == "CVE-2024-1"


def test_mail_diff_end_to_end(tmp_path):
    path = tmp_path / "b.json"
    bl.save_baseline(bl.build_baseline("mail", [mail()], domain="x.com"), path)

    diff = bl.diff_findings("mail", [mail(), mail(check="SPF", title="No SPF")],
                            bl.load_baseline(path), domain="x.com")
    assert len(diff.existing) == 1
    assert len(diff.new) == 1


def test_report_shows_severity_and_label_for_new_findings():
    diff = bl.diff_findings("code", [code(severity="CRITICAL")], bl.Baseline())
    report = bl.diff_report(diff)
    assert "CRITICAL" in report
    assert "app.py:10" in report


def test_report_can_hide_resolved(tmp_path):
    path = tmp_path / "b.json"
    bl.save_baseline(bl.build_baseline("code", [code(file="gone.py")]), path)
    diff = bl.diff_findings("code", [], bl.load_baseline(path))
    assert "RESOLVED" in bl.diff_report(diff)
    assert "RESOLVED" not in bl.diff_report(diff, show_resolved=False)
