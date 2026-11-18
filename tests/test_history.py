"""Tests for coldlight_history (secrets in git history).

These build real throwaway repositories, because the whole module is an
assertion about how git behaves and a mock of git would only test the mock.
Each repo is created in tmp_path with its own local identity, so nothing
touches the developer's global git configuration.

NOTE FOR SCANNERS: the credential-shaped strings below are fabricated
fixtures, committed to disposable repositories so the scanner has something to
find. AKIAIOSFODNN7EXAMPLE is AWS's own documented example value.
"""

import json
import shutil
import subprocess

import pytest

import coldlight_history as h


GIT = shutil.which("git")
pytestmark = pytest.mark.skipif(GIT is None, reason="git is not installed")

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
GH_PAT = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"

LEAKY_CONFIG = f'AWS_KEY = "{AWS_KEY}"\nDEBUG = False\n'
CLEAN_CONFIG = 'import os\nAWS_KEY = os.environ["AWS_KEY"]\nDEBUG = False\n'


def git(repo, *args):
    return subprocess.run(["git", *args], cwd=str(repo), check=True,
                          capture_output=True, text=True)


def make_repo(tmp_path, name="repo"):
    repo = tmp_path / name
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "user.email", "fixture@example.invalid")
    git(repo, "config", "user.name", "Fixture Author")
    git(repo, "config", "commit.gpgsign", "false")
    return repo


def commit(repo, message, files):
    for name, content in files.items():
        (repo / name).write_text(content, encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", message)


def leaked_then_removed(tmp_path, name="repo"):
    """The case the module exists for: committed, then 'fixed' by deletion."""
    repo = make_repo(tmp_path, name)
    commit(repo, "initial config", {"config.py": LEAKY_CONFIG})
    commit(repo, "move the key to the environment",
           {"config.py": CLEAN_CONFIG})
    return repo


def by_rule(result, rule_id):
    return [f for f in result.findings if f.rule_id == rule_id]


# ---------------------------------------------------------------------------
# Rules are reused, not duplicated
# ---------------------------------------------------------------------------

def test_secret_rules_come_from_both_scanners():
    ids = {r.rule_id for r in h.secret_rules()}
    assert "SECRET-AWS-AKID" in ids          # coldlight_codescan
    assert "AI-SECRET-OPENAI" in ids         # coldlight_aisec


def test_only_credential_rules_are_used():
    """A risky-pattern rule is not a secret rule; history is about secrets."""
    ids = {r.rule_id for r in h.secret_rules()}
    assert "CODE-EVAL" not in ids
    assert "SQLI-FSTRING" not in ids
    assert all(r.redact for r in h.secret_rules())


# ---------------------------------------------------------------------------
# Repository state
# ---------------------------------------------------------------------------

def test_repo_state_of_a_normal_repo(tmp_path):
    repo = leaked_then_removed(tmp_path)
    state = h.repo_state(repo)
    assert state.is_repo is True
    assert state.shallow is False
    assert state.commits == 2
    assert state.scannable is True
    assert state.error == ""
    assert state.head


def test_a_directory_that_is_not_a_repo_is_reported_clearly(tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    state = h.repo_state(plain)
    assert state.is_repo is False
    assert "not a git repository" in state.error


def test_scanning_a_non_repo_raises(tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    with pytest.raises(h.HistoryError):
        h.scan_history(plain)


def test_a_repo_with_no_commits_is_not_scannable(tmp_path):
    repo = make_repo(tmp_path)
    state = h.repo_state(repo)
    assert state.is_repo is True
    assert state.commits == 0
    assert state.scannable is False
    assert "no commits" in state.error


def test_missing_git_is_reported_not_crashed(monkeypatch):
    monkeypatch.setattr(h.shutil, "which", lambda name: None)
    with pytest.raises(h.GitUnavailable) as excinfo:
        h.git_version()
    assert "not installed" in str(excinfo.value)


def test_missing_git_leaves_repo_state_explained(monkeypatch, tmp_path):
    monkeypatch.setattr(h.shutil, "which", lambda name: None)
    state = h.repo_state(tmp_path)
    assert state.is_repo is False
    assert "git is not installed" in state.error


# ---------------------------------------------------------------------------
# The distinction the module exists to draw
# ---------------------------------------------------------------------------

def test_a_secret_deleted_from_head_is_still_found(tmp_path):
    """Deleting the line is what people believe fixes this. It does not."""
    result = h.scan_history(leaked_then_removed(tmp_path))
    hits = by_rule(result, "SECRET-AWS-AKID")
    assert len(hits) == 1
    assert hits[0].present_in_head is False
    assert hits[0].recoverable_only is True
    assert hits[0].file == "config.py"


def test_a_secret_still_in_head_is_marked_as_such(tmp_path):
    repo = make_repo(tmp_path)
    commit(repo, "add ci", {"ci.py": f'TOKEN = "{GH_PAT}"\n'})
    result = h.scan_history(repo)
    hits = by_rule(result, "SECRET-GITHUB-PAT")
    assert len(hits) == 1
    assert hits[0].present_in_head is True
    assert hits[0].recoverable_only is False


def test_history_finds_what_the_working_tree_scan_cannot(tmp_path):
    """The gap this module closes, asserted directly."""
    import coldlight_codescan as cs

    repo = leaked_then_removed(tmp_path)
    commit(repo, "add ci", {"ci.py": f'TOKEN = "{GH_PAT}"\n'})

    tree = {f.rule_id for f in cs.scan_code(repo).findings}
    history = {f.rule_id for f in h.scan_history(repo).findings}

    assert "SECRET-AWS-AKID" not in tree       # deleted, so invisible to it
    assert "SECRET-AWS-AKID" in history        # still recoverable
    assert "SECRET-GITHUB-PAT" in tree and "SECRET-GITHUB-PAT" in history


def test_findings_are_ordered_with_the_forgotten_ones_first(tmp_path):
    repo = leaked_then_removed(tmp_path)
    commit(repo, "add another", {"live.py": f'K = "{AWS_KEY}"\n'})
    result = h.scan_history(repo)
    assert len(result.findings) == 2
    # Same rule and severity, so the tiebreak is what decides: the secret
    # nobody is watching any more comes first.
    assert result.findings[0].recoverable_only is True
    assert result.findings[1].present_in_head is True


def test_both_groups_are_counted_separately(tmp_path):
    repo = leaked_then_removed(tmp_path)
    commit(repo, "add ci", {"ci.py": f'TOKEN = "{GH_PAT}"\n'})
    result = h.scan_history(repo)
    assert len(result.recoverable_only) == 1
    assert len(result.still_in_head) == 1


# ---------------------------------------------------------------------------
# Commit attribution and grouping
# ---------------------------------------------------------------------------

def test_the_introducing_commit_is_recorded(tmp_path):
    repo = leaked_then_removed(tmp_path)
    first = git(repo, "rev-list", "--max-parents=0", "HEAD").stdout.strip()
    finding = by_rule(h.scan_history(repo), "SECRET-AWS-AKID")[0]
    assert finding.first_commit == first
    assert finding.first_commit_at
    assert "Fixture Author" in finding.first_author


def test_one_secret_re_added_several_times_is_one_finding(tmp_path):
    repo = make_repo(tmp_path)
    commit(repo, "leak", {"r.py": f'K = "{AWS_KEY}"\n'})
    commit(repo, "fix", {"r.py": 'K = "env"\n'})
    commit(repo, "leak again", {"r.py": f'K = "{AWS_KEY}"\n'})
    commit(repo, "fix again", {"r.py": 'K = "env"\n'})

    hits = by_rule(h.scan_history(repo), "SECRET-AWS-AKID")
    assert len(hits) == 1
    assert hits[0].commit_count == 2


def test_the_oldest_sighting_is_the_introducing_commit(tmp_path):
    repo = make_repo(tmp_path)
    commit(repo, "leak", {"r.py": f'K = "{AWS_KEY}"\n'})
    oldest = git(repo, "rev-parse", "HEAD").stdout.strip()
    commit(repo, "fix", {"r.py": 'K = "env"\n'})
    commit(repo, "leak again", {"r.py": f'K = "{AWS_KEY}"\n'})

    finding = by_rule(h.scan_history(repo), "SECRET-AWS-AKID")[0]
    assert finding.first_commit == oldest
    assert finding.last_commit != oldest


def test_the_same_secret_in_two_files_is_two_findings_one_fingerprint(tmp_path):
    repo = make_repo(tmp_path)
    commit(repo, "leak twice", {"a.py": f'K = "{AWS_KEY}"\n',
                                "b.py": f'J = "{AWS_KEY}"\n'})
    hits = by_rule(h.scan_history(repo), "SECRET-AWS-AKID")
    assert len(hits) == 2
    assert len({f.fingerprint for f in hits}) == 1
    assert {f.file for f in hits} == {"a.py", "b.py"}


# ---------------------------------------------------------------------------
# The shallow-clone guard
# ---------------------------------------------------------------------------

def test_a_shallow_clone_is_not_assessed(tmp_path):
    """CI checks out shallow by default, which is where this would run. A
    truncated history that finds nothing looks exactly like a clean one."""
    source = leaked_then_removed(tmp_path, name="source")
    target = tmp_path / "shallow"
    subprocess.run(["git", "clone", "-q", "--depth", "1",
                    source.as_uri(), str(target)],
                   check=True, capture_output=True, text=True)

    result = h.scan_history(target)
    assert result.state.shallow is True
    assert result.state.scannable is False
    assert result.assessed is False
    assert result.findings == []
    assert "SHALLOW" in result.state.error
    assert "unshallow" in result.state.error


def test_a_shallow_report_refuses_to_look_clean(tmp_path):
    source = leaked_then_removed(tmp_path, name="source")
    target = tmp_path / "shallow"
    subprocess.run(["git", "clone", "-q", "--depth", "1",
                    source.as_uri(), str(target)],
                   check=True, capture_output=True, text=True)

    report = h.text_report(h.scan_history(target))
    assert "NOT ASSESSED" in report
    assert "NOT a clean result" in report
    assert "no conclusion" in report


def test_shallow_can_be_scanned_when_explicitly_allowed(tmp_path):
    """The operator may still want the little history there is."""
    source = leaked_then_removed(tmp_path, name="source")
    target = tmp_path / "shallow"
    subprocess.run(["git", "clone", "-q", "--depth", "1",
                    source.as_uri(), str(target)],
                   check=True, capture_output=True, text=True)

    result = h.scan_history(target, allow_shallow=True)
    assert result.commits_scanned >= 1
    # Still not presented as a complete assessment.
    assert result.assessed is False


# ---------------------------------------------------------------------------
# Secrets are never emitted
# ---------------------------------------------------------------------------

def test_the_snippet_is_redacted(tmp_path):
    finding = by_rule(h.scan_history(leaked_then_removed(tmp_path)),
                      "SECRET-AWS-AKID")[0]
    assert AWS_KEY not in finding.snippet
    assert "REDACTED" in finding.snippet


def test_the_json_report_contains_no_secret_value(tmp_path):
    repo = leaked_then_removed(tmp_path)
    commit(repo, "add ci", {"ci.py": f'TOKEN = "{GH_PAT}"\n'})
    blob = json.dumps(h.json_report(h.scan_history(repo)))
    assert AWS_KEY not in blob
    assert GH_PAT not in blob


def test_the_fingerprint_is_a_hash_not_the_value(tmp_path):
    finding = by_rule(h.scan_history(leaked_then_removed(tmp_path)),
                      "SECRET-AWS-AKID")[0]
    assert len(finding.fingerprint) == 64
    assert AWS_KEY not in finding.fingerprint
    int(finding.fingerprint, 16)      # hex


# ---------------------------------------------------------------------------
# Scanner mechanics
# ---------------------------------------------------------------------------

def test_excluded_paths_are_skipped(tmp_path):
    repo = make_repo(tmp_path)
    (repo / "fixtures").mkdir()
    commit(repo, "leak in a fixture",
           {"fixtures/sample.py": f'K = "{AWS_KEY}"\n'})
    assert h.scan_history(repo).findings
    assert h.scan_history(repo, exclude=["fixtures/*"]).findings == []


def test_suppression_comment_is_honoured(tmp_path):
    repo = make_repo(tmp_path)
    commit(repo, "documented example",
           {"doc.py": f'K = "{AWS_KEY}"  # nosec documented example\n'})
    assert h.scan_history(repo).findings == []


def test_max_commits_bounds_the_walk(tmp_path):
    repo = leaked_then_removed(tmp_path)
    for index in range(3):
        commit(repo, f"later {index}", {f"f{index}.py": "x = 1\n"})
    bounded = h.scan_history(repo, max_commits=1)
    assert bounded.commits_scanned == 1
    # The old leak is outside the window, so it is not reported.
    assert by_rule(bounded, "SECRET-AWS-AKID") == []


def test_a_clean_repo_reports_nothing(tmp_path):
    repo = make_repo(tmp_path)
    commit(repo, "clean", {"app.py": "import os\nprint(os.getcwd())\n"})
    result = h.scan_history(repo)
    assert result.findings == []
    assert result.assessed is True
    assert result.commits_scanned == 1


def test_binary_files_do_not_break_the_walk(tmp_path):
    repo = make_repo(tmp_path)
    (repo / "blob.bin").write_bytes(bytes(range(256)) * 8)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "binary")
    commit(repo, "leak", {"c.py": f'K = "{AWS_KEY}"\n'})
    result = h.scan_history(repo)
    assert result.errors == []
    assert by_rule(result, "SECRET-AWS-AKID")


def test_secrets_on_a_branch_that_is_not_head_are_found(tmp_path):
    """--all is the point: anyone who clones gets every ref."""
    repo = make_repo(tmp_path)
    commit(repo, "base", {"app.py": "x = 1\n"})
    git(repo, "checkout", "-q", "-b", "feature")
    commit(repo, "leak on a branch", {"secret.py": f'K = "{AWS_KEY}"\n'})
    git(repo, "checkout", "-q", "-")

    result = h.scan_history(repo)
    assert by_rule(result, "SECRET-AWS-AKID")
    assert result.findings[0].present_in_head is False


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def test_severity_counts_and_threshold(tmp_path):
    result = h.scan_history(leaked_then_removed(tmp_path))
    assert h.severity_counts(result.findings)["CRITICAL"] == 1
    assert h.meets_threshold(result.findings, "critical") is True
    assert h.meets_threshold([], "low") is False


def test_threshold_rejects_an_unknown_severity():
    with pytest.raises(ValueError):
        h.meets_threshold([], "extremely-bad")


def test_the_report_says_rotation_is_the_fix(tmp_path):
    """Rewriting history is not the fix; the credential is already out."""
    report = h.text_report(h.scan_history(leaked_then_removed(tmp_path)))
    assert "Rotate the credential" in report
    assert "every existing clone" in report
    assert "filter-repo" in report


def test_the_report_distinguishes_the_two_states(tmp_path):
    repo = leaked_then_removed(tmp_path)
    commit(repo, "add ci", {"ci.py": f'TOKEN = "{GH_PAT}"\n'})
    report = h.text_report(h.scan_history(repo))
    assert "GONE FROM HEAD" in report
    assert "still in HEAD" in report
    assert "also reported by `scan code`" in report


def test_removed_only_view_hides_what_the_code_scan_covers(tmp_path):
    repo = leaked_then_removed(tmp_path)
    commit(repo, "add ci", {"ci.py": f'TOKEN = "{GH_PAT}"\n'})
    report = h.text_report(h.scan_history(repo), removed_only=True)
    assert "SECRET-AWS-AKID" in report
    assert "SECRET-GITHUB-PAT" not in report


def test_the_report_states_what_it_does_not_cover(tmp_path):
    report = h.text_report(h.scan_history(leaked_then_removed(tmp_path)))
    assert "reflog" in report
    assert "rotated cannot be determined" in report


def test_json_report_shape(tmp_path):
    payload = h.json_report(h.scan_history(leaked_then_removed(tmp_path)))
    assert payload["tool"] == "coldlight history"
    for key in ("repository", "assessed", "commits_scanned", "files_seen",
                "truncated", "severity_counts", "counts", "findings",
                "errors", "remediation", "limitations"):
        assert key in payload
    assert payload["assessed"] is True
    assert payload["counts"]["recoverable_only"] == 1
    assert json.loads(json.dumps(payload))["findings"]


def test_json_report_flags_an_unassessed_repo(tmp_path):
    source = leaked_then_removed(tmp_path, name="source")
    target = tmp_path / "shallow"
    subprocess.run(["git", "clone", "-q", "--depth", "1",
                    source.as_uri(), str(target)],
                   check=True, capture_output=True, text=True)
    payload = h.json_report(h.scan_history(target))
    assert payload["assessed"] is False
    assert payload["repository"]["shallow"] is True


def test_json_limitations_name_the_pii(tmp_path):
    """The report reproduces committer names and emails from the repo."""
    limitations = " ".join(
        h.json_report(h.scan_history(leaked_then_removed(tmp_path)))
        ["limitations"])
    assert "personal data" in limitations
    assert "reflog" in limitations


def test_findings_carry_provenance(tmp_path):
    result = h.scan_history(leaked_then_removed(tmp_path))
    assert result.findings
    assert all(f.severity_source == "coldlight-rule" for f in result.findings)
