#!/usr/bin/env python3
"""
ColdLight secret scanning across git history.

`scan code` reads the working tree. That answers "is a credential in the code
now", which is the less interesting question -- the dangerous case is the key
someone committed, noticed, deleted in the next commit, and considered fixed.
It is still in the object store, still in every clone, and still valid. The
assurance ledger has been carrying that gap as an explicit NOT ASSESSED row;
this closes it.

THE DISTINCTION THIS MODULE EXISTS TO DRAW. Every finding says whether the
secret is still in HEAD:

  * still in HEAD      -- `scan code` already found it; same problem.
  * NOT in HEAD        -- the interesting one. Someone believes this was
                          dealt with. Deleting the line changed nothing: the
                          blob is reachable from history, so anyone with a
                          clone still has the credential.

THE FAILURE MODE THIS MODULE GUARDS AGAINST. A shallow clone has almost no
history, so scanning one finds almost nothing and looks like a clean result.
CI checkouts are shallow by default (`fetch-depth: 1`), which is exactly where
this would be run. A shallow repository is therefore reported as NOT ASSESSED
and exits non-zero -- it is never allowed to read as clean.

WHAT IS AND IS NOT COVERED. History reachable from any ref (`--all`), which is
what someone who clones the repository can recover. Not covered: dangling
objects from amended or rebased commits, and the local reflog -- neither
travels with a clone, so neither is what an outsider gets. Also not knowable
from here: whether the credential was ever rotated. A finding means the secret
is recoverable, not that it still authenticates.

SECRETS ARE NEVER EMITTED. Matches are redacted for display and reduced to a
SHA-256 fingerprint for grouping, so the report can say "the same key appears
in 14 commits" without the report itself becoming a place the key is written
down.

Stdlib only, plus the `git` binary. Read-only: nothing here writes to the
repository, and no command it runs can alter history.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from coldlight_codescan import MAX_LINE_LEN, SEVERITY_ORDER, SUPPRESS_RE, redact

__all__ = [
    "HistoryError", "GitUnavailable", "RepoState", "HistoryFinding",
    "HistoryScanResult", "secret_rules", "git_version", "repo_state",
    "scan_history", "severity_counts", "meets_threshold", "text_report",
    "json_report", "SEVERITY_SOURCE",
]

SEVERITY_SOURCE = "coldlight-rule"

_COMMIT_MARKER = "@@COLDLIGHT-COMMIT@@"
_SEP = "\x1f"

# Bounds, so a large repository cannot turn into an unbounded read.
MAX_OUTPUT_BYTES = 256 * 1024 * 1024
DEFAULT_TIMEOUT = 600
MAX_FINDINGS = 5000


class HistoryError(ValueError):
    """The repository cannot be scanned."""


class GitUnavailable(HistoryError):
    """`git` is not installed or not usable."""


# ---------------------------------------------------------------------------
# Rules: reuse, never duplicate
# ---------------------------------------------------------------------------

def secret_rules() -> list:
    """The secret-detection rules from the code and AI scanners.

    `redact=True` is what marks a rule as matching a credential rather than a
    risky pattern, so it is the selector. Keeping one rule table means a new
    provider token added for `scan code` is picked up here for free.
    """
    import coldlight_aisec as ai
    import coldlight_codescan as cs

    return [r for r in cs.RULES if r.redact] + [r for r in ai.RULES if r.redact]


def _fingerprint(text: str) -> str:
    """Identity of a secret, so the same key dedups across commits.

    Hashed rather than stored: grouping needs identity, not the value, and a
    report is not a place to write a credential down.
    """
    return hashlib.sha256(text.strip().encode("utf-8", "replace")).hexdigest()


# ---------------------------------------------------------------------------
# Talking to git
# ---------------------------------------------------------------------------

def _run(args: list[str], cwd: str | Path, *, timeout: int = 30) -> str:
    try:
        completed = subprocess.run(
            ["git", *args], cwd=str(cwd), capture_output=True, text=True,
            timeout=timeout, check=False,
            encoding="utf-8", errors="replace",
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0",
                 "GIT_OPTIONAL_LOCKS": "0"},
        )
    except FileNotFoundError:
        raise GitUnavailable(
            "git is not installed or not on PATH, so version history cannot "
            "be read. Install git, or run this where the repository lives."
        ) from None
    except subprocess.TimeoutExpired:
        raise HistoryError(f"git {args[0]} timed out") from None
    if completed.returncode != 0:
        raise HistoryError((completed.stderr or completed.stdout or "").strip()
                           or f"git {' '.join(args)} failed")
    return completed.stdout


def git_version() -> str:
    """The git version string, or raise GitUnavailable."""
    if shutil.which("git") is None:
        raise GitUnavailable(
            "git is not installed or not on PATH, so version history cannot "
            "be read."
        )
    return _run(["--version"], ".").strip()


@dataclass
class RepoState:
    path: str = ""
    is_repo: bool = False
    shallow: bool = False
    commits: int = 0
    refs: int = 0
    head: str = ""
    git_version: str = ""
    error: str = ""

    @property
    def scannable(self) -> bool:
        return self.is_repo and not self.shallow and self.commits > 0

    def to_dict(self) -> dict:
        return asdict(self)


def repo_state(path: str | Path) -> RepoState:
    """Describe the repository without scanning it."""
    state = RepoState(path=str(path))
    try:
        state.git_version = git_version()
    except GitUnavailable as exc:
        state.error = str(exc)
        return state

    target = Path(path)
    if not target.is_dir():
        state.error = f"not a directory: {target}"
        return state

    try:
        inside = _run(["rev-parse", "--is-inside-work-tree"], target).strip()
    except HistoryError as exc:
        state.error = (f"{target} is not a git repository, so there is no "
                       f"history to read ({exc})")
        return state
    if inside != "true":
        state.error = f"{target} is not inside a git work tree"
        return state
    state.is_repo = True

    try:
        state.shallow = _run(
            ["rev-parse", "--is-shallow-repository"], target).strip() == "true"
    except HistoryError:
        state.shallow = (target / ".git" / "shallow").exists()

    try:
        state.commits = int(_run(["rev-list", "--all", "--count"],
                                 target).strip() or 0)
    except (HistoryError, ValueError):
        state.commits = 0

    try:
        state.refs = len([line for line in _run(
            ["for-each-ref", "--format=%(refname)"], target).splitlines()
            if line.strip()])
    except HistoryError:
        state.refs = 0

    try:
        state.head = _run(["rev-parse", "--short", "HEAD"], target).strip()
    except HistoryError:
        state.head = ""

    if state.shallow:
        state.error = (
            "this is a SHALLOW clone: history has been truncated, so a scan "
            "of it would find almost nothing and prove almost nothing. Fetch "
            "the full history (git fetch --unshallow, or checkout with "
            "fetch-depth: 0) before scanning."
        )
    elif state.commits == 0:
        state.error = "the repository has no commits yet"
    return state


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

@dataclass
class HistoryFinding:
    rule_id: str
    severity: str
    title: str
    cwe: str
    file: str
    snippet: str                     # redacted
    fingerprint: str                 # sha256 of the matched secret
    first_commit: str = ""           # oldest commit that introduced it
    first_commit_at: str = ""
    first_author: str = ""
    last_commit: str = ""            # newest commit containing it
    last_commit_at: str = ""
    commit_count: int = 0
    present_in_head: bool = False
    remediation: str = ""
    severity_source: str = SEVERITY_SOURCE

    @property
    def recoverable_only(self) -> bool:
        """Gone from the working tree, still in the object store."""
        return not self.present_in_head

    @property
    def rank(self) -> tuple:
        # Secrets no longer in HEAD sort first: they are the ones nobody is
        # looking at any more.
        return (-SEVERITY_ORDER.get(self.severity.upper(), 0),
                0 if self.recoverable_only else 1, self.file, self.rule_id)

    def to_dict(self) -> dict:
        payload = asdict(self)
        payload["recoverable_only"] = self.recoverable_only
        return payload


@dataclass
class HistoryScanResult:
    state: RepoState = field(default_factory=RepoState)
    findings: list[HistoryFinding] = field(default_factory=list)
    commits_scanned: int = 0
    files_seen: int = 0
    truncated: str = ""             # why the walk stopped early, if it did
    errors: list[str] = field(default_factory=list)

    @property
    def assessed(self) -> bool:
        """False when nothing was actually examined.

        A shallow clone, a missing git, or a bailed-out walk must never be
        presented as a repository with no secrets in it.
        """
        return self.state.scannable and not self.truncated

    @property
    def recoverable_only(self) -> list[HistoryFinding]:
        return [f for f in self.findings if f.recoverable_only]

    @property
    def still_in_head(self) -> list[HistoryFinding]:
        return [f for f in self.findings if f.present_in_head]


# ---------------------------------------------------------------------------
# The walk
# ---------------------------------------------------------------------------

def _log_args(max_commits: int | None, since: str) -> list[str]:
    args = [
        "log", "--all", "--full-history", "--no-color",
        "--no-textconv", "--no-ext-diff", "--no-renames",
        "--diff-filter=AM", "-U0", "-p",
        f"--format={_COMMIT_MARKER}%H{_SEP}%aI{_SEP}%an <%ae>",
    ]
    if max_commits:
        args.append(f"--max-count={int(max_commits)}")
    if since:
        args.append(f"--since={since}")
    return args


def _head_secret_fingerprints(path: Path, files: set[str],
                              rules: list) -> dict[str, set[str]]:
    """Per file, the fingerprints of secrets still present in HEAD.

    Used to answer "did deleting the line actually remove it", which is the
    question the whole module turns on.

    Keyed BY FILE, not pooled: the same credential often appears in several
    files, and a pooled set would mark a secret deleted from one file as
    still present because a different file still holds it -- hiding exactly
    the finding this module exists to surface.
    """
    found: dict[str, set[str]] = {}
    for name in sorted(files):
        try:
            blob = _run(["show", f"HEAD:{name}"], path, timeout=30)
        except HistoryError:
            continue        # deleted in HEAD, or unreadable -- not present
        hits: set[str] = set()
        for line in blob.splitlines():
            if len(line) > MAX_LINE_LEN:
                continue
            for rule in rules:
                match = rule.pattern.search(line)
                if match:
                    hits.add(_fingerprint(match.group(0)))
        found[name] = hits
    return found


def scan_history(path: str | Path, *, max_commits: int | None = None,
                 since: str = "", exclude: list[str] | None = None,
                 timeout: int = DEFAULT_TIMEOUT,
                 max_output_bytes: int = MAX_OUTPUT_BYTES,
                 allow_shallow: bool = False) -> HistoryScanResult:
    """Scan reachable git history for committed secrets. Read-only."""
    from coldlight_codescan import is_excluded

    target = Path(path)
    result = HistoryScanResult(state=repo_state(target))

    if not result.state.is_repo:
        raise HistoryError(result.state.error or
                           f"{target} is not a git repository")
    if result.state.commits == 0:
        return result
    if result.state.shallow and not allow_shallow:
        # Deliberately not a scan-with-a-warning: a truncated history that
        # finds nothing is indistinguishable from a clean one.
        return result

    rules = secret_rules()
    grouped: dict[tuple, HistoryFinding] = {}
    files_with_hits: set[str] = set()
    seen_files: set[str] = set()
    seen_commits: set[str] = set()

    commit = commit_at = author = ""
    current_file = ""
    read_bytes = 0
    started = time.monotonic()

    try:
        process = subprocess.Popen(
            ["git", *_log_args(max_commits, since)], cwd=str(target),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            encoding="utf-8", errors="replace", bufsize=1,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0",
                 "GIT_OPTIONAL_LOCKS": "0"},
        )
    except FileNotFoundError:
        raise GitUnavailable("git is not installed or not on PATH") from None

    try:
        for line in process.stdout:
            read_bytes += len(line)
            if read_bytes > max_output_bytes:
                result.truncated = (
                    f"stopped after {read_bytes // (1024 * 1024)} MiB of diff "
                    f"output; the history was not read to the end")
                break
            if time.monotonic() - started > timeout:
                result.truncated = (
                    f"stopped after {timeout}s; the history was not read to "
                    f"the end")
                break

            if line.startswith(_COMMIT_MARKER):
                parts = line[len(_COMMIT_MARKER):].rstrip("\n").split(_SEP)
                commit = parts[0] if parts else ""
                commit_at = parts[1] if len(parts) > 1 else ""
                author = parts[2] if len(parts) > 2 else ""
                if commit:
                    seen_commits.add(commit)
                current_file = ""
                continue

            if line.startswith("diff --git "):
                # "diff --git a/x b/x" -- take the b-side path.
                tail = line[len("diff --git "):].rstrip("\n")
                marker = " b/"
                index = tail.rfind(marker)
                current_file = (tail[index + len(marker):] if index != -1
                                else "")
                if current_file:
                    seen_files.add(current_file)
                continue

            if not line.startswith("+") or line.startswith("+++"):
                continue
            if not current_file or not commit:
                continue
            if exclude and is_excluded(target / current_file, target, exclude):
                continue

            content = line[1:].rstrip("\n")
            if len(content) > MAX_LINE_LEN or SUPPRESS_RE.search(content):
                continue

            for rule in rules:
                match = rule.pattern.search(content)
                if not match:
                    continue
                fingerprint = _fingerprint(match.group(0))
                key = (rule.rule_id, current_file, fingerprint)
                existing = grouped.get(key)
                if existing is None:
                    if len(grouped) >= MAX_FINDINGS:
                        result.truncated = (
                            f"stopped after {MAX_FINDINGS} distinct findings")
                        break
                    grouped[key] = HistoryFinding(
                        rule_id=rule.rule_id, severity=rule.severity,
                        title=rule.title, cwe=rule.cwe, file=current_file,
                        snippet=redact(content).strip()[:200],
                        fingerprint=fingerprint,
                        first_commit=commit, first_commit_at=commit_at,
                        first_author=author,
                        last_commit=commit, last_commit_at=commit_at,
                        commit_count=1,
                        remediation=rule.remediation,
                    )
                    files_with_hits.add(current_file)
                else:
                    existing.commit_count += 1
                    # git log walks newest first, so each later sighting is
                    # older: it becomes the introducing commit.
                    existing.first_commit = commit
                    existing.first_commit_at = commit_at
                    existing.first_author = author
            if result.truncated:
                break
    finally:
        if process.stdout:
            process.stdout.close()
        if result.truncated:
            process.kill()
        stderr = ""
        try:
            stderr = (process.stderr.read() or "") if process.stderr else ""
        except (ValueError, OSError):
            stderr = ""
        if process.stderr:
            process.stderr.close()
        process.wait()
        if process.returncode not in (0, None) and not result.truncated:
            message = stderr.strip().splitlines()[-1] if stderr.strip() else ""
            if message:
                result.errors.append(f"git log: {message}")

    result.commits_scanned = len(seen_commits)
    result.files_seen = len(seen_files)
    result.findings = list(grouped.values())

    # The decisive question: is it still in the working tree, or did someone
    # delete the line and move on?
    if result.findings:
        try:
            in_head = _head_secret_fingerprints(target, files_with_hits, rules)
        except HistoryError as exc:
            in_head = {}
            result.errors.append(f"could not read HEAD: {exc}")
        for finding in result.findings:
            finding.present_in_head = (
                finding.fingerprint in in_head.get(finding.file, frozenset()))

    result.findings.sort(key=lambda f: f.rank)
    return result


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def severity_counts(findings: list[HistoryFinding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        key = finding.severity.upper()
        counts[key] = counts.get(key, 0) + 1
    return counts


def meets_threshold(findings: list[HistoryFinding], threshold: str) -> bool:
    floor = SEVERITY_ORDER.get((threshold or "").upper())
    if floor is None:
        raise ValueError(f"unknown severity threshold: {threshold!r}")
    return any(SEVERITY_ORDER.get(f.severity.upper(), 0) >= floor
               for f in findings)


_ROTATE_FIRST = (
    "Rotate the credential at the provider. That is the fix, and it is the "
    "only step that helps: the blob stays reachable in every existing clone "
    "and fork whatever you do to this repository afterwards. Rewriting "
    "history (git filter-repo) changes what future clones get, needs every "
    "collaborator to re-clone, and does nothing about copies already taken."
)


def text_report(result: HistoryScanResult, *,
                removed_only: bool = False) -> str:
    out: list[str] = []
    out.append("=" * 70)
    out.append("ColdLight secret scan of git history")
    out.append("=" * 70)

    state = result.state
    out.append(f"repository      : {state.path}")
    if state.git_version:
        out.append(f"git             : {state.git_version}")
    out.append(f"commits         : {state.commits}"
               + (f" ({result.commits_scanned} walked)"
                  if result.commits_scanned else ""))
    out.append(f"refs            : {state.refs}")

    if not state.scannable:
        out.append("")
        out.append("NOT ASSESSED")
        out.append(f"  {state.error or 'the repository could not be read'}")
        out.append("")
        out.append("This is NOT a clean result. Nothing was examined, so no "
                   "conclusion about committed secrets can be drawn.")
        return "\n".join(out)

    findings = (result.recoverable_only if removed_only else result.findings)
    out.append(f"files touched   : {result.files_seen}")
    out.append(f"findings        : {len(findings)}")

    counts = severity_counts(findings)
    if counts:
        ordered = sorted(counts.items(),
                         key=lambda kv: -SEVERITY_ORDER.get(kv[0], 0))
        out.append("  by severity   : "
                   + ", ".join(f"{k.lower()}={v}" for k, v in ordered))
    if not removed_only and result.findings:
        out.append(f"  gone from HEAD: {len(result.recoverable_only)} "
                   f"(still recoverable from history)")
        out.append(f"  still in HEAD : {len(result.still_in_head)} "
                   f"(also reported by `scan code`)")

    if result.truncated:
        out.append("")
        out.append(f"!! INCOMPLETE: {result.truncated}")
        out.append("   Treat the findings as a floor, not a total.")

    if findings:
        out.append("")
        for finding in findings:
            status = ("GONE FROM HEAD -- still in history"
                      if finding.recoverable_only else "still in HEAD")
            out.append(f"{finding.severity.upper():<9} {finding.cwe:<10} "
                       f"{finding.title}  [{finding.rule_id}]")
            out.append(f"          {finding.file}  ({status})")
            short = finding.first_commit[:12]
            out.append(f"          introduced {short} "
                       f"{finding.first_commit_at}  by {finding.first_author}")
            if finding.commit_count > 1:
                out.append(f"          appears in {finding.commit_count} "
                           f"commits")
            out.append(f"              | {finding.snippet}")
            out.append("")

        out.append("Remediation")
        out.append(f"  {_ROTATE_FIRST}")
        out.append("")

    if result.errors:
        out.append(f"{len(result.errors)} error(s):")
        for error in result.errors[:10]:
            out.append(f"  - {error}")
        out.append("")

    out.append("Scope: history reachable from any ref -- what someone with a "
               "clone can recover. Dangling objects from amended or rebased "
               "commits and the local reflog are not included; neither "
               "travels with a clone. Whether a credential was rotated cannot "
               "be determined from here, so a finding means recoverable, not "
               "necessarily still valid.")
    return "\n".join(out)


def json_report(result: HistoryScanResult) -> dict:
    return {
        "tool": "coldlight history",
        "repository": result.state.to_dict(),
        "assessed": result.assessed,
        "commits_scanned": result.commits_scanned,
        "files_seen": result.files_seen,
        "truncated": result.truncated,
        "severity_counts": severity_counts(result.findings),
        "counts": {
            "findings": len(result.findings),
            "recoverable_only": len(result.recoverable_only),
            "still_in_head": len(result.still_in_head),
        },
        "findings": [f.to_dict() for f in result.findings],
        "errors": result.errors,
        "remediation": _ROTATE_FIRST,
        "limitations": [
            "History reachable from refs only. Dangling objects from amended "
            "or rebased commits and the local reflog are not scanned; neither "
            "travels with a clone.",
            "Whether a credential was rotated cannot be determined from the "
            "repository, so a finding means the secret is recoverable, not "
            "that it still authenticates.",
            "Secrets are redacted and reduced to a SHA-256 fingerprint; the "
            "values are not recorded in this report.",
            "Commit author names and email addresses are reproduced from the "
            "repository and are personal data -- handle this report "
            "accordingly.",
        ],
    }
