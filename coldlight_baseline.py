#!/usr/bin/env python3
"""
ColdLight baseline / diff: report only what is NEW since the last accepted run.

WHY THIS EXISTS: `--fail-on high` is unadoptable without it. Point it at any
real codebase with an existing backlog and it fails on the first commit, so
nobody turns it on. With a baseline, the gate fails only on findings that
appeared since the backlog was accepted -- which is the behaviour teams
actually want and will leave enabled.

It also reports what was RESOLVED. Progress is as worth seeing as regression,
and a finding that silently disappears is also worth noticing.

THE HARD PART IS FINGERPRINTING. A baseline is worthless if irrelevant changes
break the match, so identity deliberately excludes volatile detail:

  * code findings key on rule + file + whitespace-normalised snippet, NOT the
    line number -- a line number shifts whenever anything above it is edited,
    which would make every refactor look like a wave of new findings
  * dependency findings key on vulnerability + ecosystem + package, NOT the
    installed version -- a version bump that does not fix the issue is still
    the same finding; one that does fix it disappears on its own
  * paths are normalised to posix and made relative to the scan root, so a CI
    runner and a developer laptop agree

Identical occurrences of one pattern in one file share a fingerprint, so
counts are tracked per fingerprint and an INCREASE is reported as new.

The baseline file is designed to be committed and reviewed: keys are readable,
not opaque hashes.

Stdlib only.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

BASELINE_VERSION = "1"
DEFAULT_BASELINE_PATH = ".coldlight/baseline.json"

SOURCE_DEPENDENCY = "dep"
SOURCE_CODE = "code"
SOURCE_MAIL = "mail"
SOURCE_AI = "ai"
SOURCE_HISTORY = "history"

SEVERITY_ORDER = {
    "CRITICAL": 6, "HIGH": 5, "MEDIUM": 4, "MODERATE": 4,
    "LOW": 3, "UNKNOWN": 2, "INFO": 1, "OK": 0, "": 0,
}


class BaselineError(ValueError):
    """The baseline file could not be used."""


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------

def normalise_path(path: str, root: str | Path | None = None) -> str:
    """Make a path comparable across machines: posix, relative to the root."""
    text = str(path or "").replace("\\", "/")
    if root:
        root_text = str(Path(root).resolve()).replace("\\", "/").rstrip("/")
        try:
            resolved = str(Path(path).resolve()).replace("\\", "/")
        except (OSError, ValueError):
            resolved = text
        for candidate in (resolved, text):
            if root_text and candidate.lower().startswith(root_text.lower() + "/"):
                return candidate[len(root_text) + 1:]
    return text.lstrip("./")


_WHITESPACE = re.compile(r"\s+")


def normalise_snippet(snippet: str) -> str:
    """Collapse whitespace so reformatting does not invent a new finding."""
    return _WHITESPACE.sub(" ", (snippet or "").strip())


def _short_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:10]


# ---------------------------------------------------------------------------
# Fingerprints
# ---------------------------------------------------------------------------

def vuln_fingerprint(finding) -> str:
    """Identity of a dependency finding: vulnerability + ecosystem + package.

    The installed version is excluded on purpose -- see the module docstring.
    """
    identifier = (getattr(finding, "identifier", "") or "").upper()
    ecosystem = getattr(finding, "ecosystem", "") or "-"
    package = (getattr(finding, "package", "") or "-").lower()
    return f"{SOURCE_DEPENDENCY}:{ecosystem}/{package}/{identifier}"


def code_fingerprint(finding, root: str | Path | None = None) -> str:
    """Identity of a code finding: rule + file + normalised snippet."""
    rule = getattr(finding, "rule_id", "") or "-"
    path = normalise_path(getattr(finding, "file", "") or "-", root)
    snippet = normalise_snippet(getattr(finding, "snippet", ""))
    suffix = f"#{_short_hash(snippet)}" if snippet else ""
    return f"{SOURCE_CODE}:{rule}@{path}{suffix}"


def mail_fingerprint(finding, domain: str = "") -> str:
    """Identity of an email-posture finding: domain + check + title."""
    check = getattr(finding, "check", "") or "-"
    title = getattr(finding, "title", "") or "-"
    return f"{SOURCE_MAIL}:{(domain or '-').lower()}/{check}/{title}"


def history_fingerprint(finding, root: str | Path | None = None) -> str:
    """Identity of a history finding: rule + file + the secret's own hash.

    The secret's fingerprint is already a content hash, so this is stable
    across rebases and reformatting -- the commit sha deliberately plays no
    part, or rewriting history would silently reset the baseline.
    """
    rule = getattr(finding, "rule_id", "") or "-"
    path = normalise_path(getattr(finding, "file", "") or "-", root)
    secret = getattr(finding, "fingerprint", "") or "-"
    return f"{SOURCE_HISTORY}:{rule}@{path}#{secret[:16]}"


def fingerprint_for(source: str, finding, *, root=None, domain="") -> str:
    if source == SOURCE_HISTORY:
        return history_fingerprint(finding, root)
    if source == SOURCE_AI:
        # Same identity rule as a code finding: rule + file + normalised
        # snippet, never the line number.
        return "ai:" + code_fingerprint(finding, root).split(":", 1)[1]
    if source == SOURCE_DEPENDENCY:
        return vuln_fingerprint(finding)
    if source == SOURCE_CODE:
        return code_fingerprint(finding, root)
    if source == SOURCE_MAIL:
        return mail_fingerprint(finding, domain)
    raise BaselineError(f"unknown baseline source: {source!r}")


def label_for(source: str, finding, *, root=None, domain="") -> str:
    """A short human-readable description, stored for review."""
    if source in (SOURCE_CODE, SOURCE_AI):
        title = getattr(finding, "title", "") or ""
        path = normalise_path(getattr(finding, "file", "") or "", root)
        line = getattr(finding, "line", "")
        return f"{title} — {path}:{line}"
    if source == SOURCE_DEPENDENCY:
        package = getattr(finding, "package", "") or ""
        version = getattr(finding, "installed_version", "") or ""
        identifier = getattr(finding, "identifier", "") or ""
        return f"{identifier} in {package} {version}".strip()
    if source == SOURCE_HISTORY:
        title = getattr(finding, "title", "") or ""
        path = normalise_path(getattr(finding, "file", "") or "", root)
        commit = (getattr(finding, "first_commit", "") or "")[:9]
        return f"{title} — {path} (introduced {commit})".strip()
    if source == SOURCE_MAIL:
        return f"{getattr(finding, 'title', '')} ({domain})".strip()
    return str(finding)


def severity_of(finding) -> str:
    return (getattr(finding, "severity", "") or "UNKNOWN").upper()


# ---------------------------------------------------------------------------
# Baseline file
# ---------------------------------------------------------------------------

@dataclass
class BaselineEntry:
    count: int = 1
    severity: str = "UNKNOWN"
    label: str = ""
    source: str = ""
    first_seen: str = ""


@dataclass
class Baseline:
    version: str = BASELINE_VERSION
    created: str = ""
    updated: str = ""
    entries: dict[str, BaselineEntry] = field(default_factory=dict)
    path: str = ""
    exists: bool = False

    def to_dict(self) -> dict:
        return {
            "coldlight_baseline_version": self.version,
            "created": self.created,
            "updated": self.updated,
            "entry_count": len(self.entries),
            "entries": {k: asdict(v) for k, v in sorted(self.entries.items())},
        }

    def count_for(self, fingerprint: str) -> int:
        entry = self.entries.get(fingerprint)
        return entry.count if entry else 0


def load_baseline(path: str | Path) -> Baseline:
    """Load a baseline. A missing file is not an error -- it yields an empty
    baseline marked `exists=False`, so the caller can say so plainly instead
    of silently passing everything."""
    file_path = Path(path)
    baseline = Baseline(path=str(file_path))

    if not file_path.is_file():
        return baseline

    try:
        data = json.loads(file_path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise BaselineError(f"{file_path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise BaselineError(f"{file_path}: expected a JSON object")

    version = str(data.get("coldlight_baseline_version", "") or "")
    if version and version != BASELINE_VERSION:
        raise BaselineError(
            f"{file_path} is baseline format v{version}; this build "
            f"understands v{BASELINE_VERSION}. Regenerate it with "
            f"--update-baseline."
        )

    baseline.exists = True
    baseline.version = version or BASELINE_VERSION
    baseline.created = str(data.get("created", "") or "")
    baseline.updated = str(data.get("updated", "") or "")

    for fingerprint, raw in (data.get("entries") or {}).items():
        if not isinstance(raw, dict):
            continue
        try:
            count = max(1, int(raw.get("count", 1) or 1))
        except (TypeError, ValueError):
            count = 1
        baseline.entries[str(fingerprint)] = BaselineEntry(
            count=count,
            severity=str(raw.get("severity", "UNKNOWN") or "UNKNOWN").upper(),
            label=str(raw.get("label", "") or ""),
            source=str(raw.get("source", "") or ""),
            first_seen=str(raw.get("first_seen", "") or ""),
        )
    return baseline


def save_baseline(baseline: Baseline, path: str | Path) -> None:
    file_path = Path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    baseline.updated = _now()
    baseline.created = baseline.created or baseline.updated
    # ensure_ascii=False keeps labels legible in a review diff rather than
    # escaping every non-ASCII character to \uXXXX.
    file_path.write_text(
        json.dumps(baseline.to_dict(), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def build_baseline(source: str, findings, *, root=None, domain="",
                   previous: Baseline | None = None) -> Baseline:
    """Create (or refresh) a baseline from the current findings.

    `first_seen` is carried over from a previous baseline so accepting new
    findings does not rewrite the history of the old ones.
    """
    baseline = Baseline()
    if previous is not None:
        baseline.created = previous.created

    today = _today()
    for finding in findings:
        fingerprint = fingerprint_for(source, finding, root=root, domain=domain)
        entry = baseline.entries.get(fingerprint)
        if entry is None:
            carried = previous.entries.get(fingerprint) if previous else None
            baseline.entries[fingerprint] = BaselineEntry(
                count=1,
                severity=severity_of(finding),
                label=label_for(source, finding, root=root, domain=domain),
                source=source,
                first_seen=(carried.first_seen if carried
                            and carried.first_seen else today),
            )
        else:
            entry.count += 1
            if (SEVERITY_ORDER.get(severity_of(finding), 0)
                    > SEVERITY_ORDER.get(entry.severity, 0)):
                entry.severity = severity_of(finding)
    return baseline


def merge_baseline(existing: Baseline, source: str, findings, *,
                   root=None, domain="") -> Baseline:
    """Add the current findings to an existing baseline, keeping other
    sources' entries intact.

    Without this, running `--update-baseline` for a code scan would discard
    the dependency entries sitting in the same file.
    """
    refreshed = build_baseline(source, findings, root=root, domain=domain,
                               previous=existing)
    merged = Baseline(created=existing.created or refreshed.created)
    # Keep every entry that this scan does not own.
    for fingerprint, entry in existing.entries.items():
        if entry.source != source and not fingerprint.startswith(f"{source}:"):
            merged.entries[fingerprint] = entry
    merged.entries.update(refreshed.entries)
    return merged


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------

@dataclass
class Diff:
    source: str = ""
    new: list = field(default_factory=list)          # findings
    existing: list = field(default_factory=list)     # findings
    resolved: list = field(default_factory=list)     # (fingerprint, entry)
    baseline_exists: bool = False
    baseline_updated: str = ""

    @property
    def total(self) -> int:
        return len(self.new) + len(self.existing)

    def new_meets(self, threshold: str) -> bool:
        floor = SEVERITY_ORDER.get((threshold or "").upper())
        if floor is None:
            raise ValueError(f"unknown severity threshold: {threshold!r}")
        return any(SEVERITY_ORDER.get(severity_of(f), 0) >= floor
                   for f in self.new)


def diff_findings(source: str, findings, baseline: Baseline, *,
                  root=None, domain="") -> Diff:
    """Split findings into new vs already-accepted, and list what is resolved.

    Occurrence counts matter: three hits on one fingerprint where the baseline
    accepted one means two are new.
    """
    diff = Diff(source=source, baseline_exists=baseline.exists,
                baseline_updated=baseline.updated)

    grouped: dict[str, list] = {}
    order: list[str] = []
    for finding in findings:
        fingerprint = fingerprint_for(source, finding, root=root, domain=domain)
        if fingerprint not in grouped:
            grouped[fingerprint] = []
            order.append(fingerprint)
        grouped[fingerprint].append(finding)

    for fingerprint in order:
        items = grouped[fingerprint]
        accepted = baseline.count_for(fingerprint)
        diff.existing.extend(items[:accepted])
        diff.new.extend(items[accepted:])

    for fingerprint, entry in sorted(baseline.entries.items()):
        # Only consider entries this scan could have produced.
        owns = entry.source == source or fingerprint.startswith(f"{source}:")
        if owns and fingerprint not in grouped:
            diff.resolved.append((fingerprint, entry))

    return diff


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def diff_report(diff: Diff, *, root=None, domain="",
                show_resolved: bool = True) -> str:
    out: list[str] = []

    if not diff.baseline_exists:
        out.append(f"No baseline found. All {diff.total} finding(s) are "
                   f"treated as new.")
        out.append("  Accept the current state as the baseline with "
                   "--update-baseline.")
        out.append("")
    else:
        accepted = (f" (accepted {diff.baseline_updated[:10]})"
                    if diff.baseline_updated else "")
        out.append(f"{diff.total} finding(s) total")
        out.append(f"  {len(diff.existing)} in baseline{accepted}")

    if diff.new:
        out.append(f"  {len(diff.new)} NEW since baseline:")
        for finding in sorted(
            diff.new,
            key=lambda f: -SEVERITY_ORDER.get(severity_of(f), 0),
        ):
            label = label_for(diff.source, finding, root=root, domain=domain)
            out.append(f"    {severity_of(finding):<9} {label}")
    elif diff.baseline_exists:
        out.append("  0 new since baseline")

    if show_resolved and diff.resolved:
        out.append("")
        out.append(f"  {len(diff.resolved)} RESOLVED since baseline "
                   f"(no longer present):")
        for _fingerprint, entry in diff.resolved[:20]:
            out.append(f"    {entry.severity:<9} {entry.label}")
        if len(diff.resolved) > 20:
            out.append(f"    ... and {len(diff.resolved) - 20} more")
        out.append("")
        out.append("  Refresh the baseline with --update-baseline so they are "
                   "not re-reported if they return.")

    return "\n".join(out)
