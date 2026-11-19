#!/usr/bin/env python3
"""
ColdLight assess: one command that runs the whole assessment.

A full engagement is otherwise five commands plus `engagement`, and you have to
remember the wiring between them. This runs every configured stage in order,
writes each stage's JSON so every number in the report is traceable back to the
scan that produced it, applies baselines, builds the report, and exits on the
worst gate.

    coldlight assess --profile assessment.toml
    coldlight assess --code . --deps . --domain corp.example.com --out-dir out

THE RULE THIS MODULE EXISTS TO ENFORCE: a stage that FAILED must never read as
a stage that found nothing. If DNS is down, the mail stage fails -- and the
report says so in its limitations rather than quietly omitting a whole category
and showing a lower finding count. Silent partial coverage is the one outcome
worse than an error, because the reader cannot tell the difference between
"we checked and it was fine" and "we never checked".

So: no stage can abort the run, every failure is recorded, and the failures are
carried into the report AND the exit code.

Exit codes:
    0  every stage ran, no gate tripped
    1  a gate tripped (findings at or above the configured severity)
    2  configuration error, or one or more stages failed -- the assessment is
       incomplete, which takes precedence over the findings gate

Stdlib only.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

STAGE_OK = "ok"
STAGE_FAILED = "failed"
STAGE_SKIPPED = "skipped"

PROFILE_TEMPLATE = '''# ColdLight assessment profile.
#
#   coldlight assess --profile assessment.toml
#
# Every section is optional: configure only the stages you want to run.
# Any stage that fails is reported as NOT ASSESSED rather than as clean.

[assessment]
client = "CHANGE-ME Client"
title = "CHANGE-ME Client — Security Assessment"
period = "2026-11-01 to 2026-11-14"
engagement_id = "CHANGE-ME-ENGAGEMENT-ID"
authorization_reference = "CHANGE-ME"
assessor = "Offensive Unicorn Crew"
scope = ["the-product 1.0", "corp.example.com"]

# --- stages -----------------------------------------------------------------

[stages.deps]
# Directories to walk for dependency manifests.
paths = ["."]

# [stages.sbom]
# CycloneDX or SPDX files -- lets you assess an artifact you did not build.
# files = ["bom.json"]

[stages.code]
paths = ["."]
exclude = ["tests/*"]

[stages.ai]
# AI/ML code and model artifacts: unsafe deserialisation (torch.load, pickle),
# prompt-injection sinks, agent tool permissions, provider credentials.
# Static only -- no model is prompted, probed or adversarially tested.
paths = ["."]
# Omit to inherit the code stage's exclude list.
# exclude = ["tests/*"]

# [stages.history]
# Secrets committed to git history, including ones later deleted from the
# working tree. Needs the FULL history -- a shallow clone is reported as NOT
# ASSESSED rather than clean.
# paths = ["."]
# allow_shallow = false

# [stages.probe]
# Benign canary probing of a live AI endpoint. Requires a scope file whose
# targets include the endpoint -- without one, nothing is sent. See
# `coldlight scope --init scope.toml`.
# scope = "scope.toml"

# [stages.ioc]
# Host-observable markers from a published indicator pack: file contents, file
# paths, file digests (SHA-256), ports declared in configuration, images a
# manifest deploys. The digest surface reads every byte of every file, so it
# is the slowest of the five on a large tree. Both keys
# are required -- a pack with nothing to scan, and a path with no pack, each
# produce a clean-looking report of a search that never happened, so either on
# its own is a configuration error.
# paths = ["."]
# packs = ["packs/exampletool.toml"]
# NOT inherited from the code stage, unlike the AI stage's exclude list: a
# pattern added to quieten code-scan noise would also hide a planted artifact.
# exclude = []
# Days before a pack counts as unrefreshed in the coverage ledger (default 90).
# stale_after = 90

[stages.mail]
domains = ["corp.example.com"]
# false = skip the MTA-STS policy fetch (DNS only)
fetch_policy = true

# [stages.awareness]
# Results from an awareness campaign (hostnames/usernames -- handle as PII).
# db = "hits.db"

[stages.detect]
# Also emit the purple-team deliverables: Sigma rules, ATT&CK layer, checklist.
enabled = true

# --- triage -----------------------------------------------------------------

# [vex]
# Records marked not_affected / fixed here move to an appendix instead of
# padding the finding count.
# triage = "vex_triage.json"

# --- gates ------------------------------------------------------------------

[gates]
# critical | high | medium | low
fail_on = "high"
# With a baseline, the gate trips only on findings NEW since it was accepted.
baseline = ".coldlight/baseline.json"

# --- output -----------------------------------------------------------------

[output]
dir = "assessment"
formats = ["html", "md"]
'''


class AssessError(ValueError):
    """The profile or the requested stages are not usable."""


# ---------------------------------------------------------------------------
# Profile
# ---------------------------------------------------------------------------

@dataclass
class Profile:
    # metadata
    client: str = ""
    title: str = ""
    period: str = ""
    engagement_id: str = ""
    authorization_reference: str = ""
    assessor: str = ""
    scope: list[str] = field(default_factory=list)
    # stages
    deps_paths: list[str] = field(default_factory=list)
    sbom_files: list[str] = field(default_factory=list)
    code_paths: list[str] = field(default_factory=list)
    code_exclude: list[str] = field(default_factory=list)
    ai_paths: list[str] = field(default_factory=list)
    ai_exclude: list[str] = field(default_factory=list)
    probe_scope: str = ""
    history_paths: list[str] = field(default_factory=list)
    history_allow_shallow: bool = False
    ioc_paths: list[str] = field(default_factory=list)
    ioc_packs: list[str] = field(default_factory=list)
    ioc_exclude: list[str] = field(default_factory=list)
    # None = the ioc module's own window. Not 0: `--stale-after 0` means
    # every pack older than today is stale, so 0 has to survive to the scan
    # rather than being read as "unset" and widened to ninety days.
    ioc_stale_after: int | None = None
    mail_domains: list[str] = field(default_factory=list)
    mail_fetch_policy: bool = True
    awareness_db: str = ""
    detect_enabled: bool = False
    # triage / gates / output
    vex_triage: str = ""
    fail_on: str = ""
    baseline: str = ""
    out_dir: str = "assessment"
    formats: list[str] = field(default_factory=lambda: ["html"])
    workers: int = 8

    @property
    def configured_stages(self) -> list[str]:
        stages = []
        if self.deps_paths:
            stages.append("dependencies")
        if self.sbom_files:
            stages.append("sbom")
        if self.code_paths:
            stages.append("source code")
        if self.ai_paths:
            stages.append("AI/ML systems")
        if self.history_paths:
            stages.append("git history")
        # Both halves, because either alone is refused by validate_profile
        # rather than run: a stage that searched nowhere, or searched for
        # nothing, reports the same "no markers" as a clean one.
        if self.ioc_packs and self.ioc_paths:
            stages.append("indicators")
        if self.probe_scope:
            stages.append("AI runtime behaviour")
        if self.mail_domains:
            stages.append("email posture")
        if self.awareness_db:
            stages.append("awareness")
        if self.detect_enabled:
            stages.append("detection artifacts")
        return stages

    def to_dict(self) -> dict:
        return asdict(self)


def _as_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return [str(v) for v in value]


def load_profile(path: str | Path) -> Profile:
    """Load an assessment profile from TOML."""
    import tomllib

    file_path = Path(path)
    if not file_path.is_file():
        raise AssessError(f"no such profile: {file_path}")
    try:
        data = tomllib.loads(file_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - tomllib raises its own type
        raise AssessError(f"{file_path} is not valid TOML: {exc}") from exc

    meta = data.get("assessment", {}) or {}
    stages = data.get("stages", {}) or {}
    deps = stages.get("deps", {}) or {}
    sbom = stages.get("sbom", {}) or {}
    code = stages.get("code", {}) or {}
    ai_stage = stages.get("ai", {}) or {}
    probe = stages.get("probe", {}) or {}
    ioc = stages.get("ioc", {}) or {}
    history = stages.get("history", {}) or {}
    mail = stages.get("mail", {}) or {}
    awareness = stages.get("awareness", {}) or {}
    detect = stages.get("detect", {}) or {}
    vex = data.get("vex", {}) or {}
    gates = data.get("gates", {}) or {}
    output = data.get("output", {}) or {}

    return Profile(
        client=str(meta.get("client", "") or ""),
        title=str(meta.get("title", "") or ""),
        period=str(meta.get("period", "") or ""),
        engagement_id=str(meta.get("engagement_id", "") or ""),
        authorization_reference=str(meta.get("authorization_reference", "") or ""),
        assessor=str(meta.get("assessor", "") or ""),
        scope=_as_list(meta.get("scope")),
        deps_paths=_as_list(deps.get("paths")),
        sbom_files=_as_list(sbom.get("files")),
        code_paths=_as_list(code.get("paths")),
        code_exclude=_as_list(code.get("exclude")),
        ai_paths=_as_list(ai_stage.get("paths")),
        ai_exclude=_as_list(ai_stage.get("exclude")),
        probe_scope=str(probe.get("scope", "") or ""),
        ioc_paths=_as_list(ioc.get("paths")),
        ioc_packs=_as_list(ioc.get("packs")),
        ioc_exclude=_as_list(ioc.get("exclude")),
        ioc_stale_after=(int(ioc["stale_after"])
                         if ioc.get("stale_after") is not None else None),
        history_paths=_as_list(history.get("paths")),
        history_allow_shallow=bool(history.get("allow_shallow", False)),
        mail_domains=_as_list(mail.get("domains")),
        mail_fetch_policy=bool(mail.get("fetch_policy", True)),
        awareness_db=str(awareness.get("db", "") or ""),
        detect_enabled=bool(detect.get("enabled", False)),
        vex_triage=str(vex.get("triage", "") or ""),
        fail_on=str(gates.get("fail_on", "") or ""),
        baseline=str(gates.get("baseline", "") or ""),
        out_dir=str(output.get("dir", "assessment") or "assessment"),
        formats=_as_list(output.get("formats")) or ["html"],
    )


def merge_args(profile: Profile, args) -> Profile:
    """CLI flags override the profile, so a profile can be a starting point."""
    def pick(attr, value, *, is_list=False):
        if value:
            setattr(profile, attr, list(value) if is_list else value)

    pick("deps_paths", getattr(args, "deps", None), is_list=True)
    pick("sbom_files", getattr(args, "sbom", None), is_list=True)
    pick("code_paths", getattr(args, "code", None), is_list=True)
    pick("code_exclude", getattr(args, "exclude", None), is_list=True)
    pick("ai_paths", getattr(args, "ai", None), is_list=True)
    pick("probe_scope", getattr(args, "probe_scope", None))
    pick("ioc_paths", getattr(args, "ioc", None), is_list=True)
    pick("ioc_packs", getattr(args, "ioc_pack", None), is_list=True)
    pick("history_paths", getattr(args, "history", None), is_list=True)
    pick("mail_domains", getattr(args, "domain", None), is_list=True)
    pick("awareness_db", getattr(args, "hits", None))
    pick("vex_triage", getattr(args, "vex", None))
    pick("fail_on", getattr(args, "fail_on", None))
    pick("baseline", getattr(args, "baseline", None))
    pick("out_dir", getattr(args, "out_dir", None))
    pick("client", getattr(args, "client", None))
    pick("title", getattr(args, "title", None))
    pick("period", getattr(args, "period", None))
    pick("assessor", getattr(args, "assessor", None))
    pick("engagement_id", getattr(args, "engagement_id", None))
    pick("authorization_reference", getattr(args, "authorization", None))
    pick("scope", getattr(args, "scope", None), is_list=True)
    pick("formats", getattr(args, "format", None), is_list=True)

    if getattr(args, "detect", False):
        profile.detect_enabled = True
    if getattr(args, "no_fetch", False):
        profile.mail_fetch_policy = False
    if getattr(args, "workers", None):
        profile.workers = args.workers
    return profile


def validate_profile(profile: Profile) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []

    if not profile.configured_stages:
        errors.append(
            "no stages configured: set at least one of deps, sbom, code, ai, "
            "mail or awareness (or pass --deps/--code/--ai/--domain/--hits)"
        )

    # Half a configured indicator stage is refused, not quietly skipped.
    # Both halves are needed before anything is looked for, and the output of
    # looking for nothing is indistinguishable from the output of finding
    # nothing.
    if profile.ioc_packs and not profile.ioc_paths:
        errors.append(
            "stages.ioc declares pack(s) but no paths: there would be "
            "nothing to scan, and a stage that searched nowhere reports the "
            "same 'no markers found' as a clean one")
    if profile.ioc_paths and not profile.ioc_packs:
        errors.append(
            "stages.ioc declares paths but no packs: nothing would be looked "
            "for, and the result would be indistinguishable from a clean one")
    if profile.ioc_stale_after is not None and profile.ioc_stale_after < 0:
        errors.append("stages.ioc stale_after cannot be negative; omit it "
                      "for the default window")

    valid_formats = {"html", "md", "json"}
    unknown = [f for f in profile.formats if f not in valid_formats]
    if unknown:
        errors.append(f"unknown output format(s): {', '.join(unknown)}; "
                      f"expected html, md or json")

    if profile.fail_on:
        from coldlight_baseline import SEVERITY_ORDER
        if profile.fail_on.upper() not in SEVERITY_ORDER:
            errors.append(f"gates.fail_on {profile.fail_on!r} is not a "
                          f"severity")

    for marker in ("CHANGE-ME",):
        if marker in profile.engagement_id or marker in profile.client:
            warnings.append("engagement_id/client still contain CHANGE-ME "
                            "placeholders")
    if not profile.authorization_reference:
        warnings.append("no authorization_reference: the report will not state "
                        "what authorised this assessment")
    return errors, warnings


# ---------------------------------------------------------------------------
# Stage results
# ---------------------------------------------------------------------------

@dataclass
class StageResult:
    name: str
    status: str = STAGE_OK
    summary: str = ""
    error: str = ""
    artifacts: list[str] = field(default_factory=list)
    findings: int = 0
    new_findings: int | None = None     # set only when a baseline was used
    gate_tripped: bool = False

    @property
    def ok(self) -> bool:
        return self.status == STAGE_OK

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AssessmentRun:
    profile: Profile
    stages: list[StageResult] = field(default_factory=list)
    report_paths: list[str] = field(default_factory=list)
    report = None                        # coldlight_engagement.Report
    ledger = None                        # coldlight_assurance.Ledger
    gate_tripped: bool = False
    gate_detail: str = ""

    @property
    def failed(self) -> list[StageResult]:
        return [s for s in self.stages if s.status == STAGE_FAILED]

    @property
    def exit_code(self) -> int:
        # An incomplete assessment outranks the findings gate: the reader
        # cannot trust totals from a run that did not finish.
        if self.failed:
            return 2
        return 1 if self.gate_tripped else 0

    def limitations(self) -> list[str]:
        """What the report must say about stages that did not complete."""
        notes = []
        for stage in self.stages:
            if stage.status == STAGE_FAILED:
                notes.append(
                    f"The {stage.name} stage FAILED and was not assessed "
                    f"({stage.error}). Treat that area as UNKNOWN, not as "
                    f"clean -- no finding from it appears in this report."
                )
            elif stage.status == STAGE_SKIPPED and stage.error:
                notes.append(f"The {stage.name} stage was skipped: "
                             f"{stage.error}")
        return notes


# ---------------------------------------------------------------------------
# Stage runners
# ---------------------------------------------------------------------------

def _write_json(path: Path, payload: dict) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return str(path)


# Artifact filename prefixes, so a stage can clear its own stale output.
_ARTIFACT_PREFIX = {
    "dependencies": "deps",
    "sbom": "sbom",
    "source code": "code",
    "AI/ML systems": "ai",
    "git history": "history",
    "AI runtime behaviour": "probe",
    "email posture": "mail",
    # The stage is named for what it reports; the artifact keeps the command's
    # name, which is what the coverage ledger globs for.
    "indicators": "ioc",
}


def _clear_stage_artifacts(name: str, out_dir: Path) -> None:
    """Delete a stage's artifacts from any previous run.

    Without this, a stage that fails leaves yesterday's JSON sitting in the
    output directory. This run's report would not use it (only successful
    stages are read), but anyone globbing `out/*.json` afterwards -- or
    re-running `engagement --mail out/mail.json` -- would silently mix in data
    from a different assessment. The output directory must only ever contain
    results from the run that produced it.
    """
    prefix = _ARTIFACT_PREFIX.get(name)
    if not prefix:
        return
    for path in sorted(out_dir.glob(f"{prefix}*.json")):
        try:
            path.unlink()
        except OSError:
            pass


def _gate_counts(source: str, findings, profile: Profile, *, root=None,
                 domain="") -> tuple[int, int | None, bool]:
    """Return (total, new_or_None, gate_tripped) for one stage."""
    import coldlight_baseline as bl

    total = len(findings)
    if not profile.baseline:
        tripped = False
        if profile.fail_on:
            floor = bl.SEVERITY_ORDER.get(profile.fail_on.upper(), 0)
            tripped = any(
                bl.SEVERITY_ORDER.get(bl.severity_of(f), 0) >= floor
                for f in findings
            )
        return total, None, tripped

    baseline = bl.load_baseline(profile.baseline)
    diff = bl.diff_findings(source, findings, baseline, root=root, domain=domain)
    tripped = bool(profile.fail_on) and diff.new_meets(profile.fail_on)
    return total, len(diff.new), tripped


def stage_dependencies(profile: Profile, out_dir: Path) -> StageResult:
    import coldlight_vulnintel as vi

    result = StageResult(name="dependencies")
    totals = 0
    new_total = None
    tripped = False

    for index, path in enumerate(profile.deps_paths, start=1):
        scan = vi.scan_dependencies(path, workers=profile.workers)
        try:
            vi.apply_kev(scan.findings, vi.kev_index())
            scan.findings = vi.sort_findings(scan.findings)
        except vi.VulnIntelError as exc:
            scan.errors.append(f"KEV cross-reference unavailable: {exc}")

        suffix = "" if len(profile.deps_paths) == 1 else f"-{index}"
        result.artifacts.append(_write_json(
            out_dir / f"deps{suffix}.json", vi.json_report(scan)))

        count, new, gate = _gate_counts("dep", scan.findings, profile)
        totals += count
        tripped = tripped or gate
        if new is not None:
            new_total = (new_total or 0) + new

    result.findings = totals
    result.new_findings = new_total
    result.summary = f"{totals} findings"
    if new_total is not None:
        result.summary += f" ({new_total} new)"
    result.gate_tripped = tripped
    return result


def stage_sbom(profile: Profile, out_dir: Path) -> StageResult:
    import coldlight_vulnintel as vi

    result = StageResult(name="sbom")
    totals = 0
    not_checked = 0
    tripped = False
    new_total = None

    for index, path in enumerate(profile.sbom_files, start=1):
        scan, sbom = vi.scan_sbom(path, workers=profile.workers)
        try:
            vi.apply_kev(scan.findings, vi.kev_index())
            scan.findings = vi.sort_findings(scan.findings)
        except vi.VulnIntelError as exc:
            scan.errors.append(f"KEV cross-reference unavailable: {exc}")

        suffix = "" if len(profile.sbom_files) == 1 else f"-{index}"
        result.artifacts.append(_write_json(
            out_dir / f"sbom{suffix}.json", vi.json_report(scan)))

        count, new, gate = _gate_counts("dep", scan.findings, profile)
        totals += count
        not_checked += scan.not_checked
        tripped = tripped or gate
        if new is not None:
            new_total = (new_total or 0) + new

    result.findings = totals
    result.new_findings = new_total
    result.summary = f"{totals} findings"
    if not_checked:
        result.summary += f", {not_checked} component(s) NOT CHECKED"
    result.gate_tripped = tripped
    return result


def stage_code(profile: Profile, out_dir: Path) -> StageResult:
    import coldlight_codescan as cs

    result = StageResult(name="source code")
    totals = 0
    new_total = None
    tripped = False

    for index, path in enumerate(profile.code_paths, start=1):
        scan = cs.scan_code(path, exclude=profile.code_exclude or None)
        suffix = "" if len(profile.code_paths) == 1 else f"-{index}"
        result.artifacts.append(_write_json(
            out_dir / f"code{suffix}.json", cs.json_report(scan)))

        count, new, gate = _gate_counts("code", scan.findings, profile,
                                        root=path)
        totals += count
        tripped = tripped or gate
        if new is not None:
            new_total = (new_total or 0) + new

    result.findings = totals
    result.new_findings = new_total
    result.summary = f"{totals} findings"
    if new_total is not None:
        result.summary += f" ({new_total} new)"
    result.gate_tripped = tripped
    return result


def stage_history(profile: Profile, out_dir: Path) -> StageResult:
    import coldlight_history as hist

    result = StageResult(name="git history")
    totals = 0
    new_total = None
    tripped = False
    recoverable = 0
    unassessed = []

    for index, path in enumerate(profile.history_paths, start=1):
        scan = hist.scan_history(
            path, exclude=profile.code_exclude or None,
            allow_shallow=profile.history_allow_shallow)
        suffix = "" if len(profile.history_paths) == 1 else f"-{index}"
        result.artifacts.append(_write_json(
            out_dir / f"history{suffix}.json", hist.json_report(scan)))

        if not scan.assessed:
            unassessed.append(scan.state.error or scan.truncated
                              or "the history could not be read")
            continue

        count, new, gate = _gate_counts("history", scan.findings, profile,
                                        root=path)
        totals += count
        recoverable += len(scan.recoverable_only)
        tripped = tripped or gate
        if new is not None:
            new_total = (new_total or 0) + new

    if unassessed and totals == 0:
        # Every target was shallow or unreadable. The artifact is kept for
        # diagnosis, but this is not a clean result and must not read as one.
        result.status = STAGE_FAILED
        result.summary = "history not assessed"
        result.error = unassessed[0]
        return result

    result.findings = totals
    result.new_findings = new_total
    result.summary = f"{totals} findings"
    if new_total is not None:
        result.summary += f" ({new_total} new)"
    if recoverable:
        result.summary += f", {recoverable} gone from HEAD but recoverable"
    if unassessed:
        result.summary += f", {len(unassessed)} repo(s) not assessed"
    result.gate_tripped = tripped
    return result


def stage_ai(profile: Profile, out_dir: Path) -> StageResult:
    import coldlight_aisec as ai

    result = StageResult(name="AI/ML systems")
    totals = 0
    new_total = None
    tripped = False
    unsafe = 0

    # An AI scan with no exclude list re-reads whatever the code scan was
    # told to skip, so inherit it unless the profile says otherwise.
    exclude = profile.ai_exclude or profile.code_exclude or None

    for index, path in enumerate(profile.ai_paths, start=1):
        scan = ai.scan_ai(path, exclude=exclude)
        suffix = "" if len(profile.ai_paths) == 1 else f"-{index}"
        result.artifacts.append(_write_json(
            out_dir / f"ai{suffix}.json", ai.json_report(scan)))

        count, new, gate = _gate_counts("ai", scan.findings, profile,
                                        root=path)
        totals += count
        unsafe += len(scan.unsafe_artifacts)
        tripped = tripped or gate
        if new is not None:
            new_total = (new_total or 0) + new

    result.findings = totals
    result.new_findings = new_total
    result.summary = f"{totals} findings"
    if new_total is not None:
        result.summary += f" ({new_total} new)"
    if unsafe:
        result.summary += f", {unsafe} code-executing model artifact(s)"
    result.gate_tripped = tripped
    return result


def stage_probe(profile: Profile, out_dir: Path) -> StageResult:
    import coldlight_canary as cn
    import coldlight_scope as rs

    result = StageResult(name="AI runtime behaviour")

    scope = rs.load_scope(profile.probe_scope)
    run = cn.run_probes(scope)
    result.artifacts.append(_write_json(
        out_dir / "probe.json", cn.json_report(run, scope)))

    items = cn.findings(run)
    result.findings = len(items)

    if not run.established:
        # Every probe was inconclusive. The artifact is kept because it is
        # genuine diagnostic output, but the stage is NOT ok: a run that
        # established nothing must never read as a model that resisted.
        result.status = STAGE_FAILED
        result.summary = "no verdict reached"
        result.error = ("every probe was inconclusive, so nothing about the "
                        "model's behaviour was established")
        return result

    result.summary = (f"{len(run.susceptible)} of {len(run.results)} "
                      f"probe(s) susceptible")
    if run.inconclusive:
        result.summary += f", {len(run.inconclusive)} inconclusive"

    if profile.fail_on:
        try:
            result.gate_tripped = cn.meets_threshold(items, profile.fail_on)
        except ValueError:
            result.gate_tripped = False
    return result


def stage_ioc(profile: Profile, out_dir: Path) -> StageResult:
    import coldlight_ioc as ioc

    result = StageResult(name="indicators")

    try:
        packs = ioc.load_packs(profile.ioc_packs)
    except ioc.PackError as exc:
        # The likeliest operator error in this stage, and the one whose quiet
        # version is worst: without the pack nothing is searched for, and a
        # stage that searched for nothing still prints zero findings.
        result.status = STAGE_FAILED
        result.summary = "no pack loaded"
        result.error = str(exc)
        return result

    # Read before the walk so the all-expired check below does not depend on
    # a loop variable surviving, and so it is the same date the scan stamps.
    from datetime import datetime, timezone
    today = datetime.now(timezone.utc).date()
    active = sum(len(p.active(today)) for p in packs)

    stale_after = (ioc.STALE_AFTER_DAYS if profile.ioc_stale_after is None
                   else profile.ioc_stale_after)
    totals = 0
    pending = 0
    expired = 0
    tripped = False
    current = True
    uncovered: set[str] = set()

    for index, path in enumerate(profile.ioc_paths, start=1):
        scan = ioc.scan_packs(path, packs,
                              exclude=profile.ioc_exclude or None,
                              stale_after_days=stale_after)
        suffix = "" if len(profile.ioc_paths) == 1 else f"-{index}"
        result.artifacts.append(_write_json(
            out_dir / f"ioc{suffix}.json", ioc.json_report(scan)))

        totals += len(scan.findings)
        pending += len(scan.corroboration)
        expired += len(scan.expired)
        current = current and scan.fully_current
        uncovered.update(row.kind for row in scan.uncovered_surfaces)

        if profile.fail_on:
            # Only `scan.findings`, like the CLI: a match awaiting
            # corroboration has not been established and an expired one is
            # not evidence, so neither may fail a build. The baseline is not
            # applied either -- see the summary line below.
            try:
                tripped = tripped or ioc.meets_threshold(scan.findings,
                                                         profile.fail_on)
            except ValueError:
                tripped = False

    if not active:
        # Every indicator has expired. The scan ran, the artifact is kept for
        # diagnosis, and the expired matches in it say what the pack would
        # once have flagged -- but nothing current was looked for, so this is
        # the one result that must not be presented as a clean tree.
        result.status = STAGE_FAILED
        result.summary = "no usable indicator"
        result.error = (
            f"every indicator in the supplied pack(s) has expired, so "
            f"nothing current was looked for ({expired} match(es) against "
            f"expired indicators are recorded in the artifact)")
        return result

    result.findings = totals
    result.summary = f"{totals} finding(s)"
    if pending:
        result.summary += f", {pending} awaiting corroboration"
    if expired:
        result.summary += f", {expired} expired match(es)"
    if uncovered:
        result.summary += f", {len(uncovered)} surface(s) NOT COVERED"
    if not current:
        result.summary += ", pack(s) not fully current"
    if profile.baseline:
        # Every other stage gates on what is new since the baseline. An
        # indicator match is not a backlog item to accept and carry, so there
        # is nothing here to baseline -- said out loud, because a reader who
        # configured one would otherwise assume it applied.
        result.summary += " (baseline not applied to indicators)"
    result.gate_tripped = tripped
    return result


def stage_mail(profile: Profile, out_dir: Path) -> StageResult:
    import coldlight_mail as rm

    result = StageResult(name="email posture")
    totals = 0
    verdicts = []
    tripped = False
    new_total = None

    for index, domain in enumerate(profile.mail_domains, start=1):
        audit = rm.audit_domain(domain, fetch_policy=profile.mail_fetch_policy,
                                workers=profile.workers)
        suffix = "" if len(profile.mail_domains) == 1 else f"-{index}"
        result.artifacts.append(_write_json(
            out_dir / f"mail{suffix}.json", audit.to_dict()))

        count, new, gate = _gate_counts("mail", audit.findings, profile,
                                        domain=audit.domain)
        totals += count
        tripped = tripped or gate
        if new is not None:
            new_total = (new_total or 0) + new
        verdicts.append("SPOOFABLE" if audit.spoofable
                        else f"protected ({audit.protection_level})")

    result.findings = totals
    result.new_findings = new_total
    result.summary = "; ".join(verdicts) + f" — {totals} findings"
    result.gate_tripped = tripped
    return result


def stage_awareness(profile: Profile, out_dir: Path) -> StageResult:
    import coldlight_engagement as eng

    result = StageResult(name="awareness")
    summary, _findings, _notes = eng.load_awareness(profile.awareness_db)
    result.findings = summary.total_runs
    vectors = ", ".join(f"{k}={v}" for k, v in summary.by_vector.items())
    result.summary = (f"{summary.total_runs} hits / "
                      f"{summary.unique_hosts} host(s)"
                      + (f" [{vectors}]" if vectors else ""))
    result.gate_tripped = False
    return result


def stage_detect(profile: Profile, out_dir: Path) -> StageResult:
    import coldlight_detect as rd

    result = StageResult(name="detection artifacts")
    sigma_dir = out_dir / "sigma"
    sigma_dir.mkdir(parents=True, exist_ok=True)

    rules = rd.generate_rules(None)
    for rule in rules:
        (sigma_dir / rule.filename).write_text(rule.to_yaml(), encoding="utf-8")
    result.artifacts.append(str(sigma_dir))

    layer = out_dir / "attack_layer.json"
    layer.write_text(rd.navigator_json(), encoding="utf-8")
    result.artifacts.append(str(layer))

    checklist = out_dir / "blue_team_checklist.md"
    checklist.write_text(rd.checklist_markdown(None), encoding="utf-8")
    result.artifacts.append(str(checklist))

    result.summary = (f"{len(rules)} Sigma rules, ATT&CK layer, checklist")
    result.gate_tripped = False
    return result


STAGES = [
    ("dependencies", lambda p: bool(p.deps_paths), stage_dependencies),
    ("sbom", lambda p: bool(p.sbom_files), stage_sbom),
    ("source code", lambda p: bool(p.code_paths), stage_code),
    ("git history", lambda p: bool(p.history_paths), stage_history),
    ("AI/ML systems", lambda p: bool(p.ai_paths), stage_ai),
    ("indicators", lambda p: bool(p.ioc_packs and p.ioc_paths), stage_ioc),
    ("AI runtime behaviour", lambda p: bool(p.probe_scope), stage_probe),
    ("email posture", lambda p: bool(p.mail_domains), stage_mail),
    ("awareness", lambda p: bool(p.awareness_db), stage_awareness),
    ("detection artifacts", lambda p: p.detect_enabled, stage_detect),
]


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def run(profile: Profile, *, progress=None) -> AssessmentRun:
    """Run every configured stage, then build the report.

    No stage can abort the run: a failure is recorded, reported, and reflected
    in the exit code.
    """
    run_result = AssessmentRun(profile=profile)
    out_dir = Path(profile.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    active = [(name, fn) for name, enabled, fn in STAGES if enabled(profile)]
    total_stages = len(active) + 1          # +1 for the report

    for index, (name, runner) in enumerate(active, start=1):
        if progress:
            progress(index, total_stages, name, None)
        # Clear this stage's previous output first, so a failure cannot leave
        # a stale artifact behind that looks like part of this run.
        _clear_stage_artifacts(name, out_dir)
        try:
            stage = runner(profile, out_dir)
        except Exception as exc:  # noqa: BLE001 - one stage must not kill the run
            _clear_stage_artifacts(name, out_dir)   # drop any partial writes
            stage = StageResult(name=name, status=STAGE_FAILED,
                                summary="did not complete",
                                error=f"{type(exc).__name__}: {exc}")
        run_result.stages.append(stage)
        if stage.gate_tripped:
            run_result.gate_tripped = True
        if progress:
            progress(index, total_stages, name, stage)

    # ---- assurance ledger -------------------------------------------------
    # Built BEFORE the report, because the report embeds it. The stage
    # statuses are passed directly since run.json does not exist yet.
    try:
        import coldlight_assurance as asr
        run_result.ledger = asr.build_ledger(
            out_dir, manifest={"stages": [s.to_dict() for s in run_result.stages]})
    except Exception:  # noqa: BLE001 - the ledger must never break the run
        run_result.ledger = None

    # ---- the report ------------------------------------------------------
    if progress:
        progress(total_stages, total_stages, "report", None)

    report_stage = StageResult(name="report")
    try:
        report_stage = _build_report(profile, out_dir, run_result)
    except Exception as exc:  # noqa: BLE001
        report_stage = StageResult(name="report", status=STAGE_FAILED,
                                   summary="did not complete",
                                   error=f"{type(exc).__name__}: {exc}")
    run_result.stages.append(report_stage)
    if progress:
        progress(total_stages, total_stages, "report", report_stage)

    if run_result.gate_tripped and profile.fail_on:
        run_result.gate_detail = (
            f"new findings at or above {profile.fail_on.upper()} "
            f"(since baseline)" if profile.baseline else
            f"findings at or above {profile.fail_on.upper()}"
        )

    _write_manifest(run_result, out_dir)
    return run_result


def _write_manifest(run_result: AssessmentRun, out_dir: Path) -> None:
    """Record what this run actually did.

    An authoritative list of which artifacts belong to this assessment, which
    stages failed, and what the exit code was -- so the output directory is
    self-describing rather than a pile of JSON someone has to interpret.
    """
    from datetime import datetime, timezone

    payload = {
        "tool": "coldlight assess",
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "exit_code": run_result.exit_code,
        "stages_ok": sum(1 for s in run_result.stages if s.ok),
        "stages_failed": len(run_result.failed),
        "gate_tripped": run_result.gate_tripped,
        "gate_detail": run_result.gate_detail,
        "incomplete": bool(run_result.failed),
        "stages": [s.to_dict() for s in run_result.stages],
        "profile": run_result.profile.to_dict(),
    }
    try:
        _write_json(out_dir / "run.json", payload)
    except OSError:
        pass


def _artifacts(stages: list[StageResult], name: str, suffix: str) -> list[str]:
    for stage in stages:
        if stage.name == name and stage.ok:
            return [a for a in stage.artifacts if a.endswith(suffix)]
    return []


def _build_report(profile: Profile, out_dir: Path,
                  run_result: AssessmentRun) -> StageResult:
    import coldlight_engagement as eng

    stage = StageResult(name="report")

    engagement = eng.Engagement(
        engagement_id=profile.engagement_id,
        authorization_reference=profile.authorization_reference,
        client=profile.client,
        assessor=profile.assessor,
        title=profile.title,
        period=profile.period,
        scope=list(profile.scope),
    )

    vuln_paths = (_artifacts(run_result.stages, "dependencies", ".json")
                  + _artifacts(run_result.stages, "sbom", ".json"))
    code_paths = _artifacts(run_result.stages, "source code", ".json")
    ai_paths = _artifacts(run_result.stages, "AI/ML systems", ".json")
    history_paths = _artifacts(run_result.stages, "git history", ".json")
    probe_paths = _artifacts(run_result.stages, "AI runtime behaviour", ".json")
    ioc_paths = _artifacts(run_result.stages, "indicators", ".json")
    mail_paths = _artifacts(run_result.stages, "email posture", ".json")

    awareness_ok = any(s.name == "awareness" and s.ok
                       for s in run_result.stages)

    report = eng.build_report(
        engagement=engagement,
        vuln_paths=vuln_paths,
        code_paths=code_paths,
        ai_paths=ai_paths,
        history_paths=history_paths,
        probe_paths=probe_paths,
        ioc_paths=ioc_paths,
        mail_paths=mail_paths,
        hits_db=profile.awareness_db if awareness_ok else None,
        vex_path=profile.vex_triage or None,
        extra_limitations=run_result.limitations(),
        assurance=(run_result.ledger.to_dict()
                   if run_result.ledger is not None else None),
    )
    run_result.report = report

    for fmt in profile.formats:
        extension = {"html": "html", "md": "md", "json": "json"}[fmt]
        path = out_dir / f"report.{extension}"
        path.write_text(eng.render(report, fmt), encoding="utf-8")
        stage.artifacts.append(str(path))
        run_result.report_paths.append(str(path))

    if run_result.ledger is not None:
        try:
            import coldlight_assurance as asr
            _write_json(out_dir / "assurance.json", run_result.ledger.to_dict())
            (out_dir / "assurance.md").write_text(
                asr.markdown_ledger(run_result.ledger), encoding="utf-8")
            stage.artifacts.extend([str(out_dir / "assurance.json"),
                                    str(out_dir / "assurance.md")])
        except OSError:
            pass

    stage.findings = len(report.findings)
    stage.summary = ", ".join(Path(p).name for p in stage.artifacts)
    stage.gate_tripped = False
    return stage


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def summary_report(run_result: AssessmentRun) -> str:
    out: list[str] = []
    stages = run_result.stages
    ok = sum(1 for s in stages if s.ok)
    failed = len(run_result.failed)

    out.append("=" * 68)
    out.append("Assessment complete")
    out.append("=" * 68)
    out.append(f"Stages: {ok} ok, {failed} failed")
    for stage in stages:
        marker = {STAGE_OK: "ok     ", STAGE_FAILED: "FAILED ",
                  STAGE_SKIPPED: "skipped"}.get(stage.status, "?      ")
        detail = stage.error if stage.status == STAGE_FAILED else stage.summary
        out.append(f"  {marker}  {stage.name:<21} {detail}")

    report = run_result.report
    if report is not None:
        out.append("")
        out.append(f"{len(report.findings)} finding(s) covering "
                   f"{report.raw_item_count} item(s)")
        counts = report.severity_counts()
        if counts:
            out.append("  " + ", ".join(f"{k.lower()}={v}"
                                        for k, v in counts.items()))
        if report.kev_findings:
            out.append(f"  KNOWN EXPLOITED: {len(report.kev_findings)} "
                       f"<-- fix these first")
        if report.suppressed:
            out.append(f"  suppressed by VEX triage: {len(report.suppressed)}")

    if failed:
        out.append("")
        out.append(f"!! {failed} stage(s) failed. The report marks those areas "
                   f"NOT ASSESSED.")
        out.append("   The findings above are therefore incomplete -- do not "
                   "read them as a clean result.")

    if run_result.gate_tripped:
        out.append("")
        out.append(f"FAIL: {run_result.gate_detail}")

    if run_result.report_paths:
        out.append("")
        for path in run_result.report_paths:
            out.append(f"Report: {path}")

    return "\n".join(out)


def write_profile_template(path: str | Path) -> Path:
    file_path = Path(path)
    if file_path.exists():
        raise AssessError(f"{file_path} already exists")
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(PROFILE_TEMPLATE, encoding="utf-8")
    return file_path
