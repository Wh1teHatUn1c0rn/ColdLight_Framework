#!/usr/bin/env python3
"""
ColdLight assurance ledger: what was actually assessed, and what nobody looked at.

Every scanner tells you what it found. Almost none tell you what it did not
look at -- so a report with few findings reads as reassurance when it may
simply be narrow. This turns that into the headline artifact: per check class,
one of ASSESSED / PARTIAL / NOT ASSESSED / FAILED, with a reason and a
checked-of-total ratio.

TWO DESIGN DECISIONS THAT MAKE IT HONEST RATHER THAN FLATTERING:

1. The ledger lists classes ColdLight CANNOT assess, not just the ones it can.
   Showing only our own four or five classes would let "all classes assessed"
   read as full coverage, when nobody tested the network, the web application,
   cloud configuration or identity. Those appear as NOT ASSESSED with
   "requires a separate assessment" -- because that is the truth, and the
   reader needs the shape of the whole problem, not just our slice.

2. Emitting Sigma rules is NOT detection coverage. Shipping a rule says
   nothing about whether anyone would have noticed. Detection is only
   ASSESSED when outcomes were actually recorded, which today means never --
   so it reports NOT ASSESSED and points at `detect validate`. A tool that
   counted its own deliverables as coverage would be grading its own homework.

The same applies to our own blind spots: the code scan reads the working tree
only, so "secrets in version history" is listed as a class ColdLight could cover
but does not.

Stdlib only. Read-only.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

STATUS_ASSESSED = "ASSESSED"
STATUS_PARTIAL = "PARTIAL"
STATUS_NOT_ASSESSED = "NOT ASSESSED"
STATUS_FAILED = "FAILED"

# Classes ColdLight can assess itself.
TIER_COVERED = "covered"
# Classes that need a different engagement entirely. Listed so their absence
# is explicit rather than implied.
TIER_EXTERNAL = "external"

_STATUS_RANK = {
    STATUS_FAILED: 0,
    STATUS_NOT_ASSESSED: 1,
    STATUS_PARTIAL: 2,
    STATUS_ASSESSED: 3,
}


@dataclass(frozen=True)
class CheckClass:
    key: str
    label: str
    tier: str
    unit: str = ""
    note: str = ""


CLASSES: tuple[CheckClass, ...] = (
    # ---- what ColdLight can do ---------------------------------------------
    CheckClass("dependencies", "Language dependencies", TIER_COVERED,
               "components"),
    CheckClass("sbom", "Bill of materials / OS packages", TIER_COVERED,
               "components"),
    CheckClass("source_code", "Source code (static analysis)", TIER_COVERED,
               "files",
               note="Pattern matching only -- no dataflow analysis."),
    CheckClass("secrets_history", "Secrets in version history", TIER_COVERED,
               "commits",
               note="Reachable history only -- what someone with a clone "
                    "can recover. Dangling objects and the local reflog are "
                    "not included, and whether a credential was rotated "
                    "cannot be determined from the repository."),
    CheckClass("ai_ml", "AI/ML systems and model artifacts", TIER_COVERED,
               "files",
               note="Static review of code and model files only. How the "
                    "model behaves is a separate class -- see AI model "
                    "runtime behaviour."),
    CheckClass("ai_runtime", "AI model runtime behaviour", TIER_COVERED,
               "probes",
               note="Benign canary probing: shows whether untrusted content "
                    "is treated as instructions. Susceptibility can be "
                    "demonstrated this way but never disproved -- a resisted "
                    "probe set is not a robust model."),
    CheckClass("email_auth", "Email authentication", TIER_COVERED, "domains"),
    CheckClass("awareness", "Human susceptibility", TIER_COVERED,
               "recorded actions",
               note="Counts observed behaviour. There is no denominator: the "
                    "number of people who received the lure is not known to "
                    "this tool."),
    CheckClass("detection", "Detection and response coverage", TIER_COVERED,
               "hits",
               note="Shipping a Sigma rule is not evidence that anyone would "
                    "have noticed. Only recorded outcomes count."),
    # Label kept under 36 characters: text_ledger truncates at that width, and
    # a class name cut off mid-word in the one table people read is worse than
    # a shorter name. The scope caveat lives in the note instead.
    CheckClass("ioc", "Known-tool indicators on disk", TIER_COVERED,
               "indicators",
               note="Markers visible on disk, from a pack the operator "
                    "supplied: file contents, file paths, file digests "
                    "(SHA-256), ports declared in configuration, and images "
                    "a manifest deploys. The denominator is indicators the "
                    "pack could still vouch for, not files: an expired "
                    "indicator was carried but not used. A pack covering one "
                    "of those five surfaces and a pack covering all five "
                    "both report here, so which surfaces were examined is in "
                    "the scan's own report and in the report's limitations, "
                    "not in this row. Network, identity and cloud telemetry "
                    "carry most of any real indicator pack and are not read "
                    "here -- see the external classes below. Absence of "
                    "these markers is not absence of compromise."),
    # ---- what ColdLight structurally cannot do ------------------------------
    CheckClass("network", "Network and host infrastructure", TIER_EXTERNAL),
    CheckClass("web_app", "Web application logic and authorisation",
               TIER_EXTERNAL),
    CheckClass("cloud_config", "Cloud configuration and IAM", TIER_EXTERNAL),
    CheckClass("identity", "Identity, directory and privilege", TIER_EXTERNAL),
    CheckClass("wireless", "Wireless", TIER_EXTERNAL),
    CheckClass("physical", "Physical security", TIER_EXTERNAL),
    CheckClass("mobile", "Mobile applications", TIER_EXTERNAL),
)

CLASS_BY_KEY = {c.key: c for c in CLASSES}

# The stage names `coldlight assess` writes into run.json, by ledger class.
# Read only when a stage left no artifact behind, to tell a class that FAILED
# from one nobody ran -- two very different sentences for the reader.
#
# Declared here rather than spelled at each call site because a name that does
# not match coldlight_assess.STAGES silently degrades into "nobody ran it":
# "ai/ml" sat here against a stage actually called "AI/ML systems", so a
# crashed AI scan was reported as one that had never been configured. A test
# now holds every value in this map against the real stage table.
STAGE_NAMES = {
    "dependencies": "dependencies",
    "sbom": "sbom",
    "source_code": "source code",
    "secrets_history": "git history",
    "ai_ml": "AI/ML systems",
    "ai_runtime": "AI runtime behaviour",
    "email_auth": "email posture",
    "awareness": "awareness",
    "ioc": "indicators",
}

EXTERNAL_REASON = "requires a separate assessment; outside this tool's scope"


class AssuranceError(ValueError):
    """The artifacts could not be read."""


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------

@dataclass
class LedgerEntry:
    key: str
    label: str
    tier: str
    status: str
    findings: int = 0
    checked: int | None = None
    total: int | None = None
    unit: str = ""
    reason: str = ""
    note: str = ""

    @property
    def ratio(self) -> str:
        if self.checked is None or self.total is None:
            return "—" if self.checked is None else f"{self.checked}"
        return f"{self.checked}/{self.total}"

    @property
    def examined(self) -> bool:
        return self.status in (STATUS_ASSESSED, STATUS_PARTIAL)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["ratio"] = self.ratio
        return data


@dataclass
class Ledger:
    entries: list[LedgerEntry] = field(default_factory=list)
    generated: str = ""
    source: str = ""

    # -- aggregates -------------------------------------------------------

    @property
    def covered(self) -> list[LedgerEntry]:
        return [e for e in self.entries if e.tier == TIER_COVERED]

    @property
    def external(self) -> list[LedgerEntry]:
        return [e for e in self.entries if e.tier == TIER_EXTERNAL]

    @property
    def examined_classes(self) -> int:
        return sum(1 for e in self.covered if e.examined)

    @property
    def unexamined(self) -> list[LedgerEntry]:
        return [e for e in self.entries if not e.examined]

    @property
    def failed(self) -> list[LedgerEntry]:
        return [e for e in self.entries if e.status == STATUS_FAILED]

    @property
    def total_findings(self) -> int:
        return sum(e.findings for e in self.entries)

    def unit_coverage(self) -> tuple[int, int]:
        """(checked, total) summed over classes that report a denominator."""
        checked = total = 0
        for entry in self.entries:
            if entry.checked is not None and entry.total is not None:
                checked += entry.checked
                total += entry.total
        return checked, total

    @property
    def unit_percentage(self) -> float | None:
        checked, total = self.unit_coverage()
        return (100.0 * checked / total) if total else None

    def to_dict(self) -> dict:
        checked, total = self.unit_coverage()
        return {
            "tool": "coldlight assurance",
            "generated": self.generated,
            "source": self.source,
            "classes_examined": self.examined_classes,
            "classes_in_tool_scope": len(self.covered),
            "classes_total": len(self.entries),
            "units_checked": checked,
            "units_total": total,
            "unit_percentage": (round(self.unit_percentage, 1)
                                if self.unit_percentage is not None else None),
            "findings": self.total_findings,
            "unexamined": [e.key for e in self.unexamined],
            "failed": [e.key for e in self.failed],
            "entries": [e.to_dict() for e in self.entries],
        }


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Building the ledger from a run's artifacts
# ---------------------------------------------------------------------------

def _load(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise AssuranceError(f"{path}: {exc}") from exc
    if not isinstance(data, dict):
        raise AssuranceError(f"{path}: expected a JSON object")
    return data


def _entry(key: str, status: str, **kwargs) -> LedgerEntry:
    spec = CLASS_BY_KEY[key]
    return LedgerEntry(key=spec.key, label=spec.label, tier=spec.tier,
                       status=status, unit=spec.unit, note=spec.note, **kwargs)


def _stage_status(manifest: dict, name: str) -> str | None:
    for stage in manifest.get("stages") or []:
        if stage.get("name") == name:
            return stage.get("status")
    return None


def _stage_error(manifest: dict, name: str) -> str:
    for stage in manifest.get("stages") or []:
        if stage.get("name") == name:
            return stage.get("error", "") or ""
    return ""


def build_ledger(out_dir: str | Path, manifest: dict | None = None) -> Ledger:
    """Derive the ledger from an assessment output directory.

    `manifest` lets the orchestrator pass stage statuses directly, since it
    builds the ledger before `run.json` exists (the report embeds the ledger,
    so it has to come first). Otherwise the directory is read as-is, which is
    what `coldlight assurance --from` does for a previous run.
    """
    directory = Path(out_dir)
    if not directory.is_dir():
        raise AssuranceError(f"no such directory: {directory}")

    if manifest is None:
        manifest = {}
        manifest_path = directory / "run.json"
        if manifest_path.is_file():
            manifest = _load(manifest_path)

    ledger = Ledger(generated=_now(), source=str(directory))

    # ---- language dependencies ------------------------------------------
    deps_files = sorted(directory.glob("deps*.json"))
    if deps_files:
        findings = checked = 0
        for path in deps_files:
            data = _load(path)
            findings += len(data.get("findings") or [])
            checked += int(data.get("packages_checked", 0) or 0)
        ledger.entries.append(_entry(
            "dependencies", STATUS_ASSESSED, findings=findings,
            checked=checked, total=checked))
    else:
        status = _stage_status(manifest, STAGE_NAMES["dependencies"])
        if status == "failed":
            ledger.entries.append(_entry(
                "dependencies", STATUS_FAILED,
                reason=_stage_error(manifest, STAGE_NAMES["dependencies"])
                or "the stage did not complete"))
        else:
            ledger.entries.append(_entry(
                "dependencies", STATUS_NOT_ASSESSED,
                reason="no dependency scan was run"))

    # ---- SBOM / OS packages ---------------------------------------------
    sbom_files = sorted(directory.glob("sbom*.json"))
    if sbom_files:
        findings = checked = not_checked = 0
        reasons: list[str] = []
        for path in sbom_files:
            data = _load(path)
            findings += len(data.get("findings") or [])
            checked += int(data.get("packages_checked", 0) or 0)
            not_checked += int(data.get("not_checked", 0) or 0)
            for reason in (data.get("not_checked_reasons") or {}):
                if reason not in reasons:
                    reasons.append(reason)
        status = STATUS_PARTIAL if not_checked else STATUS_ASSESSED
        ledger.entries.append(_entry(
            "sbom", status, findings=findings, checked=checked,
            total=checked + not_checked,
            reason=(f"{not_checked} component(s) could not be mapped to "
                    f"vulnerability data: " + "; ".join(reasons[:3]))
            if not_checked else ""))
    else:
        status = _stage_status(manifest, STAGE_NAMES["sbom"])
        if status == "failed":
            ledger.entries.append(_entry(
                "sbom", STATUS_FAILED,
                reason=_stage_error(manifest, STAGE_NAMES["sbom"])
                or "the stage did not complete"))
        else:
            ledger.entries.append(_entry(
                "sbom", STATUS_NOT_ASSESSED,
                reason="no SBOM was supplied, so shipped artifacts and OS "
                       "packages were not inventoried"))

    # ---- source code -----------------------------------------------------
    code_files = sorted(directory.glob("code*.json"))
    if code_files:
        findings = scanned = 0
        for path in code_files:
            data = _load(path)
            findings += len(data.get("findings") or [])
            scanned += int(data.get("files_scanned", 0) or 0)
        ledger.entries.append(_entry(
            "source_code", STATUS_ASSESSED, findings=findings,
            checked=scanned, total=scanned))
    else:
        status = _stage_status(manifest, STAGE_NAMES["source_code"])
        if status == "failed":
            ledger.entries.append(_entry(
                "source_code", STATUS_FAILED,
                reason=_stage_error(manifest, STAGE_NAMES["source_code"])
                or "the stage did not complete"))
        else:
            ledger.entries.append(_entry(
                "source_code", STATUS_NOT_ASSESSED,
                reason="no static analysis was run"))


    # ---- secrets in version history -------------------------------------
    history_files = sorted(directory.glob("history*.json"))
    if history_files:
        findings = commits = recoverable = 0
        assessed = False
        reasons = []
        for path in history_files:
            data = _load(path)
            findings += len(data.get("findings") or [])
            commits += int(data.get("commits_scanned", 0) or 0)
            recoverable += int((data.get("counts") or {})
                               .get("recoverable_only", 0) or 0)
            if data.get("assessed"):
                assessed = True
            else:
                repo = data.get("repository") or {}
                reasons.append(str(repo.get("error", "")
                                   or data.get("truncated", "")
                                   or "the history could not be read"))
        if assessed:
            ledger.entries.append(_entry(
                "secrets_history", STATUS_ASSESSED, findings=findings,
                checked=commits, total=commits,
                reason=(f"{recoverable} secret(s) no longer in HEAD but "
                        f"still recoverable" if recoverable else "")))
        else:
            # A shallow clone finds almost nothing and looks clean. That is
            # the one outcome this class must never show as ASSESSED.
            ledger.entries.append(_entry(
                "secrets_history", STATUS_FAILED, findings=0,
                checked=0, total=0,
                reason=reasons[0] if reasons
                else "the history was not fully read"))
    else:
        status = _stage_status(manifest, STAGE_NAMES["secrets_history"])
        if status == "failed":
            ledger.entries.append(_entry(
                "secrets_history", STATUS_FAILED,
                reason=_stage_error(manifest, STAGE_NAMES["secrets_history"])
                or "the stage did not complete"))
        else:
            ledger.entries.append(_entry(
                "secrets_history", STATUS_NOT_ASSESSED,
                reason="no history scan was run; a credential committed and "
                       "later deleted would not have been seen"))

    # ---- AI/ML systems ---------------------------------------------------
    ai_files = sorted(directory.glob("ai*.json"))
    if ai_files:
        findings = scanned = unsafe = 0
        for path in ai_files:
            data = _load(path)
            findings += len(data.get("findings") or [])
            scanned += int(data.get("files_scanned", 0) or 0)
            unsafe += int(data.get("unsafe_artifact_count", 0) or 0)
        ledger.entries.append(_entry(
            "ai_ml", STATUS_ASSESSED, findings=findings,
            checked=scanned, total=scanned,
            reason=(f"{unsafe} model artifact(s) in a code-executing format"
                    if unsafe else "")))
    else:
        status = _stage_status(manifest, STAGE_NAMES["ai_ml"])
        if status == "failed":
            ledger.entries.append(_entry(
                "ai_ml", STATUS_FAILED,
                reason=_stage_error(manifest, STAGE_NAMES["ai_ml"])
                or "the stage did not complete"))
        else:
            ledger.entries.append(_entry(
                "ai_ml", STATUS_NOT_ASSESSED,
                reason="no AI/ML scan was run; model loading, prompt-injection "
                       "sinks and agent permissions were not reviewed"))

    # ---- AI runtime behaviour -------------------------------------------
    # Static review cannot speak to how the model behaves, so this is its own
    # class. Its absence is the point: without a probe it reads NOT ASSESSED
    # rather than letting a clean static scan imply a robust model.
    probe_files = sorted(directory.glob("probe*.json"))
    if probe_files:
        findings = probes = conclusive = 0
        established = False
        for path in probe_files:
            data = _load(path)
            counts = data.get("counts") or {}
            findings += len(data.get("findings") or [])
            probes += int(counts.get("probes", 0) or 0)
            conclusive += (int(counts.get("susceptible", 0) or 0)
                           + int(counts.get("resisted", 0) or 0))
            established = established or bool(data.get("verdict_established"))
        if established:
            ledger.entries.append(_entry(
                "ai_runtime", STATUS_ASSESSED, findings=findings,
                checked=conclusive, total=probes,
                reason=(f"{probes - conclusive} probe(s) reached no verdict"
                        if probes > conclusive else "")))
        else:
            # Probes ran and every one was inconclusive. That is not a clean
            # result -- it is no result.
            ledger.entries.append(_entry(
                "ai_runtime", STATUS_FAILED, findings=0,
                checked=0, total=probes,
                reason="probes ran but none reached a verdict, so nothing "
                       "about the model's behaviour was established"))
    else:
        status = _stage_status(manifest, STAGE_NAMES["ai_runtime"])
        if status == "failed":
            ledger.entries.append(_entry(
                "ai_runtime", STATUS_FAILED,
                reason=_stage_error(manifest, STAGE_NAMES["ai_runtime"])
                or "the stage did not complete"))
        else:
            ledger.entries.append(_entry(
                "ai_runtime", STATUS_NOT_ASSESSED,
                reason="no live probe was run; the model was never asked to "
                       "follow injected instructions, so its susceptibility "
                       "is unknown rather than acceptable"))

    # ---- email authentication -------------------------------------------
    mail_files = sorted(directory.glob("mail*.json"))
    if mail_files:
        findings = 0
        inconclusive: list[str] = []
        for path in mail_files:
            data = _load(path)
            findings += len(data.get("findings") or [])
            if not (data.get("dkim") or {}).get("found"):
                inconclusive.append(str(data.get("domain", "?")))
        status = STATUS_PARTIAL if inconclusive else STATUS_ASSESSED
        ledger.entries.append(_entry(
            "email_auth", status, findings=findings,
            checked=len(mail_files), total=len(mail_files),
            reason=(f"DKIM inconclusive for {', '.join(inconclusive)}: "
                    f"selectors are arbitrary and cannot be enumerated")
            if inconclusive else ""))
    else:
        status = _stage_status(manifest, STAGE_NAMES["email_auth"])
        if status == "failed":
            ledger.entries.append(_entry(
                "email_auth", STATUS_FAILED,
                reason=_stage_error(manifest, STAGE_NAMES["email_auth"])
                or "the stage did not complete"))
        else:
            ledger.entries.append(_entry(
                "email_auth", STATUS_NOT_ASSESSED,
                reason="no domain was audited"))

    # ---- awareness -------------------------------------------------------
    awareness_status = _stage_status(manifest, STAGE_NAMES["awareness"])
    if awareness_status == "ok":
        hits = 0
        for stage in manifest.get("stages") or []:
            if stage.get("name") == "awareness":
                hits = int(stage.get("findings", 0) or 0)
        ledger.entries.append(_entry(
            "awareness", STATUS_ASSESSED, findings=0, checked=hits,
            reason="no denominator: the number of people exposed to the lure "
                   "is not known to this tool"))
    elif awareness_status == "failed":
        ledger.entries.append(_entry(
            "awareness", STATUS_FAILED,
            reason=_stage_error(manifest, STAGE_NAMES["awareness"])
            or "the stage did not complete"))
    else:
        ledger.entries.append(_entry(
            "awareness", STATUS_NOT_ASSESSED,
            reason="no awareness campaign results were supplied"))

    # ---- detection coverage ---------------------------------------------
    # Emitting rules is not coverage. Only recorded outcomes would be.
    emitted = (directory / "sigma").is_dir()
    ledger.entries.append(_entry(
        "detection", STATUS_NOT_ASSESSED,
        reason=("Sigma rules were emitted but no detection outcomes were "
                "recorded; run `coldlight detect validate` and record the result"
                if emitted else
                "no detection validation was performed")))

    # ---- known-tool indicators -------------------------------------------
    # The interesting status here is PARTIAL, and it is the common one. A pack
    # whose indicators have started expiring, or which has not been refreshed,
    # still produced a scan -- but it no longer covers what it claims to, and
    # ASSESSED would say it did.
    ioc_files = sorted(directory.glob("ioc*.json"))
    if ioc_files:
        findings = active = total = 0
        reasons: list[str] = []
        current = True
        for path in ioc_files:
            data = _load(path)
            findings += len(data.get("findings") or [])
            active += int(data.get("indicators_active", 0) or 0)
            total += int(data.get("indicators_total", 0) or 0)
            if not data.get("fully_current", False):
                current = False
            note = str(data.get("coverage_note", "") or "")
            if note and note not in reasons:
                reasons.append(note)
        if not total:
            # A report with no indicators in it is not a check that passed.
            ledger.entries.append(_entry(
                "ioc", STATUS_FAILED, findings=findings, checked=0, total=0,
                reason="an indicator report was present but carried no "
                       "indicators, so nothing was actually looked for"))
        elif not active:
            # Every indicator had expired. The scan ran, and the report says
            # what those indicators would once have flagged -- but nothing the
            # pack still stands behind was looked for. PARTIAL would claim the
            # class was covered in part; it was not covered at all.
            ledger.entries.append(_entry(
                "ioc", STATUS_FAILED, findings=findings, checked=0,
                total=total,
                reason="every indicator in the supplied pack(s) has expired, "
                       "so nothing the pack still vouches for was looked "
                       "for"))
        else:
            ledger.entries.append(_entry(
                "ioc", STATUS_ASSESSED if current else STATUS_PARTIAL,
                findings=findings, checked=active, total=total,
                reason="; ".join(reasons[:3])))
    else:
        status = _stage_status(manifest, STAGE_NAMES["ioc"])
        if status == "failed":
            ledger.entries.append(_entry(
                "ioc", STATUS_FAILED,
                reason=_stage_error(manifest, STAGE_NAMES["ioc"])
                or "the stage did not complete"))
        else:
            ledger.entries.append(_entry(
                "ioc", STATUS_NOT_ASSESSED,
                reason="no indicator pack was supplied, so markers left by a "
                       "known tool were not looked for"))

    # ---- classes this tool cannot assess at all --------------------------
    for spec in CLASSES:
        if spec.tier == TIER_EXTERNAL:
            ledger.entries.append(_entry(
                spec.key, STATUS_NOT_ASSESSED, reason=EXTERNAL_REASON))

    return ledger


def build_from_run(run_result, out_dir: str | Path) -> Ledger:
    """Convenience wrapper for the orchestrator: the artifacts are on disk by
    the time this is called, so the directory is the single source of truth."""
    return build_ledger(out_dir)


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def text_ledger(ledger: Ledger) -> str:
    out: list[str] = []
    out.append("=" * 72)
    out.append("ASSURANCE LEDGER — what was assessed, and what nobody looked at")
    out.append("=" * 72)
    out.append("")
    out.append(f"  {'class':<36} {'status':<13} {'findings':>8}  checked")
    out.append(f"  {'-' * 36} {'-' * 13} {'-' * 8}  {'-' * 12}")

    for entry in ledger.covered:
        findings = str(entry.findings) if entry.examined else "-"
        out.append(f"  {entry.label[:36]:<36} {entry.status:<13} "
                   f"{findings:>8}  {entry.ratio}")

    out.append("")
    out.append("  Not covered by this tool (separate assessment required):")
    for entry in ledger.external:
        out.append(f"    {entry.label}")

    out.append("")
    checked, total = ledger.unit_coverage()
    out.append(f"Examined {ledger.examined_classes} of "
               f"{len(ledger.covered)} class(es) in this tool's scope; "
               f"{len(ledger.external)} further class(es) are outside it "
               f"entirely.")
    if total:
        # Deliberately NOT presented as an overall coverage percentage. The
        # denominator here is only the classes that actually ran, so a bare
        # "100%" beside a 3-of-7 assessment would be exactly the kind of
        # false reassurance this ledger exists to prevent.
        out.append(f"Within those examined classes: {checked} of {total} "
                   f"unit(s) checked.")
    out.append(f"Findings: {ledger.total_findings} — this count reflects ONLY "
               f"the classes marked ASSESSED or PARTIAL above.")

    unexamined = [e for e in ledger.covered if not e.examined]
    if unexamined:
        out.append("")
        out.append(f"!! {len(unexamined)} class(es) in scope were NOT examined. "
                   f"This is not a clean result for them:")
        for entry in unexamined:
            marker = "FAILED" if entry.status == STATUS_FAILED else "not assessed"
            out.append(f"   - {entry.label} ({marker}): {entry.reason}")

    partial = [e for e in ledger.entries if e.status == STATUS_PARTIAL]
    if partial:
        out.append("")
        out.append("Partial coverage:")
        for entry in partial:
            out.append(f"   - {entry.label}: {entry.reason}")

    notes = [e for e in ledger.covered if e.note and e.examined]
    if notes:
        out.append("")
        out.append("Limits of what was examined:")
        for entry in notes:
            out.append(f"   - {entry.label}: {entry.note}")

    return "\n".join(out)


def markdown_ledger(ledger: Ledger) -> str:
    out: list[str] = []
    out.append("## Assurance ledger")
    out.append("")
    out.append("What this assessment examined, and what it did not. A class "
               "marked *not assessed* is **unknown**, not clean.")
    out.append("")
    out.append("| Check class | Status | Findings | Checked |")
    out.append("|-------------|--------|----------|---------|")
    for entry in ledger.covered:
        findings = str(entry.findings) if entry.examined else "—"
        out.append(f"| {entry.label} | **{entry.status}** | {findings} "
                   f"| {entry.ratio} |")
    out.append("")

    checked, total = ledger.unit_coverage()
    out.append(f"**Examined {ledger.examined_classes} of "
               f"{len(ledger.covered)} class(es)** in this tool's scope; "
               f"{len(ledger.external)} further class(es) are outside it "
               f"entirely.")
    if total:
        out.append("")
        out.append(f"Within those examined classes: {checked} of {total} "
                   f"unit(s) checked. This is **not** an overall coverage "
                   f"figure — the denominator counts only what was examined.")
    out.append("")

    unexamined = [e for e in ledger.covered if not e.examined]
    if unexamined:
        out.append("### Not examined")
        out.append("")
        for entry in unexamined:
            marker = ("**FAILED**" if entry.status == STATUS_FAILED
                      else "not assessed")
            out.append(f"- **{entry.label}** — {marker}: {entry.reason}")
        out.append("")

    partial = [e for e in ledger.entries if e.status == STATUS_PARTIAL]
    if partial:
        out.append("### Partial coverage")
        out.append("")
        for entry in partial:
            out.append(f"- **{entry.label}** — {entry.reason}")
        out.append("")

    out.append("### Outside this assessment entirely")
    out.append("")
    out.append("These require a separate engagement and were **not** examined:")
    out.append("")
    for entry in ledger.external:
        out.append(f"- {entry.label}")
    out.append("")
    return "\n".join(out)
