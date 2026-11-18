#!/usr/bin/env python3
"""
ColdLight engagement report: assemble every module's output into the actual
deliverable.

ColdLight produces findings from five places -- dependency/SBOM CVEs, static code
analysis, email authentication posture, awareness-campaign hits, and VEX triage
decisions. None of that is a report. This turns it into one: executive summary,
findings ranked by severity with evidence and remediation, campaign results,
and appendices.

THE EDITORIAL PROBLEM THIS SOLVES: a dependency scan can return 60 CVEs.
Sixty individual findings is an unreadable report that gets skimmed and
ignored. So findings are TRIAGED, the way a human analyst would:

  * known-exploited (CISA KEV) and critical items are promoted to standalone
    findings -- they are the action items
  * the long tail is grouped into one finding per source with a table, so the
    detail is present without burying the things that matter
  * anything marked `not_affected` or `fixed` in a VEX triage file moves to an
    appendix with its justification, instead of padding the finding count

It also states plainly what was NOT assessed. A report that implies more
coverage than it has is worse than a short one.

Read-only: reads the JSON/DB files you point it at and writes a document.
Stdlib only.
"""

from __future__ import annotations

import html
import json
import re
import sqlite3
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from coldlight_config import __version__ as TOOL_VERSION

TOOL_NAME = "ColdLight"

# One ordering for every source. MODERATE (OSV) folds into MEDIUM; UNKNOWN
# stays its own bucket because an unscored CVE is untriaged, not harmless.
SEVERITY_ORDER = {
    "CRITICAL": 6, "HIGH": 5, "MEDIUM": 4, "LOW": 3, "UNKNOWN": 2, "INFO": 1,
}

_SEVERITY_ALIASES = {
    "MODERATE": "MEDIUM",
    "": "UNKNOWN",
    "OK": "INFO",
    "NONE": "INFO",
}

SEVERITY_COLOURS = {
    "CRITICAL": "#b3123a",
    "HIGH": "#d4572a",
    "MEDIUM": "#b8860b",
    "LOW": "#3a7ca5",
    "UNKNOWN": "#6b7280",
    "INFO": "#6b7280",
}

# Severity provenance, for presentation. The canonical values live in
# coldlight_vulnintel.SEVERITY_SOURCES; "mixed" is a report-level aggregate used
# when a grouped finding draws on several authorities.
SEV_SRC_MIXED = "mixed"

SEVERITY_SOURCE_LABELS = {
    "nvd-cvss": "NVD CVSS base score",
    "osv-database": "advisory database rating",
    "cisa-kev": "raised by ColdLight (listed in CISA KEV)",
    "coldlight-rule": "ColdLight rule table",
    "coldlight-judgement": "ColdLight assessment",
    "unscored": "no severity published",
    SEV_SRC_MIXED: "mixed sources",
    "": "unrecorded",
}

# Sources that are an external measurement rather than a ColdLight opinion.
MEASURED_SOURCES = frozenset({"nvd-cvss", "osv-database"})


def severity_source_label(source: str) -> str:
    return SEVERITY_SOURCE_LABELS.get(source or "", source or "unrecorded")


def is_measured(source: str) -> bool:
    return (source or "") in MEASURED_SOURCES


CATEGORY_DEPENDENCY = "Third-party dependencies"
CATEGORY_CODE = "Source code"
CATEGORY_EMAIL = "Email authentication"
CATEGORY_AWARENESS = "Security awareness"
CATEGORY_AI = "AI/ML systems"
CATEGORY_AI_RUNTIME = "AI runtime behaviour (observed)"
CATEGORY_HISTORY = "Secrets in version history"


class EngagementError(ValueError):
    """An input file could not be used."""


def normalise_severity(value: str) -> str:
    key = (value or "").strip().upper()
    key = _SEVERITY_ALIASES.get(key, key)
    return key if key in SEVERITY_ORDER else "UNKNOWN"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------

@dataclass
class Engagement:
    engagement_id: str = ""
    authorization_reference: str = ""
    client: str = ""
    assessor: str = ""
    title: str = ""
    period: str = ""
    scope: list[str] = field(default_factory=list)

    @property
    def display_title(self) -> str:
        return self.title or "Security Assessment Report"


@dataclass
class Finding:
    title: str
    severity: str
    category: str
    description: str = ""
    remediation: str = ""
    evidence: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    identifiers: list[str] = field(default_factory=list)   # CVE / CWE / rule id
    kev: bool = False
    # Where this severity came from: an external measurement, or our own
    # judgement. See coldlight_vulnintel.SEVERITY_SOURCES.
    severity_source: str = ""
    count: int = 1                      # how many raw items this represents
    finding_id: str = ""                # assigned after ranking
    vex_status: str = ""
    vex_justification: str = ""

    @property
    def rank(self) -> tuple:
        return (
            0 if self.kev else 1,
            -SEVERITY_ORDER.get(self.severity, 0),
            -self.count,
            self.title,
        )

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AwarenessSummary:
    total_runs: int = 0
    unique_hosts: int = 0
    unique_users: int = 0
    excluded_runs: int = 0
    by_vector: dict[str, int] = field(default_factory=dict)
    by_day: dict[str, int] = field(default_factory=dict)
    engagements: list[str] = field(default_factory=list)


@dataclass
class MailSummary:
    domain: str = ""
    spoofable: bool = False
    protection_level: str = ""
    verdict: str = ""
    subdomains_spoofable: bool = False


@dataclass
class Report:
    engagement: Engagement = field(default_factory=Engagement)
    findings: list[Finding] = field(default_factory=list)
    suppressed: list[Finding] = field(default_factory=list)
    awareness: AwarenessSummary | None = None
    mail: MailSummary | None = None
    sources: list[str] = field(default_factory=list)
    not_assessed: list[str] = field(default_factory=list)
    generated: str = ""
    # Coverage ledger (coldlight_assurance.Ledger.to_dict()), when one was built.
    assurance: dict | None = None

    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return dict(sorted(counts.items(),
                           key=lambda kv: -SEVERITY_ORDER.get(kv[0], 0)))

    def provenance_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            key = finding.severity_source or ""
            counts[key] = counts.get(key, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: -kv[1]))

    @property
    def measured_count(self) -> int:
        return sum(1 for f in self.findings if is_measured(f.severity_source))

    @property
    def assessed_count(self) -> int:
        return len(self.findings) - self.measured_count

    @property
    def kev_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.kev]

    @property
    def raw_item_count(self) -> int:
        return sum(f.count for f in self.findings)

    def finalise(self) -> None:
        """Rank findings and assign stable ids."""
        self.findings.sort(key=lambda f: f.rank)
        for index, finding in enumerate(self.findings, start=1):
            finding.finding_id = f"RO-{index:03d}"
        self.generated = self.generated or _now()

    def to_dict(self) -> dict:
        return {
            "tool": f"{TOOL_NAME} {TOOL_VERSION}",
            "generated": self.generated,
            "engagement": asdict(self.engagement),
            "severity_counts": self.severity_counts(),
            "severity_provenance": self.provenance_counts(),
            "severities_measured": self.measured_count,
            "severities_assessed_by_coldlight": self.assessed_count,
            "finding_count": len(self.findings),
            "raw_item_count": self.raw_item_count,
            "known_exploited": len(self.kev_findings),
            "findings": [f.to_dict() for f in self.findings],
            "suppressed": [f.to_dict() for f in self.suppressed],
            "awareness": asdict(self.awareness) if self.awareness else None,
            "mail": asdict(self.mail) if self.mail else None,
            "sources": self.sources,
            "not_assessed": self.not_assessed,
            "assurance": self.assurance,
        }


# ---------------------------------------------------------------------------
# Loading inputs
# ---------------------------------------------------------------------------

def _load_json(path: str | Path) -> dict:
    file_path = Path(path)
    if not file_path.is_file():
        raise EngagementError(f"no such file: {file_path}")
    try:
        data = json.loads(file_path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise EngagementError(f"{file_path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise EngagementError(f"{file_path}: expected a JSON object")
    return data


def load_vex_decisions(path: str | Path) -> dict[str, tuple[str, str]]:
    """Map vulnerability id -> (status, justification-or-impact) from a VEX
    triage file, so triaged-away findings don't pad the report."""
    data = _load_json(path)
    decisions: dict[str, tuple[str, str]] = {}
    for statement in data.get("statements") or []:
        if not isinstance(statement, dict):
            continue
        identifier = str(statement.get("vulnerability", "") or "")
        status = str(statement.get("status", "") or "")
        if not identifier or not status:
            continue
        reason = (str(statement.get("justification", "") or "")
                  or str(statement.get("impact_statement", "") or "")
                  or str(statement.get("action_statement", "") or ""))
        decisions[identifier.upper()] = (status, reason)
        for alias in statement.get("aliases") or []:
            decisions.setdefault(str(alias).upper(), (status, reason))
    return decisions


def load_vulnerability_findings(path: str | Path) -> tuple[list[Finding], list[str]]:
    """Findings from a `scan deps` / `scan sbom` JSON report.

    Returns (findings, not_assessed_notes).
    """
    data = _load_json(path)
    notes: list[str] = []
    findings: list[Finding] = []

    source = data.get("inventory_source") or "dependency manifests"

    for entry in data.get("findings") or []:
        if not isinstance(entry, dict):
            continue
        identifier = str(entry.get("identifier", "") or "")
        if not identifier:
            continue

        package = str(entry.get("package", "") or "")
        version = str(entry.get("installed_version", "") or "")
        ecosystem = str(entry.get("ecosystem", "") or "")
        fixes = [str(v) for v in (entry.get("fixed_versions") or [])]

        remediation = (f"Upgrade {package} to {', '.join(fixes[:3])}."
                       if fixes and package else
                       "No fixed version is published; assess whether the "
                       "component can be removed, replaced or isolated.")

        identifiers = [identifier]
        if entry.get("cwe"):
            identifiers.append(str(entry["cwe"]))

        evidence = []
        if package:
            evidence.append(f"{package} {version} ({ecosystem})")
        if entry.get("cvss_score") is not None:
            evidence.append(f"CVSS {entry['cvss_score']}")
        if fixes:
            evidence.append("fixed in " + ", ".join(fixes[:4]))

        findings.append(Finding(
            title=(f"{identifier} in {package} {version}".strip()
                   if package else identifier),
            severity=normalise_severity(str(entry.get("severity", ""))),
            severity_source=str(entry.get("severity_source", "") or ""),
            category=CATEGORY_DEPENDENCY,
            description=str(entry.get("summary", "") or ""),
            remediation=remediation,
            evidence=evidence,
            references=[str(r) for r in (entry.get("references") or [])][:4],
            identifiers=identifiers,
            kev=bool(entry.get("kev")),
        ))

    not_checked = int(data.get("not_checked", 0) or 0)
    if not_checked:
        reasons = data.get("not_checked_reasons") or {}
        detail = "; ".join(f"{count} {reason}"
                           for reason, count in list(reasons.items())[:4])
        notes.append(
            f"{not_checked} component(s) listed in the inventory ({source}) "
            f"could not be checked against vulnerability data and are "
            f"UNKNOWN rather than clean: {detail}"
        )

    for error in data.get("errors") or []:
        notes.append(f"Vulnerability lookup error: {error}")

    return findings, notes


def load_code_findings(path: str | Path) -> tuple[list[Finding], list[str]]:
    """Findings from a `scan code` JSON report, grouped by rule.

    A SAST report lists the rule once with its occurrences, not the same
    finding repeated per line.
    """
    data = _load_json(path)
    grouped: dict[str, Finding] = {}

    for entry in data.get("findings") or []:
        if not isinstance(entry, dict):
            continue
        rule_id = str(entry.get("rule_id", "") or "unknown")
        location = f"{entry.get('file', '?')}:{entry.get('line', '?')}"
        snippet = str(entry.get("snippet", "") or "")

        if rule_id not in grouped:
            grouped[rule_id] = Finding(
                title=str(entry.get("title", "") or rule_id),
                severity=normalise_severity(str(entry.get("severity", ""))),
                severity_source=str(entry.get("severity_source", "")
                                    or "coldlight-rule"),
                category=CATEGORY_CODE,
                description=(
                    "Static analysis identified this pattern in the codebase. "
                    "Each occurrence should be confirmed in context."
                ),
                remediation=str(entry.get("remediation", "") or ""),
                identifiers=[rule_id] + ([str(entry["cwe"])]
                                         if entry.get("cwe") else []),
                count=0,
            )
        finding = grouped[rule_id]
        finding.count += 1
        if len(finding.evidence) < 20:
            finding.evidence.append(f"{location}  |  {snippet}"
                                    if snippet else location)

    for finding in grouped.values():
        if finding.count > len(finding.evidence):
            finding.evidence.append(
                f"... and {finding.count - len(finding.evidence)} further "
                f"occurrence(s)"
            )
        if finding.count > 1:
            finding.title = f"{finding.title} ({finding.count} occurrences)"

    notes = [f"Code scan error: {e}" for e in (data.get("errors") or [])]
    files = data.get("files_scanned")
    if files is not None:
        notes.append(
            f"Static analysis covered {files} file(s) using pattern matching "
            f"only; it does not perform dataflow analysis, so absence of a "
            f"finding is not proof of absence of a flaw."
        )
    return list(grouped.values()), notes


def load_ai_findings(path: str | Path) -> tuple[list[Finding], list[str]]:
    """Findings from a `scan ai` JSON report, grouped by rule.

    These carry OWASP LLM and MITRE ATLAS identifiers alongside the CWE, so
    the reader can look the weakness class up in a published catalogue rather
    than taking our word for it.
    """
    data = _load_json(path)
    grouped: dict[str, Finding] = {}

    for entry in data.get("findings") or []:
        if not isinstance(entry, dict):
            continue
        rule_id = str(entry.get("rule_id", "") or "unknown")
        line = entry.get("line")
        location = (f"{entry.get('file', '?')}:{line}" if line
                    else str(entry.get("file", "?")))
        snippet = str(entry.get("snippet", "") or "")

        if rule_id not in grouped:
            identifiers = [rule_id]
            if entry.get("cwe"):
                identifiers.append(str(entry["cwe"]))
            if entry.get("owasp"):
                owasp_name = str(entry.get("owasp_name", "") or "").strip()
                identifiers.append(
                    f"OWASP {entry['owasp']}"
                    + (f" {owasp_name}" if owasp_name else ""))
            if entry.get("atlas"):
                atlas_name = str(entry.get("atlas_name", "") or "").strip()
                identifiers.append(
                    f"ATLAS {entry['atlas']}"
                    + (f" {atlas_name}" if atlas_name else ""))

            grouped[rule_id] = Finding(
                title=str(entry.get("title", "") or rule_id),
                severity=normalise_severity(str(entry.get("severity", ""))),
                severity_source=str(entry.get("severity_source", "")
                                    or "coldlight-rule"),
                category=CATEGORY_AI,
                description=(
                    "Static review of AI/ML code and model artifacts "
                    "identified this pattern. Each occurrence should be "
                    "confirmed in context."
                ),
                remediation=str(entry.get("remediation", "") or ""),
                identifiers=identifiers,
                count=0,
            )
        finding = grouped[rule_id]
        finding.count += 1
        if len(finding.evidence) < 20:
            finding.evidence.append(f"{location}  |  {snippet}"
                                    if snippet else location)

    for finding in grouped.values():
        if finding.count > len(finding.evidence):
            finding.evidence.append(
                f"... and {finding.count - len(finding.evidence)} further "
                f"occurrence(s)"
            )
        if finding.count > 1:
            finding.title = f"{finding.title} ({finding.count} occurrences)"

    notes = [f"AI/ML scan error: {e}" for e in (data.get("errors") or [])]

    files = data.get("files_scanned")
    artifacts = data.get("model_artifacts") or []
    unsafe = data.get("unsafe_artifact_count")
    if files is not None:
        detail = f"AI/ML review covered {files} file(s)"
        if artifacts:
            detail += f" and {len(artifacts)} model artifact(s)"
            if unsafe:
                detail += (f", of which {unsafe} are in a code-executing "
                           f"format")
        notes.append(detail + ".")

    # The limitation that matters most: a static pass says nothing about how
    # the model behaves. Without this the report reads as though the system
    # had been tested for prompt injection.
    notes.append(
        "AI/ML assessment was static only. No model was prompted, probed or "
        "adversarially tested, and model artifacts were inspected by their "
        "bytes without being deserialised. Susceptibility to prompt "
        "injection, jailbreak or data extraction is therefore NOT established "
        "by this assessment."
    )
    return list(grouped.values()), notes


def load_probe_findings(path: str | Path) -> tuple[list[Finding],
                                                   list[str]]:
    """Findings from a `probe` JSON report: OBSERVED model behaviour.

    Unlike every other loader here, these describe something the assessment
    watched happen rather than a pattern it recognised. The severity is still
    our judgement -- how much an injectable channel matters depends on what
    the model can reach -- but the outcome is evidence.
    """
    data = _load_json(path)
    findings: list[Finding] = []

    for entry in data.get("findings") or []:
        if not isinstance(entry, dict):
            continue
        probe_id = str(entry.get("probe_id", "") or "unknown")
        identifiers = [probe_id]
        if entry.get("owasp"):
            identifiers.append(f"OWASP {entry['owasp']}")
        channel = str(entry.get("channel", "") or "")

        # The probe's detail is phrased as a clause; this is a written
        # deliverable, so it starts a sentence here.
        detail = str(entry.get("detail", "") or "").strip()
        if detail:
            detail = detail[0].upper() + detail[1:]
        observed = (f"Observed against the live endpoint via the {channel} "
                    f"channel." if channel
                    else "Observed against the live endpoint.")

        findings.append(Finding(
            title=str(entry.get("title", "") or probe_id),
            severity=normalise_severity(str(entry.get("severity", ""))),
            severity_source=str(entry.get("severity_source", "")
                                or "coldlight-judgement"),
            category=CATEGORY_AI_RUNTIME,
            description=f"{observed} {detail}".strip(),
            remediation=str(entry.get("remediation", "") or ""),
            identifiers=identifiers,
            evidence=([str(entry["evidence"])] if entry.get("evidence")
                      else []),
            count=1,
        ))

    notes: list[str] = []
    counts = data.get("counts") or {}
    target = str(data.get("target", "") or "")
    reference = str(data.get("authorization_reference", "") or "")

    if target:
        detail = f"Live probing targeted {target}"
        if reference:
            detail += f" under authorization {reference}"
        notes.append(detail + ".")

    if not data.get("verdict_established", False):
        # The one that must never be silent: probes that all failed say
        # nothing, and would otherwise read as a model that held the line.
        notes.append(
            "The live probe run reached NO verdict: every probe was "
            "inconclusive (unreachable endpoint, error response, or a reply "
            "that could not be read). The model's susceptibility is "
            "therefore UNKNOWN, not acceptable."
        )
    else:
        inconclusive = int(counts.get("inconclusive", 0) or 0)
        probes = int(counts.get("probes", 0) or 0)
        if inconclusive:
            notes.append(
                f"{inconclusive} of {probes} live probe(s) were inconclusive "
                f"and establish nothing either way."
            )
        if not (data.get("findings") or []):
            notes.append(
                "No canary was obeyed. That means these specific probes did "
                "not land; it is not evidence that the model is robust to "
                "prompt injection."
            )

    for limitation in data.get("limitations") or []:
        notes.append(str(limitation))

    return findings, notes


def load_history_findings(path: str | Path) -> tuple[list[Finding],
                                                     list[str]]:
    """Findings from a `scan history` JSON report.

    The distinction that matters is carried into the title: a secret still in
    HEAD is also reported by the code scan, while one deleted from HEAD is
    the finding nobody else surfaces -- and the one most likely to be
    believed fixed.
    """
    data = _load_json(path)
    findings: list[Finding] = []

    for entry in data.get("findings") or []:
        if not isinstance(entry, dict):
            continue
        rule_id = str(entry.get("rule_id", "") or "unknown")
        recoverable = bool(entry.get("recoverable_only"))
        commit = str(entry.get("first_commit", "") or "")[:9]

        identifiers = [rule_id]
        if entry.get("cwe"):
            identifiers.append(str(entry["cwe"]))
        if commit:
            identifiers.append(f"commit {commit}")

        state = ("REMOVED from the working tree but still recoverable from "
                 "history" if recoverable
                 else "still present in the working tree")
        description = (
            f"Committed to version history and {state}. "
            f"Introduced in commit {commit}"
            + (f" by {entry['first_author']}" if entry.get("first_author")
               else "")
            + "."
        )
        if int(entry.get("commit_count", 1) or 1) > 1:
            description += (f" The same credential appears in "
                            f"{entry['commit_count']} commits.")
        if recoverable:
            description += (" Deleting the line did not remove it: the blob "
                            "is still reachable, so every clone of this "
                            "repository still contains the credential.")

        evidence = []
        if entry.get("file"):
            location = str(entry["file"])
            if entry.get("snippet"):
                location += f"  |  {entry['snippet']}"
            evidence.append(location)

        findings.append(Finding(
            title=(f"{entry.get('title', rule_id)} (in git history)"
                   if recoverable
                   else f"{entry.get('title', rule_id)} (committed and still "
                        f"present)"),
            severity=normalise_severity(str(entry.get("severity", ""))),
            severity_source=str(entry.get("severity_source", "")
                                or "coldlight-rule"),
            category=CATEGORY_HISTORY,
            description=description,
            remediation=str(data.get("remediation", "")
                            or entry.get("remediation", "") or ""),
            identifiers=identifiers,
            evidence=evidence,
            count=1,
        ))

    notes: list[str] = []
    repo = data.get("repository") or {}

    if not data.get("assessed", False):
        # The shallow-clone case. Silence here would be the worst outcome:
        # the finding count would read as a clean history.
        reason = str(repo.get("error", "") or data.get("truncated", "")
                     or "the history could not be read")
        notes.append(
            f"Version history was NOT assessed: {reason} A credential that "
            f"was committed and later deleted would not have been found, so "
            f"this area is UNKNOWN rather than clean."
        )
    else:
        commits = data.get("commits_scanned")
        if commits is not None:
            notes.append(f"Version-history scan walked {commits} commit(s) "
                         f"reachable from any ref.")
        counts = data.get("counts") or {}
        recoverable = int(counts.get("recoverable_only", 0) or 0)
        if recoverable:
            notes.append(
                f"{recoverable} credential(s) are no longer in the working "
                f"tree but remain recoverable from history. Rotation is the "
                f"only effective remediation."
            )

    for limitation in data.get("limitations") or []:
        notes.append(str(limitation))

    for error in data.get("errors") or []:
        notes.append(f"History scan error: {error}")

    return findings, notes


def load_mail_findings(path: str | Path) -> tuple[list[Finding], MailSummary,
                                                  list[str]]:
    """Findings and a summary from a `mail audit` JSON report."""
    data = _load_json(path)
    domain = str(data.get("domain", "") or "")

    summary = MailSummary(
        domain=domain,
        spoofable=bool(data.get("spoofable")),
        protection_level=str(data.get("protection_level", "") or ""),
        verdict=str(data.get("verdict", "") or ""),
        subdomains_spoofable=bool(data.get("subdomains_spoofable")),
    )

    findings: list[Finding] = []
    for entry in data.get("findings") or []:
        if not isinstance(entry, dict):
            continue
        check = str(entry.get("check", "") or "")
        findings.append(Finding(
            title=f"{str(entry.get('title', '') or '')} ({domain})".strip(),
            severity=normalise_severity(str(entry.get("severity", ""))),
            severity_source=str(entry.get("severity_source", "")
                                or "coldlight-judgement"),
            category=CATEGORY_EMAIL,
            description=str(entry.get("detail", "") or ""),
            remediation=str(entry.get("remediation", "") or ""),
            evidence=[f"Domain: {domain}", f"Check: {check}"],
            identifiers=[check] if check else [],
        ))

    notes: list[str] = []
    dkim = data.get("dkim") or {}
    if not dkim.get("found"):
        notes.append(
            f"DKIM could not be confirmed for {domain}: selectors are "
            f"arbitrary and cannot be enumerated from DNS, so the probe is "
            f"inconclusive rather than negative."
        )
    if not data.get("mta_sts", {}).get("fetch_attempted", True):
        notes.append(
            f"The MTA-STS policy for {domain} was not fetched, so its mode "
            f"was not verified."
        )
    return findings, summary, notes


def load_awareness(db_path: str | Path) -> tuple[AwarenessSummary,
                                                 list[Finding], list[str]]:
    """Campaign results from the hits database."""
    path = Path(db_path)
    if not path.is_file():
        raise EngagementError(f"no such database: {path}")

    try:
        import coldlight_report as rr
        connection = rr.connect(str(path))
        stats = rr.compute_stats(connection)
    except sqlite3.Error as exc:
        raise EngagementError(f"{path}: {exc}") from exc

    summary = AwarenessSummary(
        total_runs=int(stats.get("total_runs", 0) or 0),
        unique_hosts=int(stats.get("unique_hosts", 0) or 0),
        unique_users=int(stats.get("unique_users", 0) or 0),
        excluded_runs=int(stats.get("excluded_runs", 0) or 0),
        by_vector=dict(stats.get("by_vector", {}) or {}),
        by_day=dict(stats.get("by_day", {}) or {}),
        engagements=[str(k) for k in (stats.get("per_engagement", {}) or {})],
    )

    findings: list[Finding] = []
    if summary.total_runs:
        vectors = ", ".join(f"{k}={v}" for k, v in summary.by_vector.items())
        usb_runs = summary.by_vector.get("usb", 0)

        if usb_runs:
            findings.append(Finding(
                title=(f"Staff executed an untrusted file from removable "
                       f"media ({usb_runs} run(s))"),
                severity="HIGH",
                severity_source="coldlight-judgement",
                category=CATEGORY_AWARENESS,
                description=(
                    "During the authorised awareness test, staff mounted "
                    "unknown removable media and ran an executable from it. "
                    "The payload was benign and only recorded the event, but "
                    "the same action with a malicious file would have "
                    "executed attacker-controlled code in the user's context."
                ),
                remediation=(
                    "Deliver short targeted training to the affected "
                    "population, and apply a technical control so the "
                    "decision is not left to the user: block execution from "
                    "removable media by policy (e.g. AppLocker / WDAC "
                    "path rules), or restrict removable storage entirely."
                ),
                evidence=[
                    f"{usb_runs} execution(s) from removable media",
                    f"{summary.unique_hosts} unique host(s), "
                    f"{summary.unique_users} unique user(s)",
                ],
                identifiers=["T1091", "T1204.002"],
                count=usb_runs,
            ))

        link_runs = (summary.by_vector.get("link", 0)
                     + summary.by_vector.get("qr", 0))
        if link_runs:
            findings.append(Finding(
                title=f"Staff followed an untrusted link ({link_runs} click(s))",
                severity="MEDIUM",
                severity_source="coldlight-judgement",
                category=CATEGORY_AWARENESS,
                description=(
                    "Staff visited a tracked link delivered by the simulated "
                    "phishing vector. The landing page requested no "
                    "credentials; a real campaign would have."
                ),
                remediation=(
                    "Pair awareness training with technical controls: link "
                    "rewriting/inspection at the mail gateway, and enforce "
                    "phishing-resistant MFA so a captured password is not "
                    "sufficient."
                ),
                evidence=[f"Clicks by vector: {vectors}"],
                identifiers=["T1566.002"],
                count=link_runs,
            ))

    notes = [
        "Awareness results are counts of observed behaviour. No measurement "
        "was made of whether security monitoring detected the activity; run "
        "`coldlight detect validate` to assess detection coverage."
    ]
    if summary.excluded_runs:
        notes.append(
            f"{summary.excluded_runs} run(s) matched the opt-out safe-list and "
            f"are excluded from the headline figures."
        )
    return summary, findings, notes


# ---------------------------------------------------------------------------
# Triage: promote what matters, group the tail, suppress what VEX cleared
# ---------------------------------------------------------------------------

GROUP_THRESHOLD = 3     # fewer than this in the tail and grouping adds nothing


def apply_vex(findings: list[Finding],
              decisions: dict[str, tuple[str, str]]) -> tuple[list[Finding],
                                                              list[Finding]]:
    """Split findings into (reportable, suppressed) using VEX decisions.

    `not_affected` and `fixed` move out of the finding list: a report padded
    with vulnerabilities the team has already shown do not apply trains the
    reader to ignore it.
    """
    reportable: list[Finding] = []
    suppressed: list[Finding] = []

    for finding in findings:
        status = reason = ""
        for identifier in finding.identifiers:
            if identifier.upper() in decisions:
                status, reason = decisions[identifier.upper()]
                break

        if status in ("not_affected", "fixed"):
            finding.vex_status = status
            finding.vex_justification = reason
            suppressed.append(finding)
        else:
            if status:
                finding.vex_status = status
            reportable.append(finding)

    return reportable, suppressed


def group_dependency_findings(findings: list[Finding]) -> list[Finding]:
    """Promote KEV/critical dependency findings; group the remainder.

    Sixty standalone CVE findings is noise. The ones that drive action get
    their own entry; the rest become one finding carrying the full list, so
    nothing is lost and nothing is buried.
    """
    dependency = [f for f in findings if f.category == CATEGORY_DEPENDENCY]
    other = [f for f in findings if f.category != CATEGORY_DEPENDENCY]
    if not dependency:
        return other

    promoted = [f for f in dependency
                if f.kev or f.severity == "CRITICAL"]
    tail = [f for f in dependency if f not in promoted]

    if len(tail) < GROUP_THRESHOLD:
        return other + promoted + tail

    tail.sort(key=lambda f: f.rank)
    worst = tail[0].severity
    packages = []
    for finding in tail:
        for item in finding.evidence:
            if "(" in item and item not in packages:
                packages.append(item)
                break

    evidence = [
        f"{f.identifiers[0]} — {f.evidence[0] if f.evidence else 'n/a'}"
        f"{'  [fix: ' + f.remediation.split('to ', 1)[-1].rstrip('.') + ']' if 'Upgrade' in f.remediation else ''}"
        for f in tail[:40]
    ]
    if len(tail) > 40:
        evidence.append(f"... and {len(tail) - 40} further advisory/advisories")

    sources = {f.severity_source for f in tail if f.severity_source}
    grouped_source = (sources.pop() if len(sources) == 1
                      else (SEV_SRC_MIXED if sources else ""))

    grouped = Finding(
        title=(f"Known-vulnerable third-party dependencies "
               f"({len(tail)} advisories across {len(packages)} component(s))"),
        severity=worst,
        severity_source=grouped_source,
        category=CATEGORY_DEPENDENCY,
        description=(
            "Components with published vulnerabilities are in use. These are "
            "grouped because they share one remediation path -- dependency "
            "upgrade -- and are listed individually in the evidence below. "
            "Items known to be exploited in the wild are reported separately "
            "above."
        ),
        remediation=(
            "Upgrade the affected components to the fixed versions listed. "
            "Where no fix exists, assess removal, replacement or isolation. "
            "Add a dependency scan to CI (`coldlight scan deps --fail-on high`) "
            "so regressions are caught before release."
        ),
        evidence=evidence,
        identifiers=sorted({i for f in tail for i in f.identifiers
                            if i.upper().startswith(("CVE-", "GHSA-"))})[:60],
        count=len(tail),
    )
    return other + promoted + [grouped]


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------

def build_report(*, engagement: Engagement,
                 vuln_paths=(), code_paths=(), mail_paths=(),
                 ai_paths=(), probe_paths=(), history_paths=(),
                 hits_db: str | None = None, vex_path: str | None = None,
                 group: bool = True, extra_limitations=(),
                 assurance: dict | None = None) -> Report:
    """Assemble the report.

    `extra_limitations` is how the orchestrator reports a stage that FAILED.
    A stage that did not run must never read as a stage that found nothing --
    so its absence is stated in the limitations rather than silently lowering
    the finding count.
    """
    report = Report(engagement=engagement)
    report.assurance = assurance
    collected: list[Finding] = []
    report.not_assessed.extend(extra_limitations)

    for path in vuln_paths or ():
        findings, notes = load_vulnerability_findings(path)
        collected.extend(findings)
        report.not_assessed.extend(notes)
        report.sources.append(f"Dependency/SBOM scan: {path}")

    for path in code_paths or ():
        findings, notes = load_code_findings(path)
        collected.extend(findings)
        report.not_assessed.extend(notes)
        report.sources.append(f"Static code analysis: {path}")

    for path in ai_paths or ():
        findings, notes = load_ai_findings(path)
        collected.extend(findings)
        report.not_assessed.extend(notes)
        report.sources.append(f"AI/ML security assessment: {path}")

    for path in history_paths or ():
        findings, notes = load_history_findings(path)
        collected.extend(findings)
        report.not_assessed.extend(notes)
        report.sources.append(f"Git history secret scan: {path}")

    for path in probe_paths or ():
        findings, notes = load_probe_findings(path)
        collected.extend(findings)
        report.not_assessed.extend(notes)
        report.sources.append(f"Live susceptibility probe: {path}")

    for path in mail_paths or ():
        findings, summary, notes = load_mail_findings(path)
        collected.extend(findings)
        report.not_assessed.extend(notes)
        report.mail = summary
        report.sources.append(f"Email authentication audit: {path}")

    if hits_db:
        summary, findings, notes = load_awareness(hits_db)
        collected.extend(findings)
        report.not_assessed.extend(notes)
        report.awareness = summary
        report.sources.append(f"Awareness campaign results: {hits_db}")

    if vex_path:
        decisions = load_vex_decisions(vex_path)
        collected, suppressed = apply_vex(collected, decisions)
        report.suppressed = sorted(suppressed, key=lambda f: f.rank)
        report.sources.append(f"VEX triage decisions: {vex_path}")

    if group:
        collected = group_dependency_findings(collected)

    report.findings = collected
    report.not_assessed.append(
        "No exploitation was attempted. Findings record the presence of a "
        "weakness, which is not the same as proven exploitability in this "
        "environment."
    )
    report.finalise()
    return report


# ---------------------------------------------------------------------------
# Executive summary
# ---------------------------------------------------------------------------

def executive_summary(report: Report) -> list[str]:
    """Plain-language paragraphs. No jargon, no severity table restated."""
    paragraphs: list[str] = []
    counts = report.severity_counts()
    serious = sum(v for k, v in counts.items()
                  if SEVERITY_ORDER.get(k, 0) >= SEVERITY_ORDER["HIGH"])

    opening = (
        f"This assessment produced {len(report.findings)} finding(s) "
        f"covering {report.raw_item_count} underlying item(s)."
    )
    if serious:
        opening += (f" {serious} are rated high or critical and warrant "
                    f"attention before the next release cycle.")
    else:
        opening += " None are rated high or critical."
    paragraphs.append(opening)

    kev = report.kev_findings
    if kev:
        paragraphs.append(
            f"**{len(kev)} finding(s) involve vulnerabilities that are known "
            f"to be exploited in the wild** (CISA Known Exploited "
            f"Vulnerabilities catalog). These are not theoretical and should "
            f"be treated as the first priority: "
            + ", ".join(f.identifiers[0] for f in kev[:5] if f.identifiers)
            + "."
        )

    if report.mail and report.mail.spoofable:
        level = report.mail.protection_level
        paragraphs.append(
            f"An attacker could send mail that appears to come from "
            f"**{report.mail.domain}** (DMARC protection: {level}). This "
            f"matters directly for phishing risk: it means a convincing "
            f"approach does not require a lookalike domain, and it is fixed "
            f"with DNS changes rather than a project."
        )

    if report.awareness and report.awareness.total_runs:
        awareness = report.awareness
        paragraphs.append(
            f"In the awareness campaign, {awareness.total_runs} action(s) "
            f"were recorded across {awareness.unique_hosts} host(s) and "
            f"{awareness.unique_users} user(s). The useful conclusion is not "
            f"that individuals failed, but that a single person's decision is "
            f"currently sufficient to start code running -- so the strongest "
            f"remediation is a technical control, with training as support."
        )

    if report.suppressed:
        paragraphs.append(
            f"{len(report.suppressed)} vulnerability record(s) were reviewed "
            f"and determined not to apply to this product, or already fixed. "
            f"They are listed in the appendix with their justifications "
            f"rather than counted as findings."
        )

    return paragraphs


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------

def _assurance_markdown(ledger: dict) -> str:
    """Render the coverage ledger. Takes the dict, so this module stays
    independent of coldlight_assurance."""
    entries = ledger.get("entries") or []
    covered = [e for e in entries if e.get("tier") == "covered"]
    external = [e for e in entries if e.get("tier") == "external"]

    out: list[str] = []
    out.append("## Assurance: what was assessed")
    out.append("")
    out.append("A class marked *not assessed* is **unknown, not clean**. "
               "This table exists so a short findings list cannot be mistaken "
               "for broad coverage.")
    out.append("")
    out.append("| Check class | Status | Findings | Checked |")
    out.append("|-------------|--------|----------|---------|")
    for entry in covered:
        examined = entry.get("status") in ("ASSESSED", "PARTIAL")
        findings = str(entry.get("findings", 0)) if examined else "—"
        out.append(f"| {entry.get('label', '')} | **{entry.get('status', '')}** "
                   f"| {findings} | {entry.get('ratio', '—')} |")
    out.append("")

    checked = ledger.get("units_checked")
    total = ledger.get("units_total")
    out.append(f"**Examined {ledger.get('classes_examined', 0)} of "
               f"{ledger.get('classes_in_tool_scope', 0)} class(es)** in "
               f"scope; {len(external)} further class(es) are outside it "
               f"entirely.")
    if total:
        out.append("")
        out.append(f"Within those examined classes: {checked} of {total} "
                   f"unit(s) checked. This is **not** an overall coverage "
                   f"figure — the denominator counts only what was examined.")
    out.append("")

    unexamined = [e for e in covered
                  if e.get("status") not in ("ASSESSED", "PARTIAL")]
    if unexamined:
        out.append("**Not examined:**")
        out.append("")
        for entry in unexamined:
            marker = ("**FAILED**" if entry.get("status") == "FAILED"
                      else "not assessed")
            out.append(f"- {entry.get('label', '')} — {marker}: "
                       f"{entry.get('reason', '')}")
        out.append("")

    partial = [e for e in entries if e.get("status") == "PARTIAL"]
    if partial:
        out.append("**Partial coverage:**")
        out.append("")
        for entry in partial:
            out.append(f"- {entry.get('label', '')} — {entry.get('reason', '')}")
        out.append("")

    if external:
        out.append("**Outside this assessment entirely** — these require a "
                   "separate engagement and were not examined:")
        out.append("")
        out.append(", ".join(e.get("label", "") for e in external) + ".")
        out.append("")
    return "\n".join(out)


_STATUS_COLOUR = {
    "ASSESSED": "#2e7d4f",
    "PARTIAL": "#b8860b",
    "NOT ASSESSED": "#6b7280",
    "FAILED": "#b3123a",
}


def _assurance_html(ledger: dict) -> list[str]:
    entries = ledger.get("entries") or []
    covered = [e for e in entries if e.get("tier") == "covered"]
    external = [e for e in entries if e.get("tier") == "external"]

    out: list[str] = ["<h2>Assurance: what was assessed</h2>"]
    out.append('<p class="note">A class marked <strong>not assessed</strong> '
               'is unknown, not clean. This table exists so a short findings '
               'list cannot be mistaken for broad coverage.</p>')
    out.append("<table><thead><tr><th>Check class</th><th>Status</th>"
               "<th>Findings</th><th>Checked</th></tr></thead><tbody>")
    for entry in covered:
        status = entry.get("status", "")
        examined = status in ("ASSESSED", "PARTIAL")
        findings = str(entry.get("findings", 0)) if examined else "—"
        colour = _STATUS_COLOUR.get(status, "#6b7280")
        out.append(
            f"<tr><td>{_esc(entry.get('label', ''))}</td>"
            f'<td><span class="pill" style="background:{colour}">'
            f"{_esc(status)}</span></td>"
            f"<td>{_esc(findings)}</td>"
            f"<td>{_esc(entry.get('ratio', '—'))}</td></tr>"
        )
    out.append("</tbody></table>")

    checked = ledger.get("units_checked")
    total = ledger.get("units_total")
    out.append(
        f"<p>Examined <strong>{ledger.get('classes_examined', 0)} of "
        f"{ledger.get('classes_in_tool_scope', 0)}</strong> class(es) in "
        f"scope; {len(external)} further class(es) are outside it entirely.</p>"
    )
    if total:
        out.append(f'<p class="note">Within those examined classes: {checked} '
                   f"of {total} unit(s) checked. This is <strong>not</strong> "
                   f"an overall coverage figure — the denominator counts only "
                   f"what was examined.</p>")

    unexamined = [e for e in covered
                  if e.get("status") not in ("ASSESSED", "PARTIAL")]
    if unexamined:
        out.append("<p><strong>Not examined:</strong></p><ul>")
        for entry in unexamined:
            marker = ("FAILED" if entry.get("status") == "FAILED"
                      else "not assessed")
            out.append(f"<li>{_esc(entry.get('label', ''))} — "
                       f"<strong>{_esc(marker)}</strong>: "
                       f"{_esc(entry.get('reason', ''))}</li>")
        out.append("</ul>")

    partial = [e for e in entries if e.get("status") == "PARTIAL"]
    if partial:
        out.append("<p><strong>Partial coverage:</strong></p><ul>")
        for entry in partial:
            out.append(f"<li>{_esc(entry.get('label', ''))} — "
                       f"{_esc(entry.get('reason', ''))}</li>")
        out.append("</ul>")

    if external:
        labels = ", ".join(e.get("label", "") for e in external)
        out.append('<p class="note"><strong>Outside this assessment '
                   'entirely</strong> — these require a separate engagement '
                   f"and were not examined: {_esc(labels)}.</p>")
    return out


def render_markdown(report: Report) -> str:
    engagement = report.engagement
    out: list[str] = []

    out.append(f"# {engagement.display_title}")
    out.append("")
    meta = [
        ("Client", engagement.client),
        ("Assessor", engagement.assessor),
        ("Engagement ID", engagement.engagement_id),
        ("Authorization", engagement.authorization_reference),
        ("Period", engagement.period),
        ("Generated", report.generated),
    ]
    for label, value in meta:
        if value:
            out.append(f"- **{label}:** {value}")
    out.append("")

    if engagement.scope:
        out.append("**Scope:** " + "; ".join(engagement.scope))
        out.append("")

    out.append("## Executive summary")
    out.append("")
    for paragraph in executive_summary(report):
        out.append(paragraph)
        out.append("")

    counts = report.severity_counts()
    if counts:
        out.append("## Findings at a glance")
        out.append("")
        out.append("| Severity | Findings | Measured | Assessed by ColdLight |")
        out.append("|----------|----------|----------|--------------------|")
        for severity, count in counts.items():
            at = [f for f in report.findings if f.severity == severity]
            measured = sum(1 for f in at if is_measured(f.severity_source))
            out.append(f"| {severity.title()} | {count} | {measured} "
                       f"| {count - measured} |")
        out.append("")
        out.append(f"**{report.measured_count} of {len(report.findings)}** "
                   f"severities are an external measurement (NVD CVSS or an "
                   f"advisory database); the remaining "
                   f"**{report.assessed_count}** are ColdLight' own assessment. "
                   f"They are counted together above, so this column is how "
                   f"you tell them apart.")
        out.append("")
        provenance = report.provenance_counts()
        if provenance:
            out.append("| Severity source | Findings |")
            out.append("|-----------------|----------|")
            for source, count in provenance.items():
                out.append(f"| {severity_source_label(source)} | {count} |")
            out.append("")

    if report.findings:
        out.append("## Findings")
        out.append("")
        for finding in report.findings:
            flag = "  **[KNOWN EXPLOITED]**" if finding.kev else ""
            out.append(f"### {finding.finding_id} — {finding.title}")
            out.append("")
            out.append(f"**Severity:** {finding.severity.title()} "
                       f"*({severity_source_label(finding.severity_source)})*"
                       f"  |  **Category:** {finding.category}{flag}")
            if finding.identifiers:
                out.append("")
                out.append("**References:** "
                           + ", ".join(f"`{i}`" for i in finding.identifiers[:12]))
            out.append("")
            if finding.description:
                out.append(finding.description)
                out.append("")
            if finding.evidence:
                out.append("**Evidence**")
                out.append("")
                for item in finding.evidence:
                    out.append(f"- {item}")
                out.append("")
            if finding.remediation:
                out.append(f"**Remediation:** {finding.remediation}")
                out.append("")
            for url in finding.references[:4]:
                out.append(f"- <{url}>")
            if finding.references[:4]:
                out.append("")

    if report.awareness and report.awareness.total_runs:
        awareness = report.awareness
        out.append("## Awareness campaign results")
        out.append("")
        out.append(f"- Total recorded actions: **{awareness.total_runs}**")
        out.append(f"- Unique hosts: {awareness.unique_hosts}")
        out.append(f"- Unique users: {awareness.unique_users}")
        if awareness.excluded_runs:
            out.append(f"- Excluded (opt-out safe-list): "
                       f"{awareness.excluded_runs}")
        if awareness.by_vector:
            out.append("- By vector: "
                       + ", ".join(f"{k}={v}"
                                   for k, v in awareness.by_vector.items()))
        out.append("")

    if report.mail:
        mail = report.mail
        out.append("## Email authentication posture")
        out.append("")
        out.append(f"- Domain: **{mail.domain}**")
        out.append(f"- Spoofable: **{'yes' if mail.spoofable else 'no'}** "
                   f"(DMARC protection: {mail.protection_level})")
        out.append(f"- Subdomains spoofable: "
                   f"{'yes' if mail.subdomains_spoofable else 'no'}")
        if mail.verdict:
            out.append(f"- Verdict: {mail.verdict}")
        out.append("")

    if report.assurance:
        out.append(_assurance_markdown(report.assurance))

    if report.suppressed:
        out.append("## Appendix A — Reviewed and not applicable")
        out.append("")
        out.append("These records were triaged and determined not to affect "
                   "this product, or to be already fixed. They are retained "
                   "for traceability.")
        out.append("")
        out.append("| Record | Status | Justification |")
        out.append("|--------|--------|---------------|")
        for finding in report.suppressed:
            identifier = finding.identifiers[0] if finding.identifiers else "-"
            reason = (finding.vex_justification or "-").replace("|", "/")
            out.append(f"| `{identifier}` | {finding.vex_status} | {reason} |")
        out.append("")

    out.append("## Appendix B — Scope and limitations")
    out.append("")
    out.append("What this assessment did **not** establish:")
    out.append("")
    for note in report.not_assessed:
        out.append(f"- {note}")
    out.append("")

    if report.sources:
        out.append("## Appendix C — Inputs")
        out.append("")
        for source in report.sources:
            out.append(f"- {source}")
        out.append("")

    out.append("---")
    out.append("")
    out.append(f"*Generated by {TOOL_NAME} {TOOL_VERSION} on "
               f"{report.generated}. Findings are based on identification, "
               f"not exploitation.*")
    out.append("")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# HTML (self-contained: no external fonts, scripts or stylesheets)
# ---------------------------------------------------------------------------

_HTML_HEAD = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
:root {
  --bg: #ffffff; --fg: #1a1c1e; --muted: #5b6168; --line: #e3e6ea;
  --card: #f7f8fa; --accent: #1f3a5f; --code: #f0f2f5;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #15171a; --fg: #e8eaed; --muted: #9aa3ad; --line: #2c3035;
    --card: #1d2024; --accent: #9ab8e0; --code: #22262b;
  }
}
:root[data-theme="dark"] {
  --bg: #15171a; --fg: #e8eaed; --muted: #9aa3ad; --line: #2c3035;
  --card: #1d2024; --accent: #9ab8e0; --code: #22262b;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--fg);
  font: 16px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
        Helvetica, Arial, sans-serif;
}
.wrap { max-width: 56rem; margin: 0 auto; padding: 2.5rem 16px 4rem; }
h1 { font-size: 1.9rem; line-height: 1.25; margin: 0 0 .4rem; }
h2 { font-size: 1.3rem; margin: 2.6rem 0 .9rem; padding-bottom: .35rem;
     border-bottom: 2px solid var(--line); }
h3 { font-size: 1.05rem; margin: 1.8rem 0 .5rem; }
p { margin: 0 0 1rem; }
a { color: var(--accent); }
code { background: var(--code); padding: .12em .4em; border-radius: 4px;
       font-size: .88em; font-family: ui-monospace, SFMono-Regular, Menlo,
       Consolas, monospace; }
.meta { color: var(--muted); font-size: .92rem; margin: 0 0 1.5rem; }
.meta div { margin: .15rem 0; }
.lede { background: var(--card); border: 1px solid var(--line);
        border-radius: 10px; padding: 1.1rem 1.25rem; margin: 0 0 1.5rem; }
.lede p:last-child { margin-bottom: 0; }
table { width: 100%; border-collapse: collapse; margin: 0 0 1.4rem;
        font-size: .94rem; }
th, td { text-align: left; padding: .5rem .6rem; border-bottom: 1px solid var(--line);
         vertical-align: top; }
th { color: var(--muted); font-weight: 600; font-size: .82rem;
     text-transform: uppercase; letter-spacing: .04em; }
.pill { display: inline-block; padding: .12rem .55rem; border-radius: 999px;
        color: #fff; font-size: .74rem; font-weight: 700; letter-spacing: .04em;
        text-transform: uppercase; }
.kev { display: inline-block; margin-left: .4rem; padding: .12rem .5rem;
       border-radius: 999px; background: #b3123a; color: #fff;
       font-size: .7rem; font-weight: 700; letter-spacing: .03em; }
.finding { border: 1px solid var(--line); border-left: 4px solid var(--line);
           border-radius: 8px; padding: 1rem 1.2rem; margin: 0 0 1.1rem;
           background: var(--card); }
.finding h3 { margin-top: 0; }
.fid { color: var(--muted); font-family: ui-monospace, Menlo, Consolas, monospace;
       font-size: .85em; }
.tags { margin: .4rem 0 .7rem; font-size: .85rem; color: var(--muted); }
ul.evidence { margin: .3rem 0 1rem; padding-left: 1.2rem; }
ul.evidence li { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas,
                 monospace; font-size: .83rem; word-break: break-word;
                 margin: .2rem 0; }
.fix { border-left: 3px solid var(--accent); padding: .1rem 0 .1rem .8rem;
       margin: .6rem 0 0; }
.fix strong { color: var(--accent); }
.note { color: var(--muted); font-size: .92rem; }
footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--line);
         color: var(--muted); font-size: .85rem; }
@media print {
  body { background: #fff; color: #000; }
  .finding { break-inside: avoid; background: #fff; }
  h2 { break-after: avoid; }
}
</style>
</head><body><div class="wrap">
"""


def _esc(value) -> str:
    return html.escape(str(value), quote=True)


def _md_bold_to_html(text: str) -> str:
    """Only **bold** is supported in summary prose; everything is escaped."""
    escaped = _esc(text)
    return re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", escaped)


def render_html(report: Report) -> str:
    engagement = report.engagement
    out: list[str] = [
        _HTML_HEAD.replace("__TITLE__", _esc(engagement.display_title))
    ]

    out.append(f"<h1>{_esc(engagement.display_title)}</h1>")
    out.append('<div class="meta">')
    for label, value in (
        ("Client", engagement.client),
        ("Assessor", engagement.assessor),
        ("Engagement ID", engagement.engagement_id),
        ("Authorization", engagement.authorization_reference),
        ("Period", engagement.period),
        ("Generated", report.generated),
    ):
        if value:
            out.append(f"<div><strong>{_esc(label)}:</strong> "
                       f"{_esc(value)}</div>")
    if engagement.scope:
        out.append("<div><strong>Scope:</strong> "
                   + _esc("; ".join(engagement.scope)) + "</div>")
    out.append("</div>")

    out.append("<h2>Executive summary</h2>")
    out.append('<div class="lede">')
    for paragraph in executive_summary(report):
        out.append(f"<p>{_md_bold_to_html(paragraph)}</p>")
    out.append("</div>")

    counts = report.severity_counts()
    if counts:
        out.append("<h2>Findings at a glance</h2>")
        out.append("<table><thead><tr><th>Severity</th><th>Findings</th>"
                   "<th>Measured</th><th>Assessed by ColdLight</th>"
                   "</tr></thead><tbody>")
        for severity, count in counts.items():
            colour = SEVERITY_COLOURS.get(severity, "#6b7280")
            at = [f for f in report.findings if f.severity == severity]
            measured = sum(1 for f in at if is_measured(f.severity_source))
            out.append(
                f'<tr><td><span class="pill" style="background:{colour}">'
                f'{_esc(severity)}</span></td><td>{count}</td>'
                f'<td>{measured}</td><td>{count - measured}</td></tr>'
            )
        out.append("</tbody></table>")
        out.append(
            f'<p class="note"><strong>{report.measured_count} of '
            f'{len(report.findings)}</strong> severities are an external '
            f'measurement (NVD CVSS or an advisory database); the remaining '
            f'<strong>{report.assessed_count}</strong> are assessed by '
            f'ColdLight itself. They are counted together above, so these '
            f'columns are how you tell them apart.</p>'
        )

    if report.findings:
        out.append("<h2>Findings</h2>")
        for finding in report.findings:
            colour = SEVERITY_COLOURS.get(finding.severity, "#6b7280")
            kev = '<span class="kev">Known exploited</span>' if finding.kev else ""
            out.append(f'<div class="finding" style="border-left-color:{colour}">')
            out.append(
                f'<h3><span class="fid">{_esc(finding.finding_id)}</span> '
                f'{_esc(finding.title)}{kev}</h3>'
            )
            out.append(
                f'<div class="tags">'
                f'<span class="pill" style="background:{colour}">'
                f'{_esc(finding.severity)}</span> &nbsp; '
                f'<em>{_esc(severity_source_label(finding.severity_source))}'
                f'</em> &nbsp; {_esc(finding.category)}'
            )
            if finding.identifiers:
                tags = " ".join(f"<code>{_esc(i)}</code>"
                                for i in finding.identifiers[:12])
                out.append(f" &nbsp; {tags}")
            out.append("</div>")

            if finding.description:
                out.append(f"<p>{_esc(finding.description)}</p>")
            if finding.evidence:
                out.append('<ul class="evidence">')
                for item in finding.evidence:
                    out.append(f"<li>{_esc(item)}</li>")
                out.append("</ul>")
            if finding.remediation:
                out.append(f'<p class="fix"><strong>Remediation:</strong> '
                           f'{_esc(finding.remediation)}</p>')
            for url in finding.references[:4]:
                out.append(f'<div class="note"><a href="{_esc(url)}" '
                           f'rel="noopener noreferrer">{_esc(url)}</a></div>')
            out.append("</div>")

    if report.awareness and report.awareness.total_runs:
        awareness = report.awareness
        out.append("<h2>Awareness campaign results</h2>")
        out.append("<table><tbody>")
        rows = [
            ("Total recorded actions", awareness.total_runs),
            ("Unique hosts", awareness.unique_hosts),
            ("Unique users", awareness.unique_users),
        ]
        if awareness.excluded_runs:
            rows.append(("Excluded (opt-out safe-list)", awareness.excluded_runs))
        if awareness.by_vector:
            rows.append(("By vector", ", ".join(
                f"{k}={v}" for k, v in awareness.by_vector.items())))
        for label, value in rows:
            out.append(f"<tr><th>{_esc(label)}</th><td>{_esc(value)}</td></tr>")
        out.append("</tbody></table>")

    if report.mail:
        mail = report.mail
        out.append("<h2>Email authentication posture</h2>")
        out.append("<table><tbody>")
        for label, value in (
            ("Domain", mail.domain),
            ("Spoofable", "yes" if mail.spoofable else "no"),
            ("DMARC protection", mail.protection_level),
            ("Subdomains spoofable",
             "yes" if mail.subdomains_spoofable else "no"),
            ("Verdict", mail.verdict),
        ):
            if value != "":
                out.append(f"<tr><th>{_esc(label)}</th>"
                           f"<td>{_esc(value)}</td></tr>")
        out.append("</tbody></table>")

    if report.assurance:
        out.extend(_assurance_html(report.assurance))

    if report.suppressed:
        out.append("<h2>Appendix A — Reviewed and not applicable</h2>")
        out.append('<p class="note">These records were triaged and determined '
                   'not to affect this product, or to be already fixed. They '
                   'are retained for traceability.</p>')
        out.append("<table><thead><tr><th>Record</th><th>Status</th>"
                   "<th>Justification</th></tr></thead><tbody>")
        for finding in report.suppressed:
            identifier = finding.identifiers[0] if finding.identifiers else "-"
            out.append(
                f"<tr><td><code>{_esc(identifier)}</code></td>"
                f"<td>{_esc(finding.vex_status)}</td>"
                f"<td>{_esc(finding.vex_justification or '-')}</td></tr>"
            )
        out.append("</tbody></table>")

    out.append("<h2>Appendix B — Scope and limitations</h2>")
    out.append("<p>What this assessment did <strong>not</strong> "
               "establish:</p><ul>")
    for note in report.not_assessed:
        out.append(f"<li>{_esc(note)}</li>")
    out.append("</ul>")

    if report.sources:
        out.append("<h2>Appendix C — Inputs</h2><ul>")
        for source in report.sources:
            out.append(f"<li><code>{_esc(source)}</code></li>")
        out.append("</ul>")

    out.append(
        f'<footer>Generated by {_esc(TOOL_NAME)} {_esc(TOOL_VERSION)} on '
        f'{_esc(report.generated)}. Findings are based on identification, '
        f'not exploitation.</footer>'
    )
    out.append("</div></body></html>")
    return "\n".join(out)


def render(report: Report, fmt: str) -> str:
    key = (fmt or "").strip().lower()
    if key in ("md", "markdown"):
        return render_markdown(report)
    if key == "html":
        return render_html(report)
    if key == "json":
        return json.dumps(report.to_dict(), indent=2) + "\n"
    raise EngagementError(
        f"unknown report format {fmt!r}; expected html, md or json")


def text_summary(report: Report) -> str:
    out: list[str] = []
    out.append(f"findings   : {len(report.findings)} "
               f"(covering {report.raw_item_count} item(s))")
    counts = report.severity_counts()
    if counts:
        out.append("  severity : "
                   + ", ".join(f"{k.lower()}={v}" for k, v in counts.items()))
    if report.kev_findings:
        out.append(f"  KNOWN EXPLOITED: {len(report.kev_findings)}")
    if report.suppressed:
        out.append(f"  suppressed by VEX triage: {len(report.suppressed)}")
    out.append(f"sources    : {len(report.sources)}")
    return "\n".join(out)
