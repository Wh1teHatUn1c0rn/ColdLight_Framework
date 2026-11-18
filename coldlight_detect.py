#!/usr/bin/env python3
"""
ColdLight purple-team layer: map what ColdLight exercises to MITRE ATT&CK, emit the
telemetry a defender should see, and ship Sigma rules so the blue team can
prove they would have detected it.

The point: an awareness test tells you how many people ran the file. This tells
you whether anyone would have *noticed*. Those are different findings, and the
second one is usually the more actionable.

Honest scoping: ColdLight exercises the delivery and user-execution portion of
these techniques with a benign payload. It does not exercise post-exploitation,
so a detection that catches ColdLight proves coverage of the *entry* behaviour
only. That is still worth proving -- the behavioural indicator (an unsigned
binary launched from removable media, then making an outbound request) is
identical whether the payload is benign or not. That shared indicator is
exactly what makes this useful for detection engineering.

Stdlib only. Read-only: generates documents, changes nothing on any host.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

# Sigma rule metadata. Pinned so regenerating rules doesn't churn their
# identity -- Sigma consumers key on `id`.
RULE_DATE = "2026-11-17"
RULE_AUTHOR = "ColdLight"
ATTACK_VERSION = "16"


# ---------------------------------------------------------------------------
# ATT&CK techniques ColdLight actually exercises
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Technique:
    technique_id: str
    name: str
    tactics: tuple[str, ...]
    exercised: str          # what ColdLight genuinely does for this technique
    not_exercised: str = ""  # what it deliberately does not

    @property
    def url(self) -> str:
        path = self.technique_id.replace(".", "/")
        return f"https://attack.mitre.org/techniques/{path}/"

    @property
    def tag(self) -> str:
        """Sigma tag form, e.g. attack.t1204.002"""
        return f"attack.{self.technique_id.lower()}"


TECHNIQUES: dict[str, Technique] = {
    "T1091": Technique(
        "T1091", "Replication Through Removable Media",
        ("Initial Access", "Lateral Movement"),
        exercised="A binary is placed on removable media and carried into the "
                  "environment, where a user mounts it and runs it.",
        not_exercised="No self-copying onto other drives, no autorun abuse "
                      "(AutoRun has been off for removable media since 2011).",
    ),
    "T1204.002": Technique(
        "T1204.002", "User Execution: Malicious File",
        ("Execution",),
        exercised="A user is socially engineered by filename and icon into "
                  "double-clicking an unsigned executable.",
        not_exercised="The file does nothing but log the run and show a "
                      "training message.",
    ),
    "T1566.002": Technique(
        "T1566.002", "Phishing: Spearphishing Link",
        ("Initial Access",),
        exercised="A link (in a simulated mail, a flyer, or a QR code) leads to "
                  "a tracked landing page that records the click.",
        not_exercised="The landing page has no form and never requests "
                      "credentials -- there is nothing to harvest.",
    ),
    "T1071.001": Technique(
        "T1071.001", "Application Layer Protocol: Web Protocols",
        ("Command and Control",),
        exercised="The payload makes a single authenticated HTTPS POST to the "
                  "collector, which looks like beaconing to a network sensor.",
        not_exercised="One-way reporting only: no tasking, no command channel, "
                      "no retry/jitter loop, no response parsing.",
    ),
}


# ---------------------------------------------------------------------------
# Telemetry: where the evidence lives
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DataSource:
    platform: str     # windows | network | mobile
    source: str
    detail: str
    default_on: bool = True


@dataclass
class VectorCoverage:
    vector: str                     # matches the `vector` column in hits.db
    label: str
    technique_ids: tuple[str, ...]
    telemetry: tuple[DataSource, ...]
    gaps: tuple[str, ...] = ()

    @property
    def techniques(self) -> list[Technique]:
        return [TECHNIQUES[t] for t in self.technique_ids]


VECTORS: dict[str, VectorCoverage] = {
    "usb": VectorCoverage(
        vector="usb",
        label="USB drop (found-drive)",
        technique_ids=("T1091", "T1204.002", "T1071.001"),
        telemetry=(
            DataSource("windows", "Sysmon EID 1 (ProcessCreate)",
                       "Image path on a non-system drive letter; parent is "
                       "explorer.exe; binary unsigned. This is the strongest "
                       "single signal."),
            DataSource("windows", "Sysmon EID 3 (NetworkConnect)",
                       "Outbound connection whose initiating image lives on "
                       "removable media -- execution plus egress in one chain."),
            DataSource("windows", "Sysmon EID 11 (FileCreate)",
                       "The payload writes coldlight_awareness_hits.jsonl to the "
                       "drive and %TEMP%."),
            DataSource("windows", "Security 6416 (new external device)",
                       "Device arrival. Noisy -- baseline before alerting."),
            DataSource("windows", "Security 4663 (removable storage access)",
                       "Requires Audit Object Access > Removable Storage.",
                       default_on=False),
            DataSource("windows",
                       "Microsoft-Windows-Partition/Diagnostic EID 1058",
                       "Disk serial, VID/PID and model of the inserted device. "
                       "On by default -- excellent for attributing which "
                       "physical stick was used."),
            DataSource("windows",
                       "Microsoft-Windows-DriverFrameworks-UserMode EID "
                       "2003/2100/2102",
                       "Device arrival/removal timing.", default_on=False),
            DataSource("windows", "Registry: USBSTOR / MountedDevices / "
                                  "MountPoints2",
                       "Forensic record of every device ever attached."),
            DataSource("network", "Proxy / firewall / DNS",
                       "The collector beacon: resolution of and connection to "
                       "the collector host."),
        ),
        gaps=(
            "DriverFrameworks-UserMode and removable-storage auditing are both "
            "OFF by default. If you rely on them, enable them first or the test "
            "will look like a detection failure when it is a logging gap.",
            "If the host has no EDR/Sysmon, process creation from removable "
            "media is invisible -- Security 4688 without command line and "
            "without image-path context is rarely enough.",
        ),
    ),
    "link": VectorCoverage(
        vector="link",
        label="Tracked link (simulated phish)",
        technique_ids=("T1566.002",),
        telemetry=(
            DataSource("network", "Web proxy / secure web gateway",
                       "GET of the landing URL, with the user and source host."),
            DataSource("network", "DNS resolver logs",
                       "Resolution of the collector hostname."),
            DataSource("network", "Email gateway click-tracking",
                       "If the link was delivered by mail.", default_on=False),
            DataSource("windows", "Browser history / Sysmon EID 22 (DNSQuery)",
                       "Host-side confirmation of who visited."),
        ),
        gaps=(
            "A click from a personal or off-VPN device produces no corporate "
            "telemetry. Compare click counts against proxy hits -- the "
            "difference is your blind spot, and it is usually non-zero.",
        ),
    ),
    "qr": VectorCoverage(
        vector="qr",
        label="QR code (quishing)",
        technique_ids=("T1566.002",),
        telemetry=(
            DataSource("network", "Corporate wifi DNS / proxy",
                       "Only if the phone is on the corporate network."),
            DataSource("mobile", "MDM / mobile threat defence browsing logs",
                       "Only on managed devices.", default_on=False),
        ),
        gaps=(
            "This is the big one: QR codes are usually scanned on a personal "
            "phone over cellular, which generates NO corporate telemetry at "
            "all. Expect near-zero detection and treat that as the finding -- "
            "the control for quishing is awareness and mail/link filtering, "
            "not endpoint or network detection.",
        ),
    ),
}


# ---------------------------------------------------------------------------
# Minimal YAML emitter (no pyyaml dependency)
# ---------------------------------------------------------------------------

_YAML_SPECIAL = set(":#{}[],&*!|>'\"%@`\\")


def _q(value) -> str:
    """Render a scalar as YAML, quoting only when necessary.

    Single quotes are used because Sigma detections are full of backslashes
    (regexes, Windows paths) and single-quoted YAML treats them literally.
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    text = str(value)
    needs_quotes = (
        not text
        or text != text.strip()
        or any(ch in _YAML_SPECIAL for ch in text)
        or text.lower() in {"true", "false", "null", "yes", "no", "~"}
    )
    try:
        float(text)
        needs_quotes = True
    except ValueError:
        pass
    if needs_quotes:
        return "'" + text.replace("'", "''") + "'"
    return text


def _emit(value, indent: int = 0) -> list[str]:
    """Render nested dicts/lists/scalars as YAML lines."""
    pad = " " * indent
    lines: list[str] = []

    if isinstance(value, dict):
        for key, val in value.items():
            if isinstance(val, dict):
                lines.append(f"{pad}{key}:")
                lines.extend(_emit(val, indent + 4))
            elif isinstance(val, (list, tuple)):
                lines.append(f"{pad}{key}:")
                for item in val:
                    if isinstance(item, dict):
                        rendered = _emit(item, indent + 6)
                        rendered[0] = f"{pad}    - " + rendered[0].lstrip()
                        lines.extend(rendered)
                    else:
                        lines.append(f"{pad}    - {_q(item)}")
            else:
                lines.append(f"{pad}{key}: {_q(val)}")
    elif isinstance(value, (list, tuple)):
        for item in value:
            lines.append(f"{pad}- {_q(item)}")
    else:
        lines.append(f"{pad}{_q(value)}")

    return lines


# ---------------------------------------------------------------------------
# Sigma rules
# ---------------------------------------------------------------------------

@dataclass
class SigmaRule:
    rule_id: str                      # stable UUID
    filename: str
    title: str
    description: str
    technique_ids: tuple[str, ...]
    logsource: dict
    detection: dict
    falsepositives: tuple[str, ...]
    level: str                        # informational|low|medium|high|critical
    status: str = "experimental"
    extra_references: tuple[str, ...] = ()

    @property
    def tags(self) -> list[str]:
        tags: list[str] = []
        for tid in self.technique_ids:
            tech = TECHNIQUES[tid]
            for tactic in tech.tactics:
                tag = f"attack.{tactic.lower().replace(' ', '_')}"
                if tag not in tags:
                    tags.append(tag)
            if tech.tag not in tags:
                tags.append(tech.tag)
        return tags

    @property
    def references(self) -> list[str]:
        refs = [TECHNIQUES[t].url for t in self.technique_ids]
        refs.extend(self.extra_references)
        return refs

    def to_yaml(self) -> str:
        doc = {
            "title": self.title,
            "id": self.rule_id,
            "status": self.status,
            "description": self.description,
            "references": self.references,
            "author": RULE_AUTHOR,
            "date": RULE_DATE,
            "tags": self.tags,
            "logsource": self.logsource,
            "detection": self.detection,
            "falsepositives": list(self.falsepositives),
            "level": self.level,
        }
        return "\n".join(_emit(doc)) + "\n"


# Regex for "an image path on a drive letter other than C:".
_REMOVABLE_IMAGE_RE = "^[D-Z]:\\\\"


def generic_rules() -> list[SigmaRule]:
    """Rules that apply to any ColdLight-style campaign."""
    return [
        SigmaRule(
            rule_id="8f4b1d2e-5c7a-4e39-9b61-0a2d7c4f1e80",
            filename="proc_exec_from_removable_media.yml",
            title="Executable Launched From Removable Media By A User",
            description=(
                "Detects a process whose image lives on a non-system drive "
                "letter being launched from the shell. This is the core "
                "behaviour of a USB-drop intrusion and of a ColdLight awareness "
                "test alike: a user mounts unknown media and runs a binary "
                "from it."
            ),
            technique_ids=("T1091", "T1204.002"),
            logsource={"category": "process_creation", "product": "windows"},
            detection={
                "selection_image": {"Image|re": _REMOVABLE_IMAGE_RE},
                "selection_shell_parent": {
                    "ParentImage|endswith": ["\\explorer.exe"]
                },
                "filter_system_drive": {"Image|startswith": "C:\\"},
                "condition": (
                    "selection_image and selection_shell_parent "
                    "and not filter_system_drive"
                ),
            },
            falsepositives=(
                "Portable applications deliberately run from USB by staff",
                "Installers run from a mounted ISO or a lettered network share",
                "Software distribution from a mapped drive",
            ),
            level="medium",
        ),
        SigmaRule(
            rule_id="c2a79e14-6b3d-4f58-8e0c-91d5a7b26f43",
            filename="net_conn_from_removable_media.yml",
            title="Outbound Connection From A Binary On Removable Media",
            description=(
                "Detects a process running from removable media initiating an "
                "outbound network connection. Execution plus egress in one "
                "chain is a far higher-fidelity signal than either alone, and "
                "it is rarely legitimate."
            ),
            technique_ids=("T1091", "T1071.001"),
            logsource={"category": "network_connection", "product": "windows"},
            detection={
                "selection": {
                    "Image|re": _REMOVABLE_IMAGE_RE,
                    "Initiated": True,
                },
                "condition": "selection",
            },
            falsepositives=(
                "Portable browsers or updaters run from USB",
                "Licensing checks by portable applications",
            ),
            level="high",
        ),
        SigmaRule(
            rule_id="5d6e8b03-9f21-4a7c-b8d4-3e1c0f5a92b7",
            filename="usb_mass_storage_device_arrival.yml",
            title="New Removable Storage Device Recognised",
            description=(
                "Device-arrival events for removable storage. On its own this "
                "is noisy and should be baselined rather than alerted on, but "
                "it is the pivot that tells you WHICH physical device appeared "
                "and when -- correlate it with process execution from the same "
                "drive letter."
            ),
            technique_ids=("T1091",),
            logsource={"product": "windows", "service": "security"},
            detection={
                "selection": {"EventID": 6416, "ClassName": "DiskDrive"},
                "condition": "selection",
            },
            falsepositives=(
                "Every legitimate USB stick, external disk and phone ever "
                "attached -- baseline this before alerting",
            ),
            level="informational",
            extra_references=(
                "https://learn.microsoft.com/windows/security/threat-protection/"
                "auditing/event-6416",
            ),
        ),
        SigmaRule(
            rule_id="a1c93f76-2d48-4b50-8f6e-7b05d2e4c198",
            filename="usb_device_arrival_driverframeworks.yml",
            title="USB Device Arrival (DriverFrameworks-UserMode)",
            description=(
                "Device arrival and removal timing from the "
                "DriverFrameworks-UserMode operational log. NOTE: this log is "
                "DISABLED by default -- enable it before relying on this rule, "
                "or its silence will look like a detection failure when it is "
                "really a logging gap."
            ),
            technique_ids=("T1091",),
            logsource={
                "product": "windows",
                "service": "driver-framework",
            },
            detection={
                "selection": {"EventID": [2003, 2100, 2102]},
                "condition": "selection",
            },
            falsepositives=(
                "All legitimate peripheral use",
            ),
            level="informational",
        ),
    ]


def campaign_rules(cfg) -> list[SigmaRule]:
    """Rules pinned to one engagement, so the blue team can hunt this exact
    campaign. Requires a loaded CampaignConfig."""
    rules: list[SigmaRule] = []

    lure = (getattr(cfg, "lure_filename", "") or "").strip()
    engagement = (getattr(cfg, "engagement_id", "") or "").strip()
    collector = (getattr(cfg, "collector_url", "") or "").strip()

    if lure:
        rules.append(SigmaRule(
            rule_id="e7b24a90-3c15-4d6f-9a82-5f0e1b7c3d46",
            filename="campaign_lure_execution.yml",
            title=f"ColdLight Awareness Lure Executed ({lure})",
            description=(
                f"Detects execution of the specific lure filename used by "
                f"engagement {engagement or '(unset)'}. Use this to confirm "
                f"your tooling saw the test, and to separate test activity "
                f"from real activity during the engagement window."
            ),
            technique_ids=("T1204.002", "T1091"),
            logsource={"category": "process_creation", "product": "windows"},
            detection={
                "selection": {"Image|endswith": f"\\{lure}"},
                "condition": "selection",
            },
            falsepositives=(
                "None expected -- this filename is unique to the engagement",
            ),
            level="high",
        ))

    host = _collector_host(collector)
    if host:
        rules.append(SigmaRule(
            rule_id="b93d5c81-7e04-42af-8c19-6d2b0a4f7e35",
            filename="campaign_landing_page_access.yml",
            title=f"ColdLight Awareness Landing Page Accessed ({host})",
            description=(
                "Detects access to the awareness landing page / collector for "
                "this engagement. Compare the count of proxy hits against the "
                "click count ColdLight recorded: clicks that ColdLight saw but the "
                "proxy did not are devices outside your visibility."
            ),
            technique_ids=("T1566.002",),
            logsource={"category": "proxy"},
            detection={
                "selection": {"c-host": host},
                "condition": "selection",
            },
            falsepositives=(
                "Security team members validating the campaign",
            ),
            level="medium",
        ))

    return rules


def _collector_host(url: str) -> str:
    """Host portion of a collector URL, without scheme, port or path."""
    if not url:
        return ""
    import urllib.parse

    parsed = urllib.parse.urlsplit(url if "//" in url else f"//{url}")
    return (parsed.hostname or "").strip()


def generate_rules(cfg=None) -> list[SigmaRule]:
    rules = generic_rules()
    if cfg is not None:
        rules.extend(campaign_rules(cfg))
    return rules


# ---------------------------------------------------------------------------
# ATT&CK Navigator layer
# ---------------------------------------------------------------------------

def navigator_layer(name: str = "ColdLight awareness-test coverage") -> dict:
    """An ATT&CK Navigator layer (v4.5) highlighting what ColdLight exercises."""
    techniques = []
    for tid, tech in TECHNIQUES.items():
        vectors = [v.label for v in VECTORS.values() if tid in v.technique_ids]
        techniques.append({
            "techniqueID": tid,
            "score": 100,
            "enabled": True,
            "comment": f"{tech.exercised} Vectors: {', '.join(vectors)}."
                       + (f" Not exercised: {tech.not_exercised}"
                          if tech.not_exercised else ""),
            "metadata": [
                {"name": "ColdLight vectors", "value": ", ".join(vectors)},
            ],
        })

    return {
        "name": name,
        "versions": {
            "attack": ATTACK_VERSION,
            "navigator": "4.9.0",
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": (
            "Techniques exercised by ColdLight awareness testing, with a benign "
            "payload. Covers delivery and user execution only -- no "
            "post-exploitation."
        ),
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffffff", "#ce232e"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "Exercised by ColdLight (benign payload)", "color": "#ce232e"},
        ],
        "sorting": 0,
        "hideDisabled": True,
    }


# ---------------------------------------------------------------------------
# Human-readable mapping
# ---------------------------------------------------------------------------

def mapping_report() -> str:
    out: list[str] = []
    out.append("=" * 70)
    out.append("ColdLight -> MITRE ATT&CK coverage")
    out.append("=" * 70)
    out.append("")
    out.append("ColdLight exercises the DELIVERY and USER-EXECUTION portion of")
    out.append("these techniques with a benign payload. A detection that fires")
    out.append("on ColdLight proves entry-behaviour coverage -- the behavioural")
    out.append("indicator is the same whether or not the payload is malicious.")
    out.append("")

    for vector in VECTORS.values():
        out.append("-" * 70)
        out.append(f"VECTOR: {vector.label}   (hits.db vector = {vector.vector!r})")
        out.append("-" * 70)

        for tech in vector.techniques:
            out.append(f"  {tech.technique_id}  {tech.name}")
            out.append(f"      tactics : {', '.join(tech.tactics)}")
            out.append(f"      does    : {tech.exercised}")
            if tech.not_exercised:
                out.append(f"      does not: {tech.not_exercised}")
            out.append(f"      ref     : {tech.url}")
            out.append("")

        out.append("  Telemetry to check:")
        for src in vector.telemetry:
            flag = "" if src.default_on else "   [OFF BY DEFAULT]"
            out.append(f"    - [{src.platform}] {src.source}{flag}")
            out.append(f"        {src.detail}")
        out.append("")

        if vector.gaps:
            out.append("  Known gaps:")
            for gap in vector.gaps:
                out.append(f"    ! {gap}")
            out.append("")

    return "\n".join(out)


# ---------------------------------------------------------------------------
# Blue-team validation checklist
# ---------------------------------------------------------------------------

def checklist_markdown(cfg=None) -> str:
    engagement = (getattr(cfg, "engagement_id", "") or "(set engagement_id)"
                  if cfg else "(no campaign config supplied)")
    auth = (getattr(cfg, "authorization_reference", "") or "(set authorization_reference)"
            if cfg else "(n/a)")

    out: list[str] = []
    out.append("# ColdLight blue-team validation checklist")
    out.append("")
    out.append(f"- **Engagement:** {engagement}")
    out.append(f"- **Authorization:** {auth}")
    out.append(f"- **Generated:** {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC")
    out.append("")
    out.append("Work this in order. The goal is not a pass/fail grade -- it is "
               "to find out which layer would have caught it, and to turn each "
               "gap into a concrete backlog item.")
    out.append("")

    out.append("## 0. Before the test (do this first)")
    out.append("")
    out.append("Running the test against missing logging produces a false "
               "'detection failure'. Confirm up front:")
    out.append("")
    out.append("- [ ] Sysmon (or EDR with equivalent process/network "
               "visibility) deployed on the target population")
    out.append("- [ ] Process creation events include the **full image path** "
               "and **command line**")
    out.append("- [ ] `Audit Object Access > Removable Storage` enabled, if you "
               "intend to rely on Security 4663")
    out.append("- [ ] `Microsoft-Windows-DriverFrameworks-UserMode/Operational` "
               "enabled, if you intend to rely on 2003/2100/2102")
    out.append("- [ ] Proxy/DNS logs retained for the engagement window and "
               "searchable by host and user")
    out.append("- [ ] Record the engagement window (start/end UTC) so test "
               "activity can be separated from real activity")
    out.append("")

    out.append("## 1. Detection coverage, by vector")
    out.append("")
    for vector in VECTORS.values():
        techs = ", ".join(t.technique_id for t in vector.techniques)
        out.append(f"### {vector.label} ({techs})")
        out.append("")
        for src in vector.telemetry:
            note = "" if src.default_on else " *(off by default)*"
            out.append(f"- [ ] **{src.source}**{note} — {src.detail}")
        out.append("")
        if vector.gaps:
            for gap in vector.gaps:
                out.append(f"> ⚠️ {gap}")
            out.append("")

    out.append("## 2. For each recorded hit")
    out.append("")
    out.append("Use `coldlight detect validate --db hits.db` to generate the "
               "per-hit worksheet with exact hosts and timestamps. For each "
               "one, record the earliest layer that saw it:")
    out.append("")
    out.append("| Outcome | Meaning | Action |")
    out.append("|---------|---------|--------|")
    out.append("| **Alerted** | An analyst was notified | Confirm triage time "
               "and that it reached a human |")
    out.append("| **Logged, not alerted** | Telemetry exists, no rule fired | "
               "Highest-value gap: write/tune the rule |")
    out.append("| **No telemetry** | Nothing recorded it | Logging gap — fix "
               "collection before detection |")
    out.append("")

    out.append("## 3. Close the loop")
    out.append("")
    out.append("- [ ] Deploy the Sigma rules from `coldlight detect rules` into "
               "your SIEM (convert with `sigma convert`)")
    out.append("- [ ] Re-run the affected vector and confirm the rule fires")
    out.append("- [ ] Record mean time to detect, not just whether it detected")
    out.append("- [ ] For technique depth beyond the entry behaviour, use "
               "Atomic Red Team tests for the same technique IDs")
    out.append("- [ ] Report detection findings **alongside** the awareness "
               "numbers — \"31% ran it and nothing alerted\" is a very "
               "different finding from \"31% ran it and we caught all of them\"")
    out.append("")

    return "\n".join(out)


# ---------------------------------------------------------------------------
# Hit -> detection validation worksheet
# ---------------------------------------------------------------------------

WINDOW_MINUTES = 5


def _shift(timestamp: str, minutes: int) -> str:
    """Offset an ISO-8601 timestamp, for a SIEM search window."""
    text = (timestamp or "").strip()
    if not text:
        return ""
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return ""
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return (parsed + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")


def hit_search_hints(hit: dict) -> list[str]:
    """What a defender should go look for, for one recorded hit."""
    vector = (hit.get("vector") or "usb").lower()
    host = hit.get("hostname") or "?"
    user = hit.get("username") or "?"
    ran_from = hit.get("ran_from") or ""

    hints: list[str] = []
    if vector == "usb":
        hints.append(
            f"Process creation on {host} for an image under {ran_from or '<removable drive>'}"
        )
        hints.append(f"Device arrival on {host} shortly before the run "
                     f"(Security 6416 / Partition-Diagnostic 1058)")
        hints.append(f"Outbound connection from that image on {host}")
        hints.append(f"File creation of coldlight_awareness_hits.jsonl on {host}")
    elif vector == "link":
        hints.append(f"Proxy/web-gateway GET of the landing URL by {user} on {host}")
        hints.append("DNS resolution of the collector hostname from that source")
    else:
        hints.append("Corporate wifi DNS/proxy hit for the collector hostname "
                     "(absent if scanned on a personal device over cellular)")
    return hints


def validation_worksheet(hits: list[dict], cfg=None) -> str:
    """Turn recorded hits into a per-hit detection-validation worksheet.

    This is the step that makes the awareness test useful to the blue team:
    ColdLight knows exactly which host, which user and which second each run
    happened, which is precisely the pivot needed to go check the SIEM.
    """
    engagement = getattr(cfg, "engagement_id", "") if cfg else ""

    out: list[str] = []
    out.append("# ColdLight detection-validation worksheet")
    out.append("")
    if engagement:
        out.append(f"- **Engagement:** {engagement}")
    out.append(f"- **Hits to validate:** {len(hits)}")
    out.append(f"- **Generated:** {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC")
    out.append("")

    if not hits:
        out.append("No hits recorded yet. Run the campaign, ingest the logs "
                   "(`coldlight report --ingest ...`), then re-run this.")
        out.append("")
        return "\n".join(out)

    out.append("For each hit below, search the window in your SIEM and mark the "
               "earliest layer that saw it: **alerted** / **logged, not "
               "alerted** / **no telemetry**.")
    out.append("")

    by_vector: dict[str, int] = {}
    for hit in hits:
        key = (hit.get("vector") or "usb").lower()
        by_vector[key] = by_vector.get(key, 0) + 1
    out.append("Hits by vector: "
               + ", ".join(f"{k}={v}" for k, v in sorted(by_vector.items())))
    out.append("")

    for index, hit in enumerate(hits, start=1):
        timestamp = hit.get("timestamp_utc") or hit.get("received_utc") or ""
        vector = (hit.get("vector") or "usb").lower()
        coverage = VECTORS.get(vector)
        techs = (", ".join(t.technique_id for t in coverage.techniques)
                 if coverage else "-")

        out.append(f"## Hit {index}: {hit.get('hostname', '?')} / "
                   f"{hit.get('username', '?')}")
        out.append("")
        out.append(f"- **When (UTC):** {timestamp or 'unknown'}")
        out.append(f"- **Vector:** {vector} ({techs})")
        out.append(f"- **OS:** {hit.get('os', '?')}")
        if hit.get("ran_from"):
            out.append(f"- **Ran from:** {hit['ran_from']}")
        if hit.get("excluded"):
            out.append("- **Note:** safe-listed/excluded hit")
        window_start = _shift(timestamp, -WINDOW_MINUTES)
        window_end = _shift(timestamp, WINDOW_MINUTES)
        if window_start and window_end:
            out.append(f"- **Search window:** `{window_start}` to `{window_end}`")
        out.append("")
        out.append("Look for:")
        for hint in hit_search_hints(hit):
            out.append(f"- [ ] {hint}")
        out.append("")
        out.append("Result: ( ) alerted  ( ) logged, not alerted  ( ) no telemetry")
        out.append("")

    out.append("## Summary")
    out.append("")
    out.append("| Vector | Hits | Alerted | Logged only | No telemetry |")
    out.append("|--------|------|---------|-------------|--------------|")
    for vector, count in sorted(by_vector.items()):
        out.append(f"| {vector} | {count} |  |  |  |")
    out.append("")
    out.append("Every row that is not 'alerted' is a detection-engineering "
               "backlog item. That list is the real deliverable.")
    out.append("")

    return "\n".join(out)


def navigator_json(name: str | None = None) -> str:
    layer = navigator_layer(name) if name else navigator_layer()
    return json.dumps(layer, indent=2)
