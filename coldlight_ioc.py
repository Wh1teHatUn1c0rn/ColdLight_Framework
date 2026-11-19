#!/usr/bin/env python3
"""
ColdLight indicator-pack scanning: look for host-observable markers of a known
tool or intrusion, and report what the pack can no longer vouch for.

This is deliberately NOT a detection engine. It does not read logs, netflow,
sign-in events or cloud audit trails -- those classes are declared
TIER_EXTERNAL in `coldlight_assurance`, and importing a SIEM ruleset would mean
claiming coverage this tool's own ledger says it does not have. What it does is
much narrower: take a published indicator pack and look for the parts of it
that are visible in a tree on disk.

Three rules make this different from running grep against a list of strings.

1. An expired indicator is never a finding. Intel decays on purpose -- the
   packs this is built for say so themselves, with per-indicator expiry dates
   measured in months. A scanner that keeps matching a string a year after its
   author stopped standing behind it is not reporting an intrusion, it is
   reporting its own staleness as though it were evidence. Anything past its
   `valid_until` is reported as EXPIRED, in its own section, counted
   separately, and kept out of the findings list.

2. A weak indicator does not alert alone. Pack authors grade how unique each
   marker is, because some of them -- a port number, an ordinary filename --
   occur innocently all the time. Those classes are promoted to a finding only
   when something else in the same scan also matched; on their own they are
   reported as needing corroboration. Same instinct as `patch` vs
   `patch_likely` in the vuln-intel module: say what the evidence supports, not
   what would be more alarming.

3. A pack that is old is reported as old. The freshness of the pack itself is a
   coverage claim rather than a finding, so a pack retrieved longer ago than
   STALE_AFTER_DAYS still produces its matches but downgrades the assurance
   ledger entry to PARTIAL. "I checked" and "I checked with current intel" are
   different sentences.

Two things are refused outright rather than warned about, because a warning is
not enough when the failure mode is a silent clean result:

- A pack with no source URL or no licence does not load. Intel that cannot be
  attributed does not get to produce findings in a report someone will act on.
- A pack using an indicator `kind` this module has no handler for does not
  load. The alternative -- skipping what we cannot evaluate -- produces a clean
  scan of a pack we never actually ran, which is the exact failure the rest of
  ColdLight exists to prevent. When this module learns a new kind, KINDS and
  HANDLERS grow together; a test enforces that they cannot grow apart.

Five surfaces are examined, and the report says what each one actually looked
at: file contents, file paths, file digests, port numbers in configuration
files, and container image references in Dockerfiles and compose/k8s
manifests. A surface that no loaded indicator covers is reported as not
covered rather than left out, because an omitted surface reads like a clean
one. The surfaces deliberately do not share a walk -- filenames are matched
against every file under the root, not only the ones with source extensions,
because the whole point of a filename indicator is an artifact this tool would
never open and read.

The digest surface is the expensive one and the only one that reads every byte
of every file: a content pattern can be matched on the first two megabytes and
a filename needs no read at all, but a truncated hash is not a hash. It is
also the one surface a rename cannot defeat, which is why a pack's strongest
Class A marker is usually a digest rather than a path.

In-file suppression comments (`# nosec`, `# coldlight:ignore`) are honoured by
`coldlight_codescan` and deliberately NOT honoured here. A developer may
reasonably choose to silence a static-analysis rule about code they wrote. The
file being searched for an intrusion marker is, by hypothesis, a file someone
else may have written -- letting its contents switch off its own detection is
not a feature.

Severity comes from the pack's tier, not from us, and `severity_source` on
every finding records that. The tier -> severity mapping is mechanical and
lives in TIER_SEVERITY so a reader can undo it.

SCOPE BOUNDARY: read-only, local filesystem only. No network, no remote lookup,
no blocking, no quarantine. It tells you where to look.
"""

from __future__ import annotations

import hashlib
import os
import re
import tomllib
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path

from coldlight_codescan import (MAX_FILE_BYTES, MAX_LINE_LEN, SKIP_DIRS,
                                is_excluded, iter_source_files, redact)

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

# Where the severity on an IOC finding came from. The pack author graded the
# indicator; we only mapped their tier onto our severity words. Declared as a
# literal and checked against coldlight_vulnintel.SEVERITY_SOURCES by a test,
# the same arrangement coldlight_codescan uses.
SEVERITY_SOURCE = "indicator-pack"

# ---------------------------------------------------------------------------
# The pack vocabulary
# ---------------------------------------------------------------------------
# These four axes are not ColdLight's invention -- they are the common
# vocabulary of published indicator packs, which in turn take them from the
# Admiralty source-reliability scale and the Sigma/MISP conventions built on
# it. They are kept as opaque labels on purpose: this module enforces what they
# imply about reporting and does not second-guess the grades themselves.

# How unique the marker is. A/B are distinctive enough to stand alone; C/D
# occur innocently and need a second signal; E/F are infrastructure and
# context, which this module records but does not alert on by itself.
UNIQUENESS_CLASSES = ("A", "B", "C", "D", "E", "F")

# Classes that must never produce a finding on their own.
CORROBORATION_CLASSES = frozenset({"C", "D", "E", "F"})

# How well the source was verified. V1 is first-hand confirmed, V4 unverified.
VERIFICATION_LEVELS = ("V1", "V2", "V3", "V4")

# Alert routing confidence the pack author assigned. T1 is "wake someone",
# T4 is "worth hunting for".
TIERS = ("T1", "T2", "T3", "T4")

TIER_SEVERITY = {
    "T1": "CRITICAL",
    "T2": "HIGH",
    "T3": "MEDIUM",
    "T4": "LOW",
}

# A pack older than this still scans, but the ledger stops calling the class
# fully assessed. Ninety days is the shortest expiry window the packs this was
# built for use for their own volatile indicators, so a pack we have not
# refreshed in that long has plausibly decayed under us.
STALE_AFTER_DAYS = 90

# A file larger than this is not hashed, and the digest surface counts it as
# skipped rather than examined. Deliberately far above codescan's
# MAX_FILE_BYTES: that cap exists because two megabytes of source is already
# more than a pattern needs, while a dropped binary is routinely bigger than
# that and is exactly what a digest indicator is for. A cap is still needed --
# hashing a multi-gigabyte disk image would stall a scan with no finding at
# the end of it -- so the limit is high enough to cover real artifacts and the
# skip is reported either way.
MAX_DIGEST_BYTES = 256_000_000
_DIGEST_CHUNK = 1_048_576

# ---------------------------------------------------------------------------
# What a match can be
# ---------------------------------------------------------------------------

# Stands on its own: a distinctive, in-date marker.
STATUS_FINDING = "FINDING"
# Matched, but the pack grades it too common to alert on alone and nothing
# else in this scan backed it up.
STATUS_CORROBORATION = "CORROBORATION REQUIRED"
# Matched an indicator whose author stopped standing behind it. Not evidence.
STATUS_EXPIRED = "EXPIRED"

KIND_FILE_CONTENT = "file_content"
KIND_FILE_NAME = "file_name"
KIND_FILE_DIGEST = "file_digest"
KIND_LISTENING_PORT = "listening_port"
KIND_CONTAINER_IMAGE = "container_image"

# Every kind listed here has a handler in HANDLERS and a surface description in
# KIND_SURFACE, and a pack naming anything else is rejected at load. A test
# enforces all three, because a kind with no handler would load, match nothing
# and report clean, and a kind with no surface description would be scanned and
# then not accounted for in the report.
KINDS = (KIND_FILE_CONTENT, KIND_FILE_NAME, KIND_FILE_DIGEST,
         KIND_LISTENING_PORT, KIND_CONTAINER_IMAGE)

# (unit, what was examined) per kind. The unit is the noun the report counts;
# the description is the sentence that stops a zero from being read as "clean".
KIND_SURFACE = {
    KIND_FILE_CONTENT: ("file", "contents of files the source walker reads"),
    KIND_FILE_NAME: ("path", "every file path under the root, any type"),
    KIND_FILE_DIGEST: ("file",
                       "SHA-256 of every file under the root, any type"),
    KIND_LISTENING_PORT: ("config file",
                          "port numbers declared in configuration files"),
    KIND_CONTAINER_IMAGE: ("manifest",
                           "image references in Dockerfiles and "
                           "compose/k8s manifests"),
}

# Which files each structured surface opens. Narrower than the content walk on
# purpose: a port number or an image name in a README is prose, not a
# declaration, and treating it as one is how a scanner earns its reputation for
# noise. The cost is stated in the report rather than hidden -- these surfaces
# do not see a port configured somewhere this list does not name.
CONFIG_EXTENSIONS = frozenset({
    ".yml", ".yaml", ".json", ".ini", ".cfg", ".conf", ".toml", ".env",
    ".properties", ".tf", ".tfvars", ".xml", ".service", ".socket",
})
CONFIG_FILENAMES = frozenset({
    ".env", "procfile", "caddyfile", "haproxy.cfg", "nginx.conf", "httpd.conf",
    "my.cnf", "redis.conf", "sshd_config", "hosts",
})
MANIFEST_EXTENSIONS = frozenset({".yml", ".yaml", ".json"})
# Matched as a prefix so Dockerfile.prod and Containerfile.dev count too.
MANIFEST_FILE_PREFIXES = ("dockerfile", "containerfile")


class IocError(ValueError):
    """The scan could not be performed as asked."""


class PackError(IocError):
    """A pack could not be loaded, and so was not scanned with."""


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Indicator:
    id: str
    kind: str
    value: str
    uniqueness: str
    verification: str
    tier: str
    title: str
    valid_until: str = ""       # ISO date; "" means the pack set no expiry
    source: str = ""            # per-indicator provenance, if finer than the pack's
    note: str = ""
    redact_match: bool = True
    pattern: re.Pattern | None = field(default=None, compare=False, repr=False)

    @property
    def severity(self) -> str:
        return TIER_SEVERITY.get(self.tier, "INFO")

    @property
    def stands_alone(self) -> bool:
        return self.uniqueness not in CORROBORATION_CLASSES

    def expired_on(self, today: date) -> bool:
        """True once the pack's own validity date has passed.

        Inclusive: an indicator valid until today is still valid today. An
        indicator with no declared expiry never expires here -- that is the
        pack author's claim to make, and `coverage_note` says so in the report
        rather than this module inventing a default lifetime.
        """
        if not self.valid_until:
            return False
        return _parse_date(self.valid_until, label="valid_until") < today

    def to_dict(self) -> dict:
        # Built field by field rather than with asdict(), which would have to
        # decide what to do with the compiled pattern.
        return {
            "id": self.id, "kind": self.kind, "value": self.value,
            "uniqueness": self.uniqueness, "verification": self.verification,
            "tier": self.tier, "title": self.title,
            "valid_until": self.valid_until, "source": self.source,
            "note": self.note, "redact_match": self.redact_match,
            "severity": self.severity,
        }


@dataclass(frozen=True)
class Pack:
    name: str
    version: str
    source: str
    license: str
    retrieved: str
    indicators: tuple[Indicator, ...]
    path: str = ""
    description: str = ""

    def age_days(self, today: date) -> int:
        return (today - _parse_date(self.retrieved, label="retrieved")).days

    def is_stale(self, today: date, *, after: int = STALE_AFTER_DAYS) -> bool:
        return self.age_days(today) > after

    def active(self, today: date) -> tuple[Indicator, ...]:
        return tuple(i for i in self.indicators if not i.expired_on(today))

    def expired(self, today: date) -> tuple[Indicator, ...]:
        return tuple(i for i in self.indicators if i.expired_on(today))

    def to_dict(self, today: date | None = None) -> dict:
        today = today or _today()
        return {
            "name": self.name,
            "version": self.version,
            "source": self.source,
            "license": self.license,
            "retrieved": self.retrieved,
            "description": self.description,
            "path": self.path,
            "age_days": self.age_days(today),
            "stale": self.is_stale(today),
            "indicators_total": len(self.indicators),
            "indicators_active": len(self.active(today)),
            "indicators_expired": len(self.expired(today)),
        }


@dataclass(frozen=True)
class IocFinding:
    indicator_id: str
    status: str
    severity: str
    title: str
    uniqueness: str
    verification: str
    tier: str
    pack: str
    file: str
    line: int
    snippet: str
    source: str = ""
    valid_until: str = ""
    note: str = ""
    corroborated_by: tuple[str, ...] = ()
    severity_source: str = SEVERITY_SOURCE

    def to_dict(self) -> dict:
        data = asdict(self)
        data["corroborated_by"] = list(self.corroborated_by)
        return data

    @property
    def rank(self) -> tuple:
        return (-SEVERITY_ORDER.get(self.severity.upper(), 0),
                self.file, self.line, self.indicator_id)


@dataclass
class Surface:
    """What one indicator kind was actually run against.

    `examined` is zero for two entirely different reasons: no indicator in the
    loaded packs covers this surface, or there was nothing of that kind under
    the root. `indicators` is carried beside it because one of those is a gap
    in the pack and the other is a scan that looked and found nothing, and a
    single count cannot tell a reader which happened.
    """
    kind: str
    unit: str = "item"
    description: str = ""
    examined: int = 0
    skipped: int = 0
    indicators: int = 0

    @property
    def covered(self) -> bool:
        """Whether any loaded indicator asked for this surface at all."""
        return self.indicators > 0

    def to_dict(self) -> dict:
        return {"kind": self.kind, "unit": self.unit,
                "description": self.description, "examined": self.examined,
                "skipped": self.skipped, "indicators": self.indicators,
                "covered": self.covered}


@dataclass
class IocScanResult:
    """Three lists, deliberately not one.

    Collapsing them would hand a reader a count of "matches" in which a
    distinctive live marker and a year-dead string weigh the same.
    """
    findings: list[IocFinding] = field(default_factory=list)
    corroboration: list[IocFinding] = field(default_factory=list)
    expired: list[IocFinding] = field(default_factory=list)
    packs: list[Pack] = field(default_factory=list)
    # Files whose *contents* were read -- the file_content surface only. The
    # other surfaces count their own units in `surfaces`, because one number
    # cannot mean the same thing for a content scan, a walk of every path and
    # a read of the config files.
    files_scanned: int = 0
    files_skipped: int = 0
    surfaces: dict[str, Surface] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    scanned_on: str = ""
    # Carried on the result, not just used during the scan: `stale_packs`
    # below is what the report and the ledger read, so a caller-tightened
    # window has to reach them or the parameter would appear to work and not.
    stale_after_days: int = STALE_AFTER_DAYS

    def surface(self, kind: str, *, indicators: int | None = None) -> Surface:
        """The accounting row for one surface, created on first use."""
        row = self.surfaces.get(kind)
        if row is None:
            unit, description = KIND_SURFACE.get(kind, ("item", ""))
            row = Surface(kind=kind, unit=unit, description=description)
            self.surfaces[kind] = row
        if indicators is not None:
            row.indicators = indicators
        return row

    def surface_rows(self) -> list[Surface]:
        """Every surface this module knows about, in declaration order.

        Including the ones no loaded indicator covers: listing only the
        surfaces that ran would let a reader take a silent surface for a clean
        one, which is the whole failure this module exists to avoid.

        Deliberately a pure read. Rendering a report must not add rows to the
        result it is rendering, and a missing row has to stay visible as the
        bug it is rather than being conjured up by whoever asks first --
        `scan_packs` registers every one of them before anything runs.
        """
        rows = []
        for kind in KINDS:
            row = self.surfaces.get(kind)
            if row is None:
                unit, description = KIND_SURFACE.get(kind, ("item", ""))
                row = Surface(kind=kind, unit=unit, description=description)
            rows.append(row)
        return rows

    @property
    def uncovered_surfaces(self) -> list[Surface]:
        return [row for row in self.surface_rows() if not row.covered]

    @property
    def today(self) -> date:
        return (_parse_date(self.scanned_on, label="scanned_on")
                if self.scanned_on else _today())

    @property
    def stale_packs(self) -> list[Pack]:
        return [p for p in self.packs
                if p.is_stale(self.today, after=self.stale_after_days)]

    @property
    def indicators_total(self) -> int:
        return sum(len(p.indicators) for p in self.packs)

    @property
    def indicators_active(self) -> int:
        return sum(len(p.active(self.today)) for p in self.packs)

    @property
    def indicators_expired(self) -> int:
        return self.indicators_total - self.indicators_active

    @property
    def indicators_undated(self) -> int:
        return sum(1 for p in self.packs for i in p.indicators
                   if not i.valid_until)

    @property
    def fully_current(self) -> bool:
        """Whether every indicator in every pack could actually be used.

        False is not a failure -- it is the ordinary state of intel. It is the
        difference between this class being ASSESSED and PARTIAL.
        """
        return (bool(self.packs) and not self.stale_packs
                and not self.indicators_expired)

    def coverage_note(self) -> str:
        """One sentence on what this scan could not speak for."""
        parts: list[str] = []
        if self.indicators_expired:
            parts.append(
                f"{self.indicators_expired} of {self.indicators_total} "
                "indicator(s) are past their validity date and were not used")
        if self.stale_packs:
            names = ", ".join(p.name for p in self.stale_packs)
            parts.append(f"pack(s) not refreshed in over "
                         f"{self.stale_after_days} days: {names}")
        if self.indicators_undated:
            parts.append(f"{self.indicators_undated} indicator(s) declare no "
                         "expiry, so their age is unknown to this tool")
        return "; ".join(parts)


# ---------------------------------------------------------------------------
# Dates
# ---------------------------------------------------------------------------

def _today() -> date:
    return datetime.now(timezone.utc).date()


def _parse_date(value: str, *, label: str) -> date:
    try:
        return date.fromisoformat(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise PackError(
            f"{label} must be an ISO date (YYYY-MM-DD), got {value!r}") from exc


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

_REQUIRED_PACK_FIELDS = ("name", "version", "source", "license", "retrieved")
_REQUIRED_INDICATOR_FIELDS = ("id", "kind", "value", "uniqueness",
                              "verification", "tier", "title")


def load_pack(path: str | Path) -> Pack:
    """Read one pack file, or refuse to.

    Every refusal here is deliberate. A pack that loads with its provenance
    missing, or with indicator kinds this module silently drops, produces a
    scan that looks like it ran.
    """
    path = Path(path)
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise PackError(f"cannot read pack {path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise PackError(f"{path} is not valid TOML: {exc}") from exc

    meta = raw.get("pack")
    if not isinstance(meta, dict):
        raise PackError(f"{path}: missing a [pack] table")

    missing = [f for f in _REQUIRED_PACK_FIELDS if not str(meta.get(f, "")).strip()]
    if missing:
        raise PackError(
            f"{path}: [pack] is missing {', '.join(missing)}. A pack without a "
            "source and licence cannot be attributed in a report, so it is not "
            "loaded.")

    # Validates the format now rather than at the first comparison, so a typo
    # is a load error naming the file instead of a traceback mid-scan.
    _parse_date(meta["retrieved"], label="retrieved")

    entries = raw.get("indicator")
    if not isinstance(entries, list) or not entries:
        raise PackError(f"{path}: no [[indicator]] entries")

    indicators: list[Indicator] = []
    seen: dict[str, int] = {}
    for position, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            raise PackError(f"{path}: indicator {position} is not a table")
        indicator = _build_indicator(entry, path=path, position=position)
        if indicator.id in seen:
            raise PackError(
                f"{path}: duplicate indicator id {indicator.id!r} "
                f"(entries {seen[indicator.id]} and {position}). Ids are how a "
                "finding is traced back to the pack, so they have to be unique.")
        seen[indicator.id] = position
        indicators.append(indicator)

    return Pack(
        name=str(meta["name"]),
        version=str(meta["version"]),
        source=str(meta["source"]),
        license=str(meta["license"]),
        retrieved=str(meta["retrieved"]).strip(),
        description=str(meta.get("description", "")),
        indicators=tuple(indicators),
        path=str(path),
    )


def _check_listening_port(*, value, uniqueness, entry, where, identifier):
    """A port is a number, and a number can never stand on its own.

    There are 65535 port numbers and every one of them is somebody's innocent
    default, so a pack grading one A or B is asking this tool to raise a
    standalone CRITICAL on a two-byte integer. That is refused rather than
    quietly downgraded: silently rewriting a pack author's grade would make the
    report disagree with the pack it cites, and the operator who wrote or
    edited the entry is the person who can fix it.

    `regex` and `ignore_case` are refused for the same reason the unknown-kind
    check exists -- neither does anything to a decimal integer, and an option
    that silently has no effect is worse than one that is rejected.
    """
    text = str(value).strip()
    if not re.fullmatch(r"[0-9]{1,5}", text):
        raise PackError(
            f"{where} ({identifier}): a {KIND_LISTENING_PORT} value must be a "
            f"port number, got {value!r}. Use {KIND_FILE_CONTENT} to match "
            "arbitrary text in a config file.")
    port = int(text)
    if not 1 <= port <= 65535:
        raise PackError(f"{where} ({identifier}): port {port} is outside "
                        "1-65535, so nothing could ever match it")
    if entry.get("regex", False) or entry.get("ignore_case", False):
        raise PackError(
            f"{where} ({identifier}): regex and ignore_case have no meaning "
            f"for a {KIND_LISTENING_PORT} value, which is compared as a "
            "number. Refused rather than ignored.")
    if uniqueness not in CORROBORATION_CLASSES:
        raise PackError(
            f"{where} ({identifier}): a port number cannot be graded "
            f"{uniqueness}. Every port is some unrelated software's default, "
            "so a standalone finding on one would be noise with a severity "
            "attached. Declare it "
            f"{'/'.join(sorted(CORROBORATION_CLASSES))} and let the "
            "corroboration rule promote it when a second marker turns up.")
    # Normalised, so a pack writing 08080 and one writing 8080 are the same
    # indicator rather than two that look different in a report.
    return str(port)


def _check_file_name(*, value, uniqueness, entry, where, identifier):
    """Accept the separators a pack is actually written with.

    Published packs write dropped-file indicators as absolute POSIX paths, and
    occasionally as Windows paths. Backslashes are normalised so both forms
    reach the matcher the same way; the handler is what makes an absolute path
    match a tree walked from its own root.
    """
    text = str(value)
    if not entry.get("regex", False):
        text = text.replace("\\", "/")
    if not text.strip().strip("/"):
        raise PackError(
            f"{where} ({identifier}): a {KIND_FILE_NAME} value of {value!r} is "
            "empty or only separators, which would match every path under the "
            "root")
    return text


def _check_file_digest(*, value, uniqueness, entry, where, identifier):
    """A digest is 64 hex characters of SHA-256, or it is not evaluable.

    The length check is the one that matters. An MD5 is 32 characters and a
    SHA-1 is 40, both are still published, and this surface computes SHA-256
    and nothing else -- so either would load, be counted among the indicators
    this scan claims to have evaluated, and be structurally incapable of
    matching. A `sha256:` prefix is accepted because that is how registries
    and STIX patterns write one, and the case is normalised so a pack written
    in uppercase is not a different indicator from the same digest in lower.

    Note what is NOT refused here: any uniqueness class is allowed. A port
    graded A is refused because no port is distinctive, but a digest of a
    dual-use binary -- a stock copy of a remote-admin tool, say -- is
    genuinely a common marker, and that is the pack author's call to make.
    """
    text = str(value).strip()
    if text.lower().startswith("sha256:"):
        text = text.split(":", 1)[1].strip()
    if entry.get("regex", False) or entry.get("ignore_case", False):
        raise PackError(
            f"{where} ({identifier}): regex and ignore_case have no meaning "
            f"for a {KIND_FILE_DIGEST} value, which is compared as a hash. "
            "Refused rather than ignored.")
    if not re.fullmatch(r"[0-9A-Fa-f]{64}", text):
        algorithm = {32: "an MD5", 40: "a SHA-1"}.get(len(text))
        detail = (f"That is {algorithm} digest; this surface computes SHA-256 "
                  "and would never match it."
                  if algorithm else
                  "A SHA-256 digest is 64 hexadecimal characters.")
        raise PackError(
            f"{where} ({identifier}): {KIND_FILE_DIGEST} value {value!r} is "
            f"not a SHA-256 digest. {detail}")
    return text.lower()


def _check_container_image(*, value, uniqueness, entry, where, identifier):
    """Refuse a reference that could never match.

    An image reference contains no whitespace. A value with a space in it is a
    typo, and a typo here is worse than an error: the indicator loads, counts
    towards the indicators this scan claims to have evaluated, and is
    incapable of ever firing.
    """
    text = str(value)
    if not entry.get("regex", False) and re.search(r"\s", text):
        raise PackError(
            f"{where} ({identifier}): a {KIND_CONTAINER_IMAGE} value cannot "
            f"contain whitespace, got {value!r}. As written it would load and "
            "never match, which inflates the indicator count with an "
            "indicator that does nothing.")
    return text


# Optional, per kind: a check the generic field validation cannot express.
# Each returns the value to use, which lets a validator normalise as well as
# refuse. Keys must be known kinds; a test enforces it.
KIND_VALIDATORS = {
    KIND_LISTENING_PORT: _check_listening_port,
    KIND_FILE_NAME: _check_file_name,
    KIND_FILE_DIGEST: _check_file_digest,
    KIND_CONTAINER_IMAGE: _check_container_image,
}


def _validate_kind(kind, *, value, uniqueness, entry, where, identifier) -> str:
    check = KIND_VALIDATORS.get(kind)
    if check is None:
        return value
    return check(value=value, uniqueness=uniqueness, entry=entry,
                 where=where, identifier=identifier)


def _build_indicator(entry: dict, *, path: Path, position: int) -> Indicator:
    where = f"{path}: indicator {position}"
    missing = [f for f in _REQUIRED_INDICATOR_FIELDS
               if not str(entry.get(f, "")).strip()]
    if missing:
        raise PackError(f"{where} is missing {', '.join(missing)}")

    identifier = str(entry["id"]).strip()
    kind = str(entry["kind"]).strip()
    if kind not in KINDS:
        raise PackError(
            f"{where} ({identifier}) uses kind {kind!r}, which this version of "
            f"ColdLight cannot evaluate. Supported: {', '.join(KINDS)}. The "
            "pack is refused rather than loaded without it -- skipping an "
            "indicator class would report a clean scan for a surface nothing "
            "ever looked at.")

    uniqueness = str(entry["uniqueness"]).strip().upper()
    if uniqueness not in UNIQUENESS_CLASSES:
        raise PackError(f"{where} ({identifier}): uniqueness must be one of "
                        f"{', '.join(UNIQUENESS_CLASSES)}, got {uniqueness!r}")

    verification = str(entry["verification"]).strip().upper()
    if verification not in VERIFICATION_LEVELS:
        raise PackError(f"{where} ({identifier}): verification must be one of "
                        f"{', '.join(VERIFICATION_LEVELS)}, "
                        f"got {verification!r}")

    tier = str(entry["tier"]).strip().upper()
    if tier not in TIERS:
        raise PackError(f"{where} ({identifier}): tier must be one of "
                        f"{', '.join(TIERS)}, got {tier!r}")

    valid_until = str(entry.get("valid_until", "")).strip()
    if valid_until:
        _parse_date(valid_until, label=f"{where} ({identifier}) valid_until")

    value = _validate_kind(kind, value=str(entry["value"]),
                           uniqueness=uniqueness, entry=entry, where=where,
                           identifier=identifier)
    # Literal by default. A pack author writing a marker should not have to
    # think about regex metacharacters, and a value that is accidentally a
    # pattern is a false positive nobody can explain.
    is_regex = bool(entry.get("regex", False))
    flags = re.IGNORECASE if entry.get("ignore_case", False) else 0
    try:
        pattern = re.compile(value if is_regex else re.escape(value), flags)
    except re.error as exc:
        raise PackError(
            f"{where} ({identifier}): regex does not compile: {exc}") from exc

    return Indicator(
        id=identifier,
        kind=kind,
        value=value,
        uniqueness=uniqueness,
        verification=verification,
        tier=tier,
        title=str(entry["title"]),
        valid_until=valid_until,
        source=str(entry.get("source", "")),
        note=str(entry.get("note", "")),
        redact_match=bool(entry.get("redact", True)),
        pattern=pattern,
    )


def load_packs(paths) -> list[Pack]:
    """Load several packs, refusing the lot if any one of them is bad.

    Partial loading would mean the operator asked for three packs, got two,
    and read a report that does not obviously say which.
    """
    packs = [load_pack(p) for p in paths]
    names = [p.name for p in packs]
    duplicates = {n for n in names if names.count(n) > 1}
    if duplicates:
        raise PackError(
            "two packs share the name(s) " + ", ".join(sorted(duplicates)) +
            " -- findings could not be traced back to one of them")
    return packs


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _RawMatch:
    indicator: Indicator
    pack: Pack
    file: str
    line: int
    snippet: str


# ---------------------------------------------------------------------------
# Walking
# ---------------------------------------------------------------------------

def iter_all_files(root, exclude=None):
    """Yield every file under `root`, not only the ones with a source suffix.

    `coldlight_codescan.iter_source_files` filters on extension, which is
    right for reading code and wrong for looking for a dropped artifact: a
    filename indicator exists precisely because the thing on disk is a binary,
    an archive or an extensionless blob this tool would never open. Using the
    source walker for filenames would mean reporting no dropped files after
    having looked only at the .py and .yml ones.

    Directory skips and --exclude handling are codescan's, so the two walks
    agree about what is out of scope. Nothing here is opened or read.
    """
    root = Path(root)
    if root.is_file():
        if not is_excluded(root, root.parent, exclude):
            yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames
            if d not in SKIP_DIRS and not (d.startswith(".") and d != ".")
            and not is_excluded(Path(dirpath) / d, root, exclude)
        ]
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if is_excluded(path, root, exclude):
                continue
            yield path


def _rel_posix(path, root) -> str:
    try:
        return path.resolve().relative_to(Path(root).resolve()).as_posix()
    except (ValueError, OSError):
        return path.as_posix()


def _pack_paths(pairs) -> set[Path]:
    """Where the packs themselves live, so a pack is never its own evidence.

    A pack kept in version control sits inside the tree being scanned, and
    every indicator in it matches its own declaration. Without this the scan
    reports the pack as a compromise of itself -- and on every surface, since a
    pack that names a dropped file also has that name somewhere in its own
    text.
    """
    paths = set()
    for _, pack in pairs:
        if not pack.path:
            continue
        try:
            paths.add(Path(pack.path).resolve())
        except OSError:
            paths.add(Path(pack.path))
    return paths


def _is_pack(path, pack_paths) -> bool:
    try:
        return path.resolve() in pack_paths
    except OSError:
        return path in pack_paths


def _is_config_file(path) -> bool:
    return (path.suffix.lower() in CONFIG_EXTENSIONS
            or path.name.lower() in CONFIG_FILENAMES)


def _is_manifest_file(path) -> bool:
    name = path.name.lower()
    return (path.suffix.lower() in MANIFEST_EXTENSIONS
            or any(name == prefix or name.startswith(prefix + ".")
                   for prefix in MANIFEST_FILE_PREFIXES))


def _read_lines(path, *, surface, result):
    """A file as lines, or None if it was skipped or could not be read.

    Shared by the surfaces that open files, so they skip the same oversized
    blobs and record errors the same way. Skips are counted per surface: a
    blob too large for the config surface was not examined by it, whatever
    some other surface managed to do with the same file.
    """
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            surface.skipped += 1
            return None
    except OSError:
        surface.skipped += 1
        return None
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        result.errors.append(f"{path}: {exc}")
        return None


def _evidence(line, *, found, indicator) -> str:
    """What matched, then the line it sat in -- masked, but never the match.

    Redaction exists so a report can be shared, and it masks quoted values --
    which is exactly the shape of a quoted path, a quoted port mapping and a
    quoted image reference. Running it over the whole line therefore hides the
    marker and leaves the reader a line number and a row of asterisks. So the
    thing the pack matched is extracted first and shown verbatim, and only the
    surrounding context goes through redact().
    """
    context = (redact(line) if indicator.redact_match else line).strip()
    if len(context) > 160:
        context = context[:160] + "..."
    return f"{found} in: {context}" if context else found


# ---------------------------------------------------------------------------
# The surfaces
# ---------------------------------------------------------------------------

def _match_file_content(kind, pairs, root, exclude, result):
    """Search file contents for markers, line by line.

    Takes (indicator, pack) pairs from every loaded pack at once, because the
    tree is walked here: one handler call per kind, not per pack. Walking it
    once per pack counted every file again for each one, so two packs over the
    same tree reported twice as many files scanned as exist.

    The walk is `coldlight_codescan`'s, so the same directories are skipped and
    the same --exclude globs apply. That also bounds this surface honestly: a
    marker in a file type that walker does not yield is not looked for, which
    the report's surface table states.
    """
    matches: list[_RawMatch] = []
    if not pairs:
        return matches

    surface = result.surface(kind, indicators=len(pairs))
    pack_paths = _pack_paths(pairs)

    for path in iter_source_files(root, exclude):
        if _is_pack(path, pack_paths):
            continue
        lines = _read_lines(path, surface=surface, result=result)
        if lines is None:
            continue

        surface.examined += 1
        for lineno, line in enumerate(lines, start=1):
            if len(line) > MAX_LINE_LEN:
                continue
            # Note: no suppression check. See the module docstring -- a file
            # under suspicion does not get to switch off its own detection.
            for indicator, pack in pairs:
                if not indicator.pattern.search(line):
                    continue
                snippet = redact(line) if indicator.redact_match else line
                matches.append(_RawMatch(
                    indicator=indicator, pack=pack, file=str(path),
                    line=lineno, snippet=snippet.strip()[:200]))

    # The two long-standing counters mean this surface, and only this one.
    result.files_scanned = surface.examined
    result.files_skipped = surface.skipped
    return matches


def _match_file_name(kind, pairs, root, exclude, result):
    """Match indicators against file paths rather than file contents.

    Every path is offered to the pattern three ways: the bare name, the
    root-relative posix path, and that path with a leading "/". The third form
    is what makes an absolute-path indicator work. Published packs write
    dropped-file markers as "/var/tmp/.something", and against a relative walk
    that could never match -- so the indicator would load, be counted among
    the ones this scan evaluated, and be structurally incapable of firing.

    Nothing is opened: this surface is about what exists, not what is in it.
    """
    matches: list[_RawMatch] = []
    if not pairs:
        return matches

    surface = result.surface(kind, indicators=len(pairs))
    pack_paths = _pack_paths(pairs)

    for path in iter_all_files(root, exclude):
        if _is_pack(path, pack_paths):
            continue
        surface.examined += 1
        rel = _rel_posix(path, root)
        candidates = ((path.name, "name"), (rel, "path"), ("/" + rel, "path"))
        for indicator, pack in pairs:
            for text, label in candidates:
                if indicator.pattern.search(text):
                    matches.append(_RawMatch(
                        indicator=indicator, pack=pack, file=str(path),
                        line=0, snippet=f"{label} matched: {rel}"))
                    break
    return matches


def _digest_of(path, *, surface, result):
    """The file's SHA-256, or None if it was not read.

    None has to be distinguishable from "no match": a file too large to hash
    and a file that could not be opened were both NOT examined, and counting
    either as examined would put a file in the denominator that nothing
    looked at.
    """
    try:
        if path.stat().st_size > MAX_DIGEST_BYTES:
            surface.skipped += 1
            return None
    except OSError:
        surface.skipped += 1
        return None

    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(_DIGEST_CHUNK)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError as exc:
        # Recorded, not swallowed. A file this surface could not read is a
        # gap in the scan, and the one thing it must not look like is a file
        # that was hashed and did not match.
        surface.skipped += 1
        result.errors.append(f"{path}: could not be hashed: {exc}")
        return None
    return digest.hexdigest()


def _match_file_digest(kind, pairs, root, exclude, result):
    """Match indicators against the SHA-256 of each file's contents.

    Every file is hashed once and the digest looked up, rather than hashed per
    indicator: a pack carrying forty digests must not read the tree forty
    times.

    This surface is the reason a digest earns its place in a pack. A filename
    indicator is defeated by `mv`, a content pattern by one changed byte in
    the right place; a hash survives both, and fails only when the artifact
    itself changes -- at which point the pack author has a new artifact and
    knows it.
    """
    matches: list[_RawMatch] = []
    if not pairs:
        return matches

    surface = result.surface(kind, indicators=len(pairs))
    pack_paths = _pack_paths(pairs)

    wanted: dict[str, list] = {}
    for indicator, pack in pairs:
        # Validated at load; normalised again here because an Indicator built
        # directly in code never went through the validator. An unusable
        # value is reported rather than silently never matching.
        value = str(indicator.value).strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            result.errors.append(
                f"indicator {indicator.id} declares {indicator.value!r}, "
                f"which is not a SHA-256 digest, and was NOT evaluated")
            continue
        wanted.setdefault(value, []).append((indicator, pack))
    if not wanted:
        return matches

    for path in iter_all_files(root, exclude):
        if _is_pack(path, pack_paths):
            continue
        digest = _digest_of(path, surface=surface, result=result)
        if digest is None:
            continue
        surface.examined += 1
        rel = _rel_posix(path, root)
        for indicator, pack in wanted.get(digest, ()):
            matches.append(_RawMatch(
                indicator=indicator, pack=pack, file=str(path), line=0,
                snippet=f"sha256:{digest} matched: {rel}"))
    return matches


_PORT_KEY_WORDS = frozenset({"port", "ports", "listen", "listener", "bind",
                             "binds", "binding"})

# key: value / KEY=value. The key is filtered in Python rather than by the
# pattern -- see _is_port_key.
_PORT_FIELD = re.compile(
    r"""(?:^|[^\w.-])(?P<key>[A-Za-z][\w.-]*)\s*[:=]\s*"""
    r"""["']?(?P<rest>[\w.:*\[\]-]+)""")
# nginx/haproxy style directive: listen 8443 ssl;
_PORT_DIRECTIVE = re.compile(
    r"""(?:^|[^\w.-])(?:listen|bind)\s+["']?(?P<rest>[\w.:*\[\]-]+)""", re.I)
# A compose-style published mapping, in a list item with no key of its own.
_PORT_MAPPING = re.compile(
    r"""(?:^|[\s"'=\[,])(?P<rest>[0-9]{1,5}:[0-9]{1,5})(?:/(?:tcp|udp))?"""
    r"""(?=[\s"',\]]|$)""", re.I)
# An authority anywhere, including inside a URL.
_PORT_AUTHORITY = re.compile(
    r"""(?:^|[^\w.-])(?P<rest>(?:[0-9]{1,3}(?:\.[0-9]{1,3}){3}"""
    r"""|\[[0-9A-Fa-f:]+\]|localhost|\*):[0-9]{1,5})""", re.I)

_DIGITS = re.compile(r"[0-9]{1,5}")


def _is_port_key(key: str) -> bool:
    """Whether a config key names a port, or merely contains the word.

    "support: 3" and "transport = 8080" both have "port" as a substring and
    neither declares one. The key is split on separators and camelCase
    boundaries and the words are compared whole, so `containerPort`,
    `listen_address` and `PORTS` qualify while `support`, `transport` and
    `reporting` do not.
    """
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", key)
    return any(word.lower() in _PORT_KEY_WORDS
               for word in re.findall(r"[A-Za-z]+", spaced))


def _ports_in_line(line: str) -> set[int]:
    """Port numbers a line appears to declare.

    Each extractor hands back an authority-ish string, which is split on ":"
    and only the all-digit components are kept. That is what stops
    127.0.0.1:8080 from offering 127 and 1 as ports -- otherwise an indicator
    for either would match every line mentioning a loopback address.
    """
    found: set[int] = set()
    for pattern in (_PORT_FIELD, _PORT_DIRECTIVE, _PORT_MAPPING,
                    _PORT_AUTHORITY):
        for match in pattern.finditer(line):
            if pattern is _PORT_FIELD and not _is_port_key(match.group("key")):
                continue
            for part in match.group("rest").split(":"):
                if _DIGITS.fullmatch(part) and 1 <= int(part) <= 65535:
                    found.add(int(part))
    return found


def _match_listening_port(kind, pairs, root, exclude, result):
    """Look for a port the configuration appears to declare.

    Deliberately not a text search for the digits. A port number inside a
    version string, a timestamp or a longer number is not a declaration, and
    reporting it as one is how a scanner teaches its operator to ignore it.
    Only the files `_is_config_file` names are opened, which is a real limit
    rather than a claim to understand every config format there is -- the
    report's surface table says which files this was.
    """
    matches: list[_RawMatch] = []
    if not pairs:
        return matches

    surface = result.surface(kind, indicators=len(pairs))
    wanted: dict[int, list] = {}
    for indicator, pack in pairs:
        try:
            port = int(indicator.value)
        except (TypeError, ValueError):
            # Unreachable through load_pack, which validates the value. Kept
            # as a recorded error rather than a traceback, for an Indicator
            # built directly in code: one bad entry must not take the scan
            # down, and must not pass for a clean one either. Same treatment
            # as an indicator kind with no handler.
            result.errors.append(
                f"indicator {indicator.id} declares a non-numeric port "
                f"{indicator.value!r} and was NOT evaluated")
            continue
        wanted.setdefault(port, []).append((indicator, pack))
    if not wanted:
        return matches
    pack_paths = _pack_paths(pairs)

    for path in iter_all_files(root, exclude):
        if not _is_config_file(path) or _is_pack(path, pack_paths):
            continue
        lines = _read_lines(path, surface=surface, result=result)
        if lines is None:
            continue

        surface.examined += 1
        for lineno, line in enumerate(lines, start=1):
            if len(line) > MAX_LINE_LEN:
                continue
            declared = _ports_in_line(line)
            if not declared:
                continue
            for port in sorted(declared.intersection(wanted)):
                for indicator, pack in wanted[port]:
                    matches.append(_RawMatch(
                        indicator=indicator, pack=pack, file=str(path),
                        line=lineno,
                        snippet=_evidence(line, found=f"port {port}",
                                          indicator=indicator)))
    return matches


_IMAGE_FROM = re.compile(r"^\s*FROM\s+(?:--\S+\s+)*(?P<ref>\S+)", re.I)
_IMAGE_FIELD = re.compile(
    r"""["']?\bimage["']?\s*:\s*["']?(?P<ref>[^\s"',}\]]+)""", re.I)


def _image_refs(line: str) -> list[str]:
    """Image references a line declares, in order, without repeats.

    Only a FROM line or an `image:` field counts. That is the whole value of
    this surface over a content search: it reports what a manifest deploys,
    not what a document mentions. A registry named in a README is prose.
    """
    refs: list[str] = []
    for pattern in (_IMAGE_FROM, _IMAGE_FIELD):
        for match in pattern.finditer(line):
            ref = match.group("ref").strip().strip(",;")
            if ref and ref not in refs:
                refs.append(ref)
    return refs


def _match_container_image(kind, pairs, root, exclude, result):
    """Match indicators against the image references a manifest deploys.

    The indicator is tested against the extracted reference, so a pack can
    name a repository and match every tag of it, or name one digest and match
    only that. Tag and digest are left on the reference rather than stripped:
    a pack that cares about `:latest` should be able to say so.
    """
    matches: list[_RawMatch] = []
    if not pairs:
        return matches

    surface = result.surface(kind, indicators=len(pairs))
    pack_paths = _pack_paths(pairs)

    for path in iter_all_files(root, exclude):
        if not _is_manifest_file(path) or _is_pack(path, pack_paths):
            continue
        lines = _read_lines(path, surface=surface, result=result)
        if lines is None:
            continue

        surface.examined += 1
        for lineno, line in enumerate(lines, start=1):
            if len(line) > MAX_LINE_LEN:
                continue
            for ref in _image_refs(line):
                for indicator, pack in pairs:
                    if indicator.pattern.search(ref):
                        matches.append(_RawMatch(
                            indicator=indicator, pack=pack, file=str(path),
                            line=lineno,
                            snippet=_evidence(line, found=f"image {ref}",
                                              indicator=indicator)))
    return matches


HANDLERS = {
    KIND_FILE_CONTENT: _match_file_content,
    KIND_FILE_NAME: _match_file_name,
    KIND_FILE_DIGEST: _match_file_digest,
    KIND_LISTENING_PORT: _match_listening_port,
    KIND_CONTAINER_IMAGE: _match_container_image,
}


def scan_packs(root: str | Path, packs, *, exclude=None,
               today: date | None = None,
               stale_after_days: int = STALE_AFTER_DAYS) -> IocScanResult:
    """Scan `root` with `packs`. Read-only.

    `today` is injectable because the whole point of this module is that time
    changes the answer, and a test that cannot move the clock cannot check
    that.
    """
    # A root that is not there walks to nothing, and nothing looks exactly
    # like a clean result: zero files, zero findings, no error. SECURITY.md
    # calls a clean result that is not clean a vulnerability in this tool, and
    # a mistyped path is the easiest way to produce one. So it is refused.
    root_path = Path(root)
    if not root_path.exists():
        raise IocError(
            f"no such path to scan: {root}. Refused rather than reported as "
            "clean -- an empty walk and an absent threat are indistinguishable "
            "in the output.")

    today = today or _today()
    packs = list(packs)
    result = IocScanResult(packs=packs, scanned_on=today.isoformat(),
                           stale_after_days=stale_after_days)

    # Every surface gets its accounting row before anything runs, so one that
    # no loaded indicator covers is reported as uncovered rather than simply
    # absent from the report.
    for kind in KINDS:
        result.surface(kind)

    # Grouped by kind across every pack, so each surface is walked once.
    # Expired indicators are still matched -- the operator is told what the
    # pack would have flagged, and told that it no longer counts. Dropping them
    # here would hide the fact that the pack has decayed.
    by_kind: dict[str, list[tuple[Indicator, Pack]]] = {}
    for pack in packs:
        for indicator in pack.indicators:
            by_kind.setdefault(indicator.kind, []).append((indicator, pack))

    raw: list[_RawMatch] = []
    for kind, pairs in sorted(by_kind.items()):
        handler = HANDLERS.get(kind)
        if handler is None:
            # Unreachable through load_pack, which refuses unknown kinds. Kept
            # as a loud failure rather than a silent skip, for a Pack built
            # directly in code.
            result.errors.append(
                f"no handler for indicator kind {kind!r}; {len(pairs)} "
                f"indicator(s) were NOT evaluated")
            continue
        raw.extend(handler(kind, pairs, root, exclude, result))

    _grade(raw, result, today=today)
    return result


def _grade(raw, result, *, today: date) -> None:
    """Turn raw matches into graded ones.

    Corroboration is scan-wide and cross-pack on purpose. The rule the packs
    state is that a common marker must not alert on its own; two different
    common markers turning up in the same tree is the second signal, and
    insisting they share a file would throw away the normal case of a tool that
    leaves one trace in a config and another in a script. Mutual promotion is
    intended: if the only things present are two distinct Class C markers, that
    is still two markers.

    This reading is ColdLight's, not the pack author's, which is why every
    promoted finding records the ids that corroborated it.
    """
    live_ids = {m.indicator.id for m in raw
                if not m.indicator.expired_on(today)}

    for match in raw:
        indicator = match.indicator
        if indicator.expired_on(today):
            status = STATUS_EXPIRED
            corroborators: tuple[str, ...] = ()
        elif indicator.stands_alone:
            status = STATUS_FINDING
            corroborators = ()
        else:
            others = tuple(sorted(live_ids - {indicator.id}))
            status = STATUS_FINDING if others else STATUS_CORROBORATION
            corroborators = others

        finding = IocFinding(
            indicator_id=indicator.id,
            status=status,
            severity=indicator.severity,
            title=indicator.title,
            uniqueness=indicator.uniqueness,
            verification=indicator.verification,
            tier=indicator.tier,
            pack=match.pack.name,
            file=match.file,
            line=match.line,
            snippet=match.snippet,
            source=indicator.source or match.pack.source,
            valid_until=indicator.valid_until,
            note=indicator.note,
            corroborated_by=corroborators,
        )

        if status == STATUS_EXPIRED:
            result.expired.append(finding)
        elif status == STATUS_CORROBORATION:
            result.corroboration.append(finding)
        else:
            result.findings.append(finding)

    for bucket in (result.findings, result.corroboration, result.expired):
        bucket.sort(key=lambda f: f.rank)


# ---------------------------------------------------------------------------
# Convenience
# ---------------------------------------------------------------------------

def scan_ioc(root: str | Path, pack_paths, *, exclude=None,
             today: date | None = None) -> IocScanResult:
    """Load packs and scan in one call. Raises PackError if a pack is bad."""
    return scan_packs(root, load_packs(pack_paths), exclude=exclude,
                      today=today)


def severity_counts(findings) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.upper()] = counts.get(f.severity.upper(), 0) + 1
    return counts


def meets_threshold(findings, threshold: str) -> bool:
    """Whether any finding is at or above `threshold`.

    Only the findings list is considered. A match awaiting corroboration has
    not been established, and an expired one is not evidence at all, so neither
    may fail a build.
    """
    floor = SEVERITY_ORDER.get((threshold or "").upper())
    if floor is None:
        raise ValueError(f"unknown severity threshold: {threshold!r}")
    return any(SEVERITY_ORDER.get(f.severity.upper(), 0) >= floor
               for f in findings)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def _finding_block(out: list[str], findings, *, show_note: bool) -> None:
    current = None
    for f in findings:
        if f.indicator_id != current:
            current = f.indicator_id
            grades = f"class {f.uniqueness}/{f.verification}/{f.tier}"
            out.append(f"{f.severity.upper():<8} {f.title}  "
                       f"[{f.indicator_id}, {grades}]")
            if f.corroborated_by:
                out.append("         corroborated by: " +
                           ", ".join(f.corroborated_by))
            if f.valid_until:
                out.append(f"         pack stands behind this until "
                           f"{f.valid_until}")
            if show_note and f.note:
                out.append(f"         note: {f.note}")
            if f.source:
                out.append(f"         source: {f.source}")
        where = f.file if f.line <= 0 else f"{f.file}:{f.line}"
        out.append(f"         {where}")
        out.append(f"             | {f.snippet}")


def text_report(result: IocScanResult, *, show_notes: bool = True) -> str:
    out: list[str] = []
    out.append("=" * 68)
    out.append("ColdLight indicator-pack scan")
    out.append("=" * 68)

    if not result.packs:
        out.append("NOT ASSESSED: no indicator packs were loaded, so nothing "
                   "was looked for.")
        return "\n".join(out)

    today = result.today
    # The window comes off the result, not from the module default. Reading
    # the default here made the report disagree with its own coverage note
    # whenever a caller tightened it.
    stale_names = {p.name for p in result.stale_packs}
    for pack in result.packs:
        age = pack.age_days(today)
        flag = "  *** STALE ***" if pack.name in stale_names else ""
        out.append(f"pack          : {pack.name} {pack.version}{flag}")
        out.append(f"  retrieved   : {pack.retrieved} ({age} days ago)")
        out.append(f"  licence     : {pack.license}")
        out.append(f"  source      : {pack.source}")
        out.append(f"  indicators  : {len(pack.indicators)} "
                   f"({len(pack.active(today))} usable, "
                   f"{len(pack.expired(today))} expired)")

    # Every surface, including the ones these packs do not cover. A surface
    # left out of the table would read as one that came back clean.
    out.append("surfaces      :")
    for row in result.surface_rows():
        label = row.kind.replace("_", " ")
        if not row.covered:
            out.append(f"  {label:<16}: NOT COVERED by these packs -- would "
                       f"read {row.description}")
            continue
        skipped = f", {row.skipped} skipped" if row.skipped else ""
        out.append(f"  {label:<16}: {row.examined} {row.unit}(s)"
                   f"{skipped}, {row.indicators} indicator(s) -- "
                   f"{row.description}")

    out.append(f"findings      : {len(result.findings)}")
    counts = severity_counts(result.findings)
    if counts:
        ordered = sorted(counts.items(), key=lambda kv: -SEVERITY_ORDER.get(kv[0], 0))
        out.append("  by severity : " +
                   ", ".join(f"{k.lower()}={v}" for k, v in ordered))

    if result.findings:
        out.append("")
        _finding_block(out, result.findings, show_note=show_notes)

    if result.corroboration:
        out.append("")
        out.append(f"{STATUS_CORROBORATION} ({len(result.corroboration)}): the "
                   "pack grades these too common to alert on alone, and "
                   "nothing else in this scan backed them up. Not findings.")
        _finding_block(out, result.corroboration, show_note=show_notes)

    if result.expired:
        out.append("")
        out.append(f"{STATUS_EXPIRED} ({len(result.expired)}): matched, but the "
                   "pack author stopped standing behind these on the dates "
                   "shown. Reported so you can see the pack has decayed -- "
                   "they are not evidence of anything.")
        _finding_block(out, result.expired, show_note=False)

    note = result.coverage_note()
    if note:
        out.append("")
        out.append("Coverage: " + note + ".")

    if result.errors:
        out.append("")
        out.append(f"{len(result.errors)} error(s):")
        for err in result.errors[:10]:
            out.append(f"  - {err}")

    out.append("")
    out.append("Note: host-observable markers only, on the surfaces listed "
               "above and no others. Network, identity and cloud telemetry "
               "are a different assessment -- see `coldlight assurance`. A "
               "clean result here means these markers were absent from these "
               "surfaces, not that the host is clean.")
    return "\n".join(out)


def json_report(result: IocScanResult) -> dict:
    today = result.today
    return {
        "tool": "coldlight ioc",
        "scanned_on": result.scanned_on,
        "packs": [p.to_dict(today) for p in result.packs],
        "files_scanned": result.files_scanned,
        "files_skipped": result.files_skipped,
        "surfaces": [row.to_dict() for row in result.surface_rows()],
        "surfaces_uncovered": [row.kind for row in result.uncovered_surfaces],
        "indicators_total": result.indicators_total,
        "indicators_active": result.indicators_active,
        "indicators_expired": result.indicators_expired,
        "indicators_undated": result.indicators_undated,
        "stale_packs": [p.name for p in result.stale_packs],
        "fully_current": result.fully_current,
        "coverage_note": result.coverage_note(),
        "severity_counts": severity_counts(result.findings),
        "findings": [f.to_dict() for f in result.findings],
        "corroboration_required": [f.to_dict() for f in result.corroboration],
        "expired": [f.to_dict() for f in result.expired],
        "errors": result.errors,
    }
