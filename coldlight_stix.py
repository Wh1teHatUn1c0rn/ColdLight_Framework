#!/usr/bin/env python3
"""
ColdLight STIX import: turn a published STIX 2.1 bundle into an indicator pack.

A real indicator pack is not hand-typed. Published packs ship a STIX 2.1
bundle because that is the one format every consumer can read, and it carries
exactly the fields `coldlight_ioc` needs -- a pattern, a validity window, a
confidence, external references, a marking. This reads one and writes the
pack.

WHAT THIS REFUSES TO DO, AND WHY IT MATTERS MORE THAN WHAT IT IMPORTS:

* A pattern this module cannot represent in full is NOT narrowed down to the
  part it understands. `[file:name = 'x' AND file:size = 4096]` describes one
  file; the `file:name` half on its own describes every file with that name.
  Importing the half would hand the operator an indicator that looks like the
  author's and matches more than the author said, which is a false positive
  with someone else's name on it.
* A rule in another language is not translated. A bundle's Sigma, Suricata and
  YARA patterns are carried as `pattern_type` values, and ColdLight evaluates
  none of them. Pretending otherwise would claim coverage of a correlation
  rule by matching one of its strings.
* An indicator with no tier and no confidence is not given one. Tier maps to
  the severity a report prints and attributes to the pack author; inventing it
  would put our guess in their mouth. It is refused and counted.
* Every refusal is reported, grouped and counted. An importer that silently
  drops two thirds of a bundle produces a pack whose clean scan means nothing,
  and the operator has no way to know. The refusal list IS the coverage
  statement for the resulting pack.

ONE DEFAULT IS APPLIED RATHER THAN REFUSED. A bundle that states no uniqueness
class gets `C`, so the indicator cannot alert on its own and waits for a second
marker. The alternative defaults are worse in both directions: `A` would print
standalone findings the author never graded as distinctive, and refusing would
discard most real bundles, since uniqueness is a ColdLight/Admiralty axis that
STIX has no field for. Every indicator that got the default says so in its
`note`, which the report prints beside the finding, and the import summary
counts them.

Read-only, offline, stdlib only. Nothing here fetches a bundle: it reads the
file you already have, which is also why the generated pack's `retrieved` date
is the bundle's own last-modified date rather than today when the bundle is
older -- understating freshness is the safe direction, and the coverage ledger
is what reports it.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path

from coldlight_config import __version__ as TOOL_VERSION
from coldlight_ioc import (KIND_FILE_DIGEST, KIND_FILE_NAME,
                           KIND_LISTENING_PORT, TIERS, UNIQUENESS_CLASSES,
                           VERIFICATION_LEVELS)


class StixError(ValueError):
    """The bundle cannot be used, or produced nothing usable."""


# ---------------------------------------------------------------------------
# What a STIX pattern can become
# ---------------------------------------------------------------------------

# (object-type, normalised property) -> ColdLight indicator kind.
#
# Deliberately short. Every pair here is a fact about a file or a configured
# port on the host being scanned, which is the only thing ColdLight looks at.
SUPPORTED_PROPERTIES = {
    ("file", "name"): KIND_FILE_NAME,
    ("file", "hashes.sha-256"): KIND_FILE_DIGEST,
    ("network-traffic", "dst_port"): KIND_LISTENING_PORT,
}

# Why a STIX object type is out of scope, in the operator's terms rather than
# "unsupported". A reason a reader can act on is the difference between a
# refusal list they read and one they skim.
OUT_OF_SCOPE = {
    "ipv4-addr": "a network address: no file on disk carries it",
    "ipv6-addr": "a network address: no file on disk carries it",
    "domain-name": "DNS, which this tool does not read",
    "url": "network traffic, which this tool does not read",
    "email-addr": "mail, which this tool does not read",
    "email-message": "mail, which this tool does not read",
    "user-account": "an account, and ColdLight has no account surface",
    "windows-registry-key": "the Windows registry, which this tool does not read",
    "process": "a running process; this tool reads files, not process tables",
    "autonomous-system": "routing infrastructure",
    "x509-certificate": "a certificate, which this tool does not inspect",
    "mutex": "runtime state, not a file",
    "software": "an installed-software inventory, which this tool does not build",
    "directory": "a directory; the file surfaces match files, not the folders "
                 "holding them",
    "artifact": "an embedded payload. ColdLight never reconstructs a sample",
}

# Properties of an object type ColdLight does handle that it still cannot use.
OUT_OF_SCOPE_PROPERTIES = {
    ("file", "hashes.md5"): "an MD5 digest; the digest surface computes SHA-256",
    ("file", "hashes.sha-1"): "a SHA-1 digest; the digest surface computes "
                              "SHA-256",
    ("file", "size"): "a file size, which is not a marker on its own",
    ("file", "created"): "a timestamp, which this tool does not match on",
    ("file", "parent_directory_ref.path"): "a reference to another object, "
                                           "which needs the whole pattern "
                                           "graph rather than one comparison",
    ("network-traffic", "src_port"): "a source port, which is ephemeral",
    ("network-traffic", "dst_ref.value"): "a network address",
}

# Operators whose meaning ColdLight can carry exactly.
#   =        a literal value
#   MATCHES  a regular expression, which is what `regex = true` is for
# Everything else is refused rather than approximated: LIKE's % and _ are not
# regex metacharacters, and != / < / > describe a set this scanner has no way
# to express.
_OP_EQUAL = "="
_OP_MATCHES = "MATCHES"

_COMPOUND = re.compile(r"\b(AND|OR|FOLLOWEDBY|WITHIN|REPEATS|IN|EXISTS)\b",
                       re.I)

_COMPARISON = re.compile(
    r"""^\s*\[\s*
        (?P<object>[A-Za-z0-9-]+)
        :
        (?P<prop>[A-Za-z0-9_.'"\-]+)
        \s*(?P<op>=|!=|>=|<=|>|<|MATCHES|LIKE)\s*
        (?P<value>'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|[0-9]+)
        \s*\]\s*$""",
    re.X | re.I)

# STIX label spellings for the three ColdLight axes. A bundle that states one
# explicitly always wins over anything derived.
_UNIQUENESS_LABELS = {}
for _cls in UNIQUENESS_CLASSES:
    for _form in (f"class-{_cls}", f"uniqueness-{_cls}", f"class{_cls}",
                  f"coldlight-class-{_cls}"):
        _UNIQUENESS_LABELS[_form.lower()] = _cls

_VERIFICATION_LABELS = {}
for _level in VERIFICATION_LEVELS:
    for _form in (_level, f"verification-{_level}", f"source-{_level}"):
        _VERIFICATION_LABELS[_form.lower()] = _level

_TIER_LABELS = {}
for _tier in TIERS:
    for _form in (_tier, f"tier-{_tier}", f"tier{_tier[1]}",
                  f"tier-{_tier[1]}"):
        _TIER_LABELS[_form.lower()] = _tier

# STIX confidence is 0-100. The pack this was built for states that its
# bundle's confidence is "mapped from tier", so this inverts that mapping.
# Exposed as a table rather than buried in an if-chain because it is a
# judgement a reader may disagree with, and an indicator's severity follows
# from it.
CONFIDENCE_TIERS = ((85, "T1"), (65, "T2"), (40, "T3"), (0, "T4"))

DEFAULT_UNIQUENESS = "C"
DEFAULT_VERIFICATION = "V4"


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Refusal:
    """One STIX object that did not become an indicator."""
    stix_id: str
    name: str
    reason: str
    detail: str = ""

    def to_dict(self) -> dict:
        return {"stix_id": self.stix_id, "name": self.name,
                "reason": self.reason, "detail": self.detail}


@dataclass
class Entry:
    """One indicator, ready to be written into a pack."""
    id: str
    kind: str
    value: str
    uniqueness: str
    verification: str
    tier: str
    title: str
    valid_until: str = ""
    source: str = ""
    note: str = ""
    regex: bool = False
    stix_id: str = ""
    defaults: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {"id": self.id, "kind": self.kind, "value": self.value,
                "uniqueness": self.uniqueness,
                "verification": self.verification, "tier": self.tier,
                "title": self.title, "valid_until": self.valid_until,
                "source": self.source, "note": self.note, "regex": self.regex,
                "stix_id": self.stix_id, "defaults": list(self.defaults)}


@dataclass
class Imported:
    """What one bundle produced, and what it did not."""
    name: str = ""
    version: str = ""
    source: str = ""
    license: str = ""
    retrieved: str = ""
    description: str = ""
    entries: list[Entry] = field(default_factory=list)
    refusals: list[Refusal] = field(default_factory=list)
    indicators_seen: int = 0
    objects_seen: int = 0

    @property
    def refusals_by_reason(self) -> dict[str, list[Refusal]]:
        grouped: dict[str, list[Refusal]] = {}
        for refusal in self.refusals:
            grouped.setdefault(refusal.reason, []).append(refusal)
        return dict(sorted(grouped.items(), key=lambda kv: -len(kv[1])))

    @property
    def defaulted(self) -> list[Entry]:
        return [e for e in self.entries if e.defaults]

    def expired_on(self, today: date) -> list[Entry]:
        """Entries whose window had already closed when they were imported.

        Not an error -- the scanner reports them as EXPIRED and excludes them
        from findings, which is the point. It is counted here because an
        import that is mostly dead indicators is a pack worth re-fetching, and
        nothing else in the chain would say so.
        """
        out = []
        for entry in self.entries:
            if not entry.valid_until:
                continue
            try:
                if date.fromisoformat(entry.valid_until) < today:
                    out.append(entry)
            except ValueError:
                continue
        return out

    def to_dict(self, today: date | None = None) -> dict:
        today = today or datetime.now(timezone.utc).date()
        return {
            "tool": f"coldlight stix import {TOOL_VERSION}",
            "pack": {"name": self.name, "version": self.version,
                     "source": self.source, "license": self.license,
                     "retrieved": self.retrieved,
                     "description": self.description},
            "objects_seen": self.objects_seen,
            "indicators_seen": self.indicators_seen,
            "imported": len(self.entries),
            "refused": len(self.refusals),
            "defaults_applied": len(self.defaulted),
            "already_expired": len(self.expired_on(today)),
            "entries": [e.to_dict() for e in self.entries],
            "refusals": [r.to_dict() for r in self.refusals],
            "refusals_by_reason": {reason: len(items) for reason, items
                                   in self.refusals_by_reason.items()},
        }


# ---------------------------------------------------------------------------
# Pattern parsing
# ---------------------------------------------------------------------------

def _normalise_property(raw: str) -> str:
    """`hashes.'SHA-256'` and `hashes.SHA-256` are the same property."""
    return raw.replace("'", "").replace('"', "").strip().lower()


def _unquote(raw: str) -> str:
    """The value of a STIX string literal, with its escapes resolved.

    STIX patterning defines exactly two escapes inside a literal: a quote and
    a backslash. Only those are resolved, and every other backslash sequence
    is left exactly as written -- because the values where this is not
    cosmetic are the MATCHES ones, and a regex is made of backslash
    sequences. Resolving `\\.` to `.` would turn an escaped dot into "any
    character" and hand the operator a broader pattern than the author
    published, under the author's name.
    """
    if raw[:1] in {"'", '"'} and raw[-1:] == raw[:1]:
        inner = raw[1:-1]
        return re.sub(r"""\\(['"\\])""", lambda m: m.group(1), inner)
    return raw


def parse_pattern(pattern: str) -> tuple[str, str, bool]:
    """(kind, value, is_regex) for a pattern ColdLight can evaluate.

    Raises StixError with the reason otherwise. The reason is the product
    here: it is what the refusal list shows the operator.
    """
    text = (pattern or "").strip()
    if not text:
        raise StixError("the indicator carries no pattern")

    # String literals are blanked before looking for AND/OR, so a file called
    # "FOO AND BAR.txt" is not mistaken for a compound pattern. The comparison
    # itself is still matched against the original text.
    bare = re.sub(r"'(?:[^'\\]|\\.)*'", "''", text)
    bare = re.sub(r'"(?:[^"\\]|\\.)*"', '""', bare)

    compound = _COMPOUND.search(bare)
    if bare.count("[") > 1 or compound:
        operator = (compound.group(1).upper() if compound
                    else "multiple observations")
        raise StixError(
            f"compound pattern ({operator}): importing one comparison from it "
            "would match more than the author described")

    match = _COMPARISON.match(text)
    if not match:
        raise StixError("the pattern is not a single STIX comparison this "
                        "importer can read")

    obj = match.group("object").lower()
    prop = _normalise_property(match.group("prop"))
    operator = match.group("op").upper()

    if obj in OUT_OF_SCOPE:
        raise StixError(f"{obj} is {OUT_OF_SCOPE[obj]}")
    if (obj, prop) in OUT_OF_SCOPE_PROPERTIES:
        raise StixError(f"{obj}:{prop} is "
                        f"{OUT_OF_SCOPE_PROPERTIES[(obj, prop)]}")

    kind = SUPPORTED_PROPERTIES.get((obj, prop))
    if kind is None:
        raise StixError(f"{obj}:{prop} has no surface in this tool")

    if operator == _OP_MATCHES:
        if kind != KIND_FILE_NAME:
            raise StixError(
                f"MATCHES on {obj}:{prop} cannot be carried: a "
                f"{kind} value is compared whole, not as a pattern")
        return kind, _unquote(match.group("value")), True
    if operator != _OP_EQUAL:
        raise StixError(
            f"the {operator} operator describes a set of values this scanner "
            "cannot express; only = and MATCHES are carried")

    return kind, _unquote(match.group("value")), False


# ---------------------------------------------------------------------------
# The three ColdLight axes
# ---------------------------------------------------------------------------

def _labels(obj: dict) -> list[str]:
    raw = obj.get("labels") or []
    out = [str(x).strip().lower() for x in raw if str(x).strip()]
    for key in ("indicator_types",):
        out.extend(str(x).strip().lower() for x in (obj.get(key) or []))
    return out


def tier_of(obj: dict) -> tuple[str, bool]:
    """(tier, was_derived). Raises StixError when the bundle states neither.

    An explicit label beats a derived confidence: the author said it.
    """
    for label in _labels(obj):
        if label in _TIER_LABELS:
            return _TIER_LABELS[label], False

    confidence = obj.get("confidence")
    if isinstance(confidence, bool) or not isinstance(confidence, int):
        raise StixError(
            "no tier label and no confidence, so the severity a report would "
            "print has no basis in the bundle")
    if not 0 <= confidence <= 100:
        raise StixError(f"confidence {confidence} is outside 0-100")
    for floor, tier in CONFIDENCE_TIERS:
        if confidence >= floor:
            return tier, True
    return "T4", True


def uniqueness_of(obj: dict) -> tuple[str, bool]:
    """(class, was_defaulted). See the module docstring for the default."""
    for label in _labels(obj):
        if label in _UNIQUENESS_LABELS:
            return _UNIQUENESS_LABELS[label], False
    return DEFAULT_UNIQUENESS, True


def verification_of(obj: dict) -> tuple[str, bool]:
    """(level, was_defaulted).

    Unlike uniqueness and tier, this changes nothing about what the scanner
    does -- it is reported, not acted on -- so the unverified end of the scale
    is the safe default rather than a refusal.
    """
    for label in _labels(obj):
        if label in _VERIFICATION_LABELS:
            return _VERIFICATION_LABELS[label], False
    return DEFAULT_VERIFICATION, True


# ---------------------------------------------------------------------------
# Bundle reading
# ---------------------------------------------------------------------------

def _iso_date(value) -> str:
    """The date part of a STIX timestamp, or "" if there isn't one."""
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        return date.fromisoformat(text[:10]).isoformat()
    except ValueError:
        return ""


def _slug(text: str) -> str:
    out = re.sub(r"[^A-Za-z0-9]+", "-", str(text or "")).strip("-").upper()
    return out[:60]


def _external_url(obj: dict) -> str:
    for ref in obj.get("external_references") or []:
        if isinstance(ref, dict) and str(ref.get("url", "")).startswith("http"):
            return str(ref["url"])
    return ""


def _any_external_url(objects: list[dict]) -> str:
    """The first external reference URL in the bundle, whatever carries it.

    A pack must name where its intel came from, and in a published bundle that
    URL is on the objects themselves -- the indicators, the tool, the report.
    When nothing carries one, `import_bundle` refuses rather than writing a
    pack with an empty source field, because `load_pack` would refuse it later
    and the operator would be holding a file instead of an error.
    """
    for obj in objects:
        url = _external_url(obj)
        if url:
            return url
    return ""


def load_bundle(path: str | Path) -> dict:
    """Read a bundle, or refuse it.

    A file that is not a bundle is refused rather than scanned for anything
    indicator-shaped: guessing at the structure of a security artifact is how
    an importer ends up half-reading two different formats.
    """
    file_path = Path(path)
    if not file_path.is_file():
        raise StixError(f"no such bundle: {file_path}")
    try:
        data = json.loads(file_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise StixError(f"cannot read {file_path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise StixError(f"{file_path} is not valid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise StixError(f"{file_path} is not a STIX bundle (expected an "
                        "object at the top level)")
    if str(data.get("type", "")).lower() != "bundle":
        raise StixError(f"{file_path} declares type "
                        f"{data.get('type', 'nothing')!r}, not 'bundle'")
    if not isinstance(data.get("objects"), list):
        raise StixError(f"{file_path} has no objects array")
    return data


def _marking_license(objects: list[dict]) -> str:
    """A licence from a statement marking, if the bundle carries one.

    A TLP marking is deliberately NOT read as a licence. TLP:CLEAR says who
    may see the data; it says nothing about the terms of reuse, and a pack
    whose licence field says "TLP:CLEAR" would be misattributing the author's
    own terms.
    """
    for obj in objects:
        if obj.get("type") != "marking-definition":
            continue
        if obj.get("definition_type") != "statement":
            continue
        statement = str((obj.get("definition") or {}).get("statement", ""))
        if statement.strip():
            return statement.strip()
    return ""


def _bundle_identity(objects: list[dict]) -> str:
    for obj in objects:
        if obj.get("type") == "identity" and obj.get("name"):
            return str(obj["name"])
    return ""


def _newest_modified(objects: list[dict]) -> str:
    dates = [_iso_date(o.get("modified") or o.get("created"))
             for o in objects]
    dates = [d for d in dates if d]
    return max(dates) if dates else ""


def import_bundle(path: str | Path, *, name: str = "", version: str = "",
                  source: str = "", license: str = "",
                  today: date | None = None) -> Imported:
    """Convert a STIX 2.1 bundle into pack entries plus a refusal list.

    Raises StixError when the bundle yields nothing: a pack with no indicators
    does not load, so emitting one would move the failure to whoever tried to
    use the file.
    """
    today = today or datetime.now(timezone.utc).date()
    data = load_bundle(path)
    objects = [o for o in data["objects"] if isinstance(o, dict)]

    result = Imported(objects_seen=len(objects))
    seen_ids: dict[str, int] = {}

    for obj in objects:
        if obj.get("type") != "indicator":
            continue
        result.indicators_seen += 1
        stix_id = str(obj.get("id", "") or "")
        title = str(obj.get("name", "") or "").strip()

        pattern_type = str(obj.get("pattern_type", "stix") or "stix").lower()
        if pattern_type != "stix":
            result.refusals.append(Refusal(
                stix_id=stix_id, name=title,
                reason=f"a {pattern_type} rule, which ColdLight does not "
                       f"evaluate",
                detail="translating it would claim coverage this tool does "
                       "not have"))
            continue

        try:
            kind, value, is_regex = parse_pattern(str(obj.get("pattern", "")))
            tier, tier_derived = tier_of(obj)
        except StixError as exc:
            result.refusals.append(Refusal(stix_id=stix_id, name=title,
                                           reason=str(exc)))
            continue

        uniqueness, uniqueness_defaulted = uniqueness_of(obj)
        verification, verification_defaulted = verification_of(obj)

        defaults = []
        if uniqueness_defaulted:
            defaults.append(
                f"uniqueness not stated in the bundle; ColdLight assigned "
                f"{DEFAULT_UNIQUENESS}, so this cannot alert on its own")
        if verification_defaulted:
            defaults.append(
                f"source verification not stated; recorded as "
                f"{DEFAULT_VERIFICATION} (unverified)")
        if tier_derived:
            defaults.append(
                f"tier {tier} derived from STIX confidence "
                f"{obj.get('confidence')}")

        identifier = _slug(title) or f"STIX-{stix_id[-8:].upper()}"
        if identifier in seen_ids:
            seen_ids[identifier] += 1
            identifier = f"{identifier}-{seen_ids[identifier]}"
        else:
            seen_ids[identifier] = 1

        note_parts = []
        description = str(obj.get("description", "") or "").strip()
        if description:
            note_parts.append(description.replace("\n", " ")[:400])
        note_parts.append(f"imported from {stix_id}")
        note_parts.extend(defaults)

        result.entries.append(Entry(
            id=identifier,
            kind=kind,
            value=value,
            uniqueness=uniqueness,
            verification=verification,
            tier=tier,
            title=title or identifier,
            valid_until=_iso_date(obj.get("valid_until")),
            source=_external_url(obj),
            note=" | ".join(note_parts),
            regex=is_regex,
            stix_id=stix_id,
            defaults=tuple(defaults),
        ))

    # ---- pack-level metadata ---------------------------------------------
    tool_names = [str(o.get("name")) for o in objects
                  if o.get("type") == "tool" and o.get("name")]
    newest = _newest_modified(objects)

    result.name = (name or (_slug(tool_names[0]).lower() if tool_names
                            else "imported-bundle"))
    result.version = version or newest or "0"
    result.source = source or _any_external_url(objects)
    result.license = license or _marking_license(objects)
    # The bundle's own last-modified date, not today, when it is older. A pack
    # fetched today from a year-old bundle is a year-old pack, and `retrieved`
    # is what the coverage ledger reads to decide whether it is still current.
    result.retrieved = min(newest, today.isoformat()) if newest else \
        today.isoformat()
    identity = _bundle_identity(objects)
    result.description = (
        f"Imported from {Path(path).name}"
        + (f", published by {identity}" if identity else "")
        + f", {result.indicators_seen} STIX indicator(s) read, "
        f"{len(result.entries)} evaluable here.")

    if not result.entries:
        reasons = "; ".join(f"{reason} ({len(items)})" for reason, items
                            in list(result.refusals_by_reason.items())[:4])
        raise StixError(
            f"{Path(path).name} yielded no indicator this tool can evaluate "
            f"out of {result.indicators_seen} in the bundle. A pack with no "
            f"indicators does not load, so nothing was written. "
            f"Reasons: {reasons or 'no indicator objects in the bundle'}")

    missing = [field_name for field_name, value in
               (("source", result.source), ("license", result.license))
               if not str(value).strip()]
    if missing:
        raise StixError(
            f"{Path(path).name} does not state its "
            f"{' or '.join(missing)}, and a pack without that cannot be "
            f"attributed in a report. Pass "
            + " ".join(f"--{m}" for m in missing)
            + " to state it yourself.")
    return result


# ---------------------------------------------------------------------------
# Writing the pack
# ---------------------------------------------------------------------------

def _toml_string(value: str) -> str:
    """A TOML string that survives a backslash.

    A MATCHES value is a regular expression, so backslashes are the normal
    case rather than the exception. A literal string takes no escapes at all,
    which is why it is preferred whenever the value has no single quote and no
    control character; everything else falls back to a basic string with each
    escape written out.
    """
    text = str(value)
    risky = any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in text)
    if "'" not in text and not risky:
        return f"'{text}'"
    out = []
    for ch in text:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ord(ch) < 0x20 or ord(ch) == 0x7f:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def render_pack(imported: Imported) -> str:
    """The pack file, as TOML.

    Generated rather than hand-written, so it says so at the top: which
    bundle, which tool version, how many STIX indicators were read, how many
    were refused and which decisions ColdLight made. Someone will open this
    file in six months and need to know whether to trust its grades.
    """
    out: list[str] = []
    out.append("# ColdLight indicator pack -- GENERATED, do not hand-edit.")
    out.append("#")
    out.append(f"# Written by coldlight stix import {TOOL_VERSION}.")
    out.append(f"# {imported.description}")
    out.append("#")
    out.append(f"# Refused: {len(imported.refusals)} STIX indicator(s). That "
               "list is the coverage")
    out.append("# statement for this pack -- a scan with it is clean only on "
               "the surfaces")
    out.append("# the entries below actually cover. Re-run the import with "
               "--json to keep it.")
    if imported.defaulted:
        out.append("#")
        out.append(f"# {len(imported.defaulted)} entr(ies) carry a ColdLight "
                   "default because the bundle")
        out.append("# stated no equivalent. Each one says so in its note, "
                   "and an entry that")
        out.append("# defaulted to uniqueness "
                   f"{DEFAULT_UNIQUENESS} cannot raise a finding alone.")
    out.append("")
    out.append("[pack]")
    out.append(f"name = {_toml_string(imported.name)}")
    out.append(f"version = {_toml_string(imported.version)}")
    out.append(f"source = {_toml_string(imported.source)}")
    out.append(f"license = {_toml_string(imported.license)}")
    out.append(f"retrieved = {_toml_string(imported.retrieved)}")
    out.append(f"description = {_toml_string(imported.description)}")

    for entry in imported.entries:
        out.append("")
        out.append("[[indicator]]")
        out.append(f"id = {_toml_string(entry.id)}")
        out.append(f"kind = {_toml_string(entry.kind)}")
        out.append(f"value = {_toml_string(entry.value)}")
        if entry.regex:
            out.append("regex = true")
        out.append(f"uniqueness = {_toml_string(entry.uniqueness)}")
        out.append(f"verification = {_toml_string(entry.verification)}")
        out.append(f"tier = {_toml_string(entry.tier)}")
        out.append(f"title = {_toml_string(entry.title)}")
        if entry.valid_until:
            out.append(f"valid_until = {_toml_string(entry.valid_until)}")
        if entry.source:
            out.append(f"source = {_toml_string(entry.source)}")
        if entry.note:
            out.append(f"note = {_toml_string(entry.note)}")
    out.append("")
    return "\n".join(out)


def write_pack(imported: Imported, path: str | Path) -> Path:
    file_path = Path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(render_pack(imported), encoding="utf-8",
                         newline="\n")
    return file_path


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def text_report(imported: Imported, *, today: date | None = None) -> str:
    today = today or datetime.now(timezone.utc).date()
    out: list[str] = []
    out.append("=" * 68)
    out.append("STIX import")
    out.append("=" * 68)
    out.append(f"bundle objects    : {imported.objects_seen}")
    out.append(f"STIX indicators   : {imported.indicators_seen}")
    out.append(f"imported          : {len(imported.entries)}")
    out.append(f"refused           : {len(imported.refusals)}")

    kinds: dict[str, int] = {}
    for entry in imported.entries:
        kinds[entry.kind] = kinds.get(entry.kind, 0) + 1
    if kinds:
        out.append("  by surface      : "
                   + ", ".join(f"{k}={v}" for k, v in sorted(kinds.items())))

    expired = imported.expired_on(today)
    if expired:
        out.append(f"already expired   : {len(expired)} -- imported, reported "
                   "as EXPIRED, and unable to produce a finding")
    if imported.defaulted:
        out.append(f"ColdLight defaults: {len(imported.defaulted)} entr(ies) "
                   "carry a grade the bundle did not state")

    if imported.refusals:
        out.append("")
        out.append("NOT imported -- this is the coverage statement for the "
                   "pack:")
        for reason, items in imported.refusals_by_reason.items():
            out.append(f"  {len(items):>3}  {reason}")
            for refusal in items[:3]:
                label = refusal.name or refusal.stix_id or "unnamed"
                out.append(f"       - {label}")
            if len(items) > 3:
                out.append(f"       ... and {len(items) - 3} more")

    out.append("")
    out.append("A scan with this pack covers the surfaces its entries name "
               "and nothing else.")
    out.append("Everything in the refusal list above is a marker the bundle "
               "published and this")
    out.append("pack does not carry -- most of a real pack lives in network, "
               "identity and cloud")
    out.append("telemetry, which ColdLight does not read.")
    return "\n".join(out)


def json_report(imported: Imported, *, today: date | None = None) -> dict:
    return imported.to_dict(today)
