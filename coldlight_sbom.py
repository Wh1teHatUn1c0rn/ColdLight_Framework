#!/usr/bin/env python3
"""
ColdLight SBOM ingest: read a CycloneDX or SPDX bill of materials and turn it into
a list of components that can be checked against OSV.

Why this matters: a manifest scan needs the source tree. An SBOM scan does not.
That means you can assess an artifact you did NOT build -- a vendor container, a
third-party appliance image, a compiled binary a supplier shipped you -- using
the inventory they (or `syft`/`trivy`/`cdxgen`) already produced.

Supported inputs:
  * CycloneDX JSON (1.2 - 1.6)
  * SPDX JSON (2.x)
  * SPDX tag-value (.spdx)

A DELIBERATE DESIGN CHOICE: components that cannot be mapped to an OSV
ecosystem with confidence are recorded as SKIPPED, with a reason, and reported
loudly. They are never silently dropped. Container SBOMs are mostly OS
packages, and querying OSV with a wrong ecosystem string returns zero results
-- which would report "no vulnerabilities" for packages that were never
actually checked. A known unknown is safe; a silent gap is not.

Stdlib only. Read-only.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote


class SbomError(ValueError):
    """The file is not an SBOM we can read."""


# ---------------------------------------------------------------------------
# Package URL (purl) parsing -- https://github.com/package-url/purl-spec
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Purl:
    type: str
    namespace: str
    name: str
    version: str
    qualifiers: dict[str, str] = field(default_factory=dict)


def parse_purl(text: str) -> Purl | None:
    """Parse `pkg:type/namespace/name@version?qualifiers#subpath`."""
    if not text:
        return None
    raw = text.strip()
    if not raw.lower().startswith("pkg:"):
        return None

    rest = raw[4:].lstrip("/")
    if not rest:
        return None

    rest = rest.split("#", 1)[0]                     # drop subpath

    qualifiers: dict[str, str] = {}
    if "?" in rest:
        rest, query = rest.split("?", 1)
        for pair in query.split("&"):
            if "=" in pair:
                key, value = pair.split("=", 1)
                qualifiers[unquote(key).lower()] = unquote(value)

    version = ""
    if "@" in rest:
        rest, version = rest.rsplit("@", 1)
        version = unquote(version)

    segments = [s for s in rest.split("/") if s]
    if len(segments) < 2:
        return None

    ptype = unquote(segments[0]).lower()
    name = unquote(segments[-1])
    namespace = "/".join(unquote(s) for s in segments[1:-1])

    if not ptype or not name:
        return None
    return Purl(ptype, namespace, name, version, qualifiers)


# purl type -> OSV ecosystem, for language package managers.
PURL_TYPE_TO_ECOSYSTEM: dict[str, str] = {
    "pypi": "PyPI",
    "npm": "npm",
    "golang": "Go",
    "cargo": "crates.io",
    "maven": "Maven",
    "nuget": "NuGet",
    "gem": "RubyGems",
    "composer": "Packagist",
    "hex": "Hex",
    "pub": "Pub",
    "conan": "ConanCenter",
    "cran": "CRAN",
    "swift": "SwiftURL",
    "hackage": "Hackage",
}

# OS package types need the distribution AND its version to be meaningful.
OS_PURL_TYPES = {"deb", "rpm", "apk"}

# distro name (from the `distro` qualifier or the purl namespace) -> OSV family
_DISTRO_FAMILY: dict[str, str] = {
    "debian": "Debian",
    "ubuntu": "Ubuntu",
    "alpine": "Alpine",
    "rhel": "Red Hat",
    "redhat": "Red Hat",
    "rocky": "Rocky Linux",
    "rockylinux": "Rocky Linux",
    "alma": "AlmaLinux",
    "almalinux": "AlmaLinux",
}

# Families where OSV does NOT version the ecosystem string.
_UNVERSIONED_FAMILIES = {"Red Hat"}


def _normalise_pypi(name: str) -> str:
    """PEP 503 normalisation -- OSV keys PyPI on the normalised name."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _os_ecosystem(purl: Purl) -> str:
    """OSV ecosystem for an OS package, or '' when it can't be determined.

    OSV spells these 'Debian:11', 'Ubuntu:22.04', 'Alpine:v3.18', 'Red Hat'.
    Without the distro version a query is meaningless, so we return '' and let
    the caller record a skip rather than guess.
    """
    distro = purl.qualifiers.get("distro", "")
    family_key, _, version = distro.partition("-")
    family_key = family_key.strip().lower()

    if not family_key:
        family_key = purl.namespace.strip().lower()
        version = ""

    family = _DISTRO_FAMILY.get(family_key, "")
    if not family:
        return ""
    if family in _UNVERSIONED_FAMILIES:
        return family
    if not version:
        return ""

    parts = version.split(".")
    if family == "Debian":
        return f"Debian:{parts[0]}"
    if family == "Ubuntu":
        return f"Ubuntu:{'.'.join(parts[:2])}"
    if family == "Alpine":
        return f"Alpine:v{'.'.join(parts[:2])}"
    if family in ("Rocky Linux", "AlmaLinux"):
        return f"{family}:{parts[0]}"
    return ""


def purl_to_osv(purl: Purl) -> tuple[str, str, str]:
    """Map a purl to (ecosystem, name, version) for an OSV query.

    Returns ('', '', '') when the type is not something we can query safely.
    """
    ptype = purl.type

    if ptype in PURL_TYPE_TO_ECOSYSTEM:
        ecosystem = PURL_TYPE_TO_ECOSYSTEM[ptype]
        version = purl.version

        if ptype == "maven":
            # OSV uses group:artifact
            name = f"{purl.namespace}:{purl.name}" if purl.namespace else purl.name
        elif ptype == "golang":
            # The module path is namespace + name; OSV omits the leading 'v'.
            name = f"{purl.namespace}/{purl.name}" if purl.namespace else purl.name
            version = version.lstrip("v")
        elif ptype == "npm":
            # Scoped packages: @scope/name
            name = f"{purl.namespace}/{purl.name}" if purl.namespace else purl.name
        elif ptype == "pypi":
            name = _normalise_pypi(purl.name)
        elif ptype in ("composer", "swift"):
            name = f"{purl.namespace}/{purl.name}" if purl.namespace else purl.name
        else:
            name = purl.name

        return (ecosystem, name, version) if version else ("", "", "")

    if ptype in OS_PURL_TYPES:
        ecosystem = _os_ecosystem(purl)
        if ecosystem and purl.version:
            return ecosystem, purl.name, purl.version
        return "", "", ""

    return "", "", ""


# ---------------------------------------------------------------------------
# Component model
# ---------------------------------------------------------------------------

@dataclass
class Component:
    name: str
    version: str = ""
    ecosystem: str = ""        # OSV ecosystem; empty => not checkable
    purl: str = ""
    skip_reason: str = ""

    @property
    def checkable(self) -> bool:
        return bool(self.ecosystem and self.name and self.version)

    @property
    def label(self) -> str:
        base = f"{self.name}@{self.version}" if self.version else self.name
        return f"{base} [{self.purl}]" if self.purl else base


def _component_from(name: str, version: str, purl_text: str) -> Component:
    """Build a Component, resolving its OSV ecosystem or recording why not."""
    comp = Component(name=name or "", version=version or "", purl=purl_text or "")

    if not purl_text:
        comp.skip_reason = "no purl in SBOM (cannot determine ecosystem)"
        return comp

    purl = parse_purl(purl_text)
    if purl is None:
        comp.skip_reason = f"unparseable purl: {purl_text!r}"
        return comp

    # The purl is authoritative over the SBOM's own name/version fields.
    if purl.version:
        comp.version = purl.version

    ecosystem, osv_name, osv_version = purl_to_osv(purl)
    if not ecosystem:
        if purl.type in OS_PURL_TYPES:
            comp.skip_reason = (
                f"OS package ({purl.type}) without a resolvable distro version "
                f"-- OSV needs e.g. 'Debian:11'"
            )
        elif purl.type in PURL_TYPE_TO_ECOSYSTEM:
            comp.skip_reason = f"no version for {purl.type} component"
        else:
            comp.skip_reason = f"unsupported purl type: {purl.type!r}"
        return comp

    comp.ecosystem = ecosystem
    comp.name = osv_name
    comp.version = osv_version
    return comp


# ---------------------------------------------------------------------------
# SBOM document
# ---------------------------------------------------------------------------

@dataclass
class Sbom:
    fmt: str = ""                 # CycloneDX | SPDX
    spec_version: str = ""
    document_name: str = ""
    tools: list[str] = field(default_factory=list)
    components: list[Component] = field(default_factory=list)
    path: str = ""

    @property
    def checkable(self) -> list[Component]:
        return [c for c in self.components if c.checkable]

    @property
    def skipped(self) -> list[Component]:
        return [c for c in self.components if not c.checkable]

    @property
    def label(self) -> str:
        bits = [self.fmt]
        if self.spec_version:
            bits.append(self.spec_version)
        if self.tools:
            bits.append(f"via {', '.join(self.tools[:2])}")
        return " ".join(bits)

    def skip_summary(self) -> dict[str, int]:
        """Skip reasons, grouped with counts.

        Reasons are kept verbatim rather than collapsed: identical reasons
        group on their own, and knowing WHICH purl type was unsupported (or
        which distro was unresolvable) is the actionable part.
        """
        counts: dict[str, int] = {}
        for comp in self.skipped:
            reason = comp.skip_reason or "unknown"
            counts[reason] = counts.get(reason, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


# ---------------------------------------------------------------------------
# CycloneDX
# ---------------------------------------------------------------------------

def _cyclonedx_tools(metadata: dict) -> list[str]:
    tools = metadata.get("tools")
    names: list[str] = []

    if isinstance(tools, dict):            # CycloneDX 1.5+
        for comp in tools.get("components", []) or []:
            name = comp.get("name", "")
            version = comp.get("version", "")
            if name:
                names.append(f"{name} {version}".strip())
    elif isinstance(tools, list):          # CycloneDX <= 1.4
        for tool in tools:
            if isinstance(tool, dict):
                name = tool.get("name", "")
                version = tool.get("version", "")
                if name:
                    names.append(f"{name} {version}".strip())
    return names


def _walk_cyclonedx(components, out: list[Component]) -> None:
    """CycloneDX components can nest arbitrarily deep."""
    for entry in components or []:
        if not isinstance(entry, dict):
            continue
        out.append(_component_from(
            entry.get("name", ""),
            str(entry.get("version", "") or ""),
            entry.get("purl", "") or "",
        ))
        _walk_cyclonedx(entry.get("components"), out)


def parse_cyclonedx(data: dict) -> Sbom:
    metadata = data.get("metadata", {}) or {}
    root = metadata.get("component", {}) or {}

    sbom = Sbom(
        fmt="CycloneDX",
        spec_version=str(data.get("specVersion", "") or ""),
        document_name=root.get("name", "") or data.get("serialNumber", "") or "",
        tools=_cyclonedx_tools(metadata),
    )
    components: list[Component] = []
    _walk_cyclonedx(data.get("components"), components)
    sbom.components = components
    return sbom


# ---------------------------------------------------------------------------
# SPDX (JSON and tag-value)
# ---------------------------------------------------------------------------

def _spdx_purl(package: dict) -> str:
    for ref in package.get("externalRefs", []) or []:
        if not isinstance(ref, dict):
            continue
        if (ref.get("referenceType", "") or "").lower() == "purl":
            return ref.get("referenceLocator", "") or ""
    return ""


def _spdx_tools(creation_info: dict) -> list[str]:
    tools: list[str] = []
    for creator in creation_info.get("creators", []) or []:
        if isinstance(creator, str) and creator.lower().startswith("tool:"):
            tools.append(creator.split(":", 1)[1].strip())
    return tools


def parse_spdx_json(data: dict) -> Sbom:
    sbom = Sbom(
        fmt="SPDX",
        spec_version=str(data.get("spdxVersion", "") or ""),
        document_name=str(data.get("name", "") or ""),
        tools=_spdx_tools(data.get("creationInfo", {}) or {}),
    )
    for package in data.get("packages", []) or []:
        if not isinstance(package, dict):
            continue
        sbom.components.append(_component_from(
            package.get("name", ""),
            str(package.get("versionInfo", "") or ""),
            _spdx_purl(package),
        ))
    return sbom


def parse_spdx_tag_value(text: str) -> Sbom:
    """Parse the tag-value (.spdx) serialisation."""
    sbom = Sbom(fmt="SPDX")
    name = version = purl = ""
    have_package = False

    def flush() -> None:
        nonlocal name, version, purl, have_package
        if have_package and name:
            sbom.components.append(_component_from(name, version, purl))
        name = version = purl = ""
        have_package = False

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        tag, value = line.split(":", 1)
        tag, value = tag.strip(), value.strip()

        if tag == "SPDXVersion":
            sbom.spec_version = value
        elif tag == "DocumentName":
            sbom.document_name = value
        elif tag == "Creator" and value.lower().startswith("tool:"):
            sbom.tools.append(value.split(":", 1)[1].strip())
        elif tag == "PackageName":
            flush()                      # a new package begins
            name = value
            have_package = True
        elif tag == "PackageVersion":
            version = value
        elif tag == "ExternalRef":
            parts = value.split()
            if len(parts) >= 3 and parts[1].lower() == "purl":
                purl = parts[2]

    flush()
    return sbom


# ---------------------------------------------------------------------------
# Loading / detection
# ---------------------------------------------------------------------------

def detect_format(text: str) -> str:
    """Return 'cyclonedx', 'spdx-json', 'spdx-tag' or ''."""
    stripped = text.lstrip()
    if stripped.startswith("{"):
        try:
            data = json.loads(text)
        except ValueError:
            return ""
        if not isinstance(data, dict):
            return ""
        if data.get("bomFormat") or "specVersion" in data and "components" in data:
            return "cyclonedx"
        if data.get("spdxVersion") or "SPDXID" in data:
            return "spdx-json"
        return ""
    if stripped.startswith("<"):
        return "xml"
    if re.search(r"^SPDXVersion\s*:", text, re.M):
        return "spdx-tag"
    return ""


def load_sbom(path: str | Path) -> Sbom:
    """Load an SBOM, auto-detecting the format."""
    file_path = Path(path)
    if not file_path.is_file():
        raise SbomError(f"no such file: {file_path}")

    text = file_path.read_text(encoding="utf-8", errors="replace")
    fmt = detect_format(text)

    if fmt == "cyclonedx":
        sbom = parse_cyclonedx(json.loads(text))
    elif fmt == "spdx-json":
        sbom = parse_spdx_json(json.loads(text))
    elif fmt == "spdx-tag":
        sbom = parse_spdx_tag_value(text)
    elif fmt == "xml":
        raise SbomError(
            "XML SBOMs are not supported. Convert to JSON first, e.g. "
            "`cyclonedx convert --input-file bom.xml --output-format json`."
        )
    else:
        raise SbomError(
            "unrecognised SBOM format. Expected CycloneDX JSON, SPDX JSON, or "
            "SPDX tag-value."
        )

    sbom.path = str(file_path)
    return sbom


def to_jobs(sbom: Sbom) -> list[tuple[str, str, str, str]]:
    """Checkable components as (name, version, ecosystem, location) tuples,
    matching what coldlight_vulnintel.scan_components expects."""
    location = sbom.path or "SBOM"
    return [
        (c.name, c.version, c.ecosystem, location)
        for c in sbom.checkable
    ]


def inventory_report(sbom: Sbom, *, show_skips: bool = True) -> str:
    """Human-readable summary of what the SBOM contains.

    `show_skips=False` omits the NOT CHECKED block for callers that print the
    full scan report afterwards, which carries the same warning.
    """
    out: list[str] = []
    out.append(f"SBOM            : {sbom.label}")
    if sbom.document_name:
        out.append(f"describes       : {sbom.document_name}")
    out.append(f"components      : {len(sbom.components)}")
    out.append(f"  checkable     : {len(sbom.checkable)}")
    out.append(f"  not checkable : {len(sbom.skipped)}")

    ecosystems: dict[str, int] = {}
    for comp in sbom.checkable:
        ecosystems[comp.ecosystem] = ecosystems.get(comp.ecosystem, 0) + 1
    if ecosystems:
        ordered = sorted(ecosystems.items(), key=lambda kv: -kv[1])
        out.append("  by ecosystem  : "
                   + ", ".join(f"{k}={v}" for k, v in ordered))

    skips = sbom.skip_summary() if show_skips else {}
    if skips:
        out.append("")
        out.append("NOT CHECKED (these were not assessed -- treat as unknown, "
                   "not as clean):")
        for reason, count in skips.items():
            out.append(f"  {count:>5}  {reason}")

    return "\n".join(out)
