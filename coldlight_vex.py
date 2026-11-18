#!/usr/bin/env python3
"""
ColdLight VEX: turn scan findings into a Vulnerability Exploitability eXchange
document, so you can tell downstream consumers (or answer a supplier) which
vulnerabilities actually affect a product.

THE CENTRAL POINT: a scanner cannot produce VEX on its own. "Is this
exploitable in your build?" is a human judgement about reachability,
configuration and mitigations. So this module is deliberately two-step:

    coldlight vex init   -> a triage file with every finding `under_investigation`
    (a human records the decisions, with justifications)
    coldlight vex emit   -> OpenVEX / CycloneDX VEX / CSAF 2.0

`under_investigation` is an honest, conformant starting state. Asserting
`not_affected` without having checked would be worse than publishing nothing.

Emitters refuse to produce non-conformant output: `not_affected` without a
justification or impact statement, and `affected` without an action statement,
are errors -- consumers reject such documents, and a VEX nobody can consume is
worse than no VEX at all.

Formats, and why their vocabularies differ: OpenVEX and CSAF share the VEX
core status/justification vocabulary; CycloneDX uses its own analysis states
and justification labels. This module keeps ONE canonical model and maps it
outward, so a decision recorded once is expressed correctly in all three.

Stdlib only. Read-only: writes documents, touches nothing else.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from coldlight_config import __version__ as GENERATOR_VERSION

TRIAGE_VERSION = "1"
GENERATOR_NAME = "ColdLight"

OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"
CYCLONEDX_SPEC = "1.5"
CSAF_VERSION = "2.0"


# ---------------------------------------------------------------------------
# Canonical VEX vocabulary (the OpenVEX / CSAF core)
# ---------------------------------------------------------------------------

STATUS_NOT_AFFECTED = "not_affected"
STATUS_AFFECTED = "affected"
STATUS_FIXED = "fixed"
STATUS_UNDER_INVESTIGATION = "under_investigation"

STATUSES = (
    STATUS_NOT_AFFECTED,
    STATUS_AFFECTED,
    STATUS_FIXED,
    STATUS_UNDER_INVESTIGATION,
)

# The five standard not_affected justifications. CSAF adopted these verbatim
# as flag labels; CycloneDX uses different wording (see CDX_JUSTIFICATION).
JUSTIFICATIONS = (
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
)

# canonical status -> CycloneDX `analysis.state`
CDX_STATE = {
    STATUS_AFFECTED: "exploitable",
    STATUS_NOT_AFFECTED: "not_affected",
    STATUS_FIXED: "resolved",
    STATUS_UNDER_INVESTIGATION: "in_triage",
}

# canonical justification -> CycloneDX `analysis.justification`
CDX_JUSTIFICATION = {
    "component_not_present": "code_not_present",
    "vulnerable_code_not_present": "code_not_present",
    "vulnerable_code_not_in_execute_path": "code_not_reachable",
    "vulnerable_code_cannot_be_controlled_by_adversary": "requires_configuration",
    "inline_mitigations_already_exist": "protected_by_mitigating_control",
}

# canonical status -> CSAF product_status bucket
CSAF_STATUS = {
    STATUS_AFFECTED: "known_affected",
    STATUS_NOT_AFFECTED: "known_not_affected",
    STATUS_FIXED: "fixed",
    STATUS_UNDER_INVESTIGATION: "under_investigation",
}


class VexError(ValueError):
    """The triage document is not usable."""


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-") or "product"


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------

@dataclass
class Product:
    name: str = ""
    version: str = ""
    purl: str = ""

    @property
    def label(self) -> str:
        return f"{self.name} {self.version}".strip() or "unnamed product"

    @property
    def identifier(self) -> str:
        """A stable identifier for the product.

        OpenVEX wants an IRI-ish product id. If no purl was supplied we
        synthesise a `pkg:generic/...` one rather than emitting a bare name,
        which consumers cannot match on.
        """
        if self.purl:
            return self.purl
        base = f"pkg:generic/{_slug(self.name)}"
        return f"{base}@{self.version}" if self.version else base


@dataclass
class Statement:
    vulnerability: str                                   # CVE-... / GHSA-...
    components: list[str] = field(default_factory=list)  # purls or name@version
    status: str = STATUS_UNDER_INVESTIGATION
    justification: str = ""        # only meaningful for not_affected
    impact_statement: str = ""     # free text alternative to a justification
    action_statement: str = ""     # required when status is affected
    description: str = ""
    aliases: list[str] = field(default_factory=list)
    fix_versions: list[str] = field(default_factory=list)
    severity: str = ""
    known_exploited: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class VexDocument:
    product: Product = field(default_factory=Product)
    author: str = ""
    document_id: str = ""
    document_version: int = 1
    timestamp: str = ""
    statements: list[Statement] = field(default_factory=list)
    # Where the findings came from, for provenance in the emitted document.
    source_label: str = ""

    def to_dict(self) -> dict:
        return {
            "coldlight_vex_version": TRIAGE_VERSION,
            "product": asdict(self.product),
            "author": self.author,
            "document_id": self.document_id,
            "document_version": self.document_version,
            "timestamp": self.timestamp,
            "source_label": self.source_label,
            "statements": [s.to_dict() for s in self.statements],
        }

    def status_counts(self) -> dict[str, int]:
        counts = {s: 0 for s in STATUSES}
        for statement in self.statements:
            counts[statement.status] = counts.get(statement.status, 0) + 1
        return {k: v for k, v in counts.items() if v}


# ---------------------------------------------------------------------------
# Build a triage document from a scan
# ---------------------------------------------------------------------------

def from_scan(findings, *, product: Product, author: str = "",
              source_label: str = "", document_id: str = "",
              timestamp: str = "") -> VexDocument:
    """Build a triage document with every vulnerability under investigation.

    Findings for the same vulnerability are merged into one statement listing
    every affected component -- that's how VEX models it, and it's also how a
    human wants to triage it.
    """
    doc = VexDocument(
        product=product,
        author=author or "unspecified",
        document_id=document_id or f"coldlight-vex-{uuid.uuid4()}",
        timestamp=timestamp or _now(),
        source_label=source_label,
    )

    merged: dict[str, Statement] = {}
    order: list[str] = []

    for finding in findings:
        vuln_id = getattr(finding, "identifier", "") or ""
        if not vuln_id:
            continue

        component = _component_ref(finding)

        if vuln_id not in merged:
            merged[vuln_id] = Statement(
                vulnerability=vuln_id,
                components=[component] if component else [],
                status=STATUS_UNDER_INVESTIGATION,
                description=getattr(finding, "summary", "") or "",
                aliases=list(getattr(finding, "aliases", []) or []),
                fix_versions=list(getattr(finding, "fixed_versions", []) or []),
                severity=(getattr(finding, "severity", "") or "").upper(),
                known_exploited=bool(getattr(finding, "kev", False)),
            )
            order.append(vuln_id)
        else:
            statement = merged[vuln_id]
            if component and component not in statement.components:
                statement.components.append(component)
            for version in getattr(finding, "fixed_versions", []) or []:
                if version not in statement.fix_versions:
                    statement.fix_versions.append(version)
            if getattr(finding, "kev", False):
                statement.known_exploited = True

    # KEV first, then severity -- triage the exploited ones first.
    severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "MODERATE": 2,
                     "LOW": 1, "UNKNOWN": 0, "": 0}
    doc.statements = sorted(
        (merged[v] for v in order),
        key=lambda s: (0 if s.known_exploited else 1,
                       -severity_rank.get(s.severity, 0),
                       s.vulnerability),
    )
    return doc


def _component_ref(finding) -> str:
    """Prefer a purl-ish reference; fall back to name@version."""
    package = getattr(finding, "package", "") or ""
    version = getattr(finding, "installed_version", "") or ""
    ecosystem = getattr(finding, "ecosystem", "") or ""
    if not package:
        return ""

    purl_type = _PURL_TYPE_FOR.get(ecosystem)
    if purl_type and version:
        if purl_type == "maven" and ":" in package:
            group, _, artifact = package.partition(":")
            return f"pkg:maven/{group}/{artifact}@{version}"
        return f"pkg:{purl_type}/{package}@{version}"
    return f"{package}@{version}" if version else package


# OSV ecosystem -> purl type, for rebuilding component references.
_PURL_TYPE_FOR = {
    "PyPI": "pypi",
    "npm": "npm",
    "Go": "golang",
    "crates.io": "cargo",
    "Maven": "maven",
    "NuGet": "nuget",
    "RubyGems": "gem",
    "Packagist": "composer",
    "Hex": "hex",
    "Pub": "pub",
    "ConanCenter": "conan",
    "CRAN": "cran",
    "Hackage": "hackage",
}


# ---------------------------------------------------------------------------
# Validation -- refuse to emit non-conformant VEX
# ---------------------------------------------------------------------------

def validate(doc: VexDocument) -> tuple[list[str], list[str]]:
    """Return (errors, warnings). Errors must block emission."""
    errors: list[str] = []
    warnings: list[str] = []

    if not doc.product.name:
        errors.append("product.name is empty -- a VEX statement must say what "
                      "product it is about")
    if not doc.product.purl:
        warnings.append("product.purl is empty; a synthesised "
                        "pkg:generic/... identifier will be used, which "
                        "consumers cannot match against a real artifact")
    if not doc.author or doc.author == "unspecified":
        warnings.append("author is unset -- VEX consumers use it to decide "
                        "whether to trust the assertion")
    if not doc.statements:
        warnings.append("no statements: the document asserts nothing")

    seen: set[str] = set()
    for index, statement in enumerate(doc.statements):
        where = f"statement {index + 1} ({statement.vulnerability or 'no id'})"

        if not statement.vulnerability:
            errors.append(f"{where}: vulnerability id is empty")
        elif statement.vulnerability in seen:
            errors.append(f"{where}: duplicate statement for this "
                          f"vulnerability -- merge them")
        else:
            seen.add(statement.vulnerability)

        if not statement.components:
            errors.append(f"{where}: no components listed")

        if statement.status not in STATUSES:
            errors.append(f"{where}: status {statement.status!r} is not one of "
                          f"{', '.join(STATUSES)}")
            continue

        if statement.justification and statement.justification not in JUSTIFICATIONS:
            errors.append(
                f"{where}: justification {statement.justification!r} is not a "
                f"standard VEX justification ({', '.join(JUSTIFICATIONS)})"
            )

        if statement.status == STATUS_NOT_AFFECTED:
            if not statement.justification and not statement.impact_statement:
                errors.append(
                    f"{where}: 'not_affected' requires either a justification "
                    f"or an impact_statement. Consumers reject a bare "
                    f"'not_affected'."
                )
        elif statement.justification:
            warnings.append(
                f"{where}: justification is only meaningful for "
                f"'not_affected'; it will be dropped for "
                f"'{statement.status}'"
            )

        if statement.status == STATUS_AFFECTED and not statement.action_statement:
            errors.append(
                f"{where}: 'affected' requires an action_statement saying what "
                f"a consumer should do"
            )

        if statement.status == STATUS_FIXED and not statement.fix_versions:
            warnings.append(f"{where}: 'fixed' with no fix_versions recorded")

        if statement.known_exploited and statement.status == STATUS_UNDER_INVESTIGATION:
            warnings.append(
                f"{where}: known-exploited (CISA KEV) and still under "
                f"investigation -- triage this first"
            )

    return errors, warnings


def require_valid(doc: VexDocument) -> None:
    errors, _ = validate(doc)
    if errors:
        raise VexError(
            "cannot emit non-conformant VEX:\n  - " + "\n  - ".join(errors)
        )


# ---------------------------------------------------------------------------
# Triage file I/O
# ---------------------------------------------------------------------------

def save_triage(doc: VexDocument, path: str | Path) -> None:
    Path(path).write_text(json.dumps(doc.to_dict(), indent=2) + "\n",
                          encoding="utf-8")


def load_triage(path: str | Path) -> VexDocument:
    file_path = Path(path)
    if not file_path.is_file():
        raise VexError(f"no such triage file: {file_path}")
    try:
        data = json.loads(file_path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise VexError(f"{file_path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise VexError(f"{file_path}: expected a JSON object")
    return from_dict(data)


def from_dict(data: dict) -> VexDocument:
    product_data = data.get("product") or {}
    doc = VexDocument(
        product=Product(
            name=str(product_data.get("name", "") or ""),
            version=str(product_data.get("version", "") or ""),
            purl=str(product_data.get("purl", "") or ""),
        ),
        author=str(data.get("author", "") or ""),
        document_id=str(data.get("document_id", "") or ""),
        document_version=int(data.get("document_version", 1) or 1),
        timestamp=str(data.get("timestamp", "") or ""),
        source_label=str(data.get("source_label", "") or ""),
    )
    for entry in data.get("statements") or []:
        if not isinstance(entry, dict):
            continue
        doc.statements.append(Statement(
            vulnerability=str(entry.get("vulnerability", "") or ""),
            components=[str(c) for c in (entry.get("components") or [])],
            status=str(entry.get("status", STATUS_UNDER_INVESTIGATION) or ""),
            justification=str(entry.get("justification", "") or ""),
            impact_statement=str(entry.get("impact_statement", "") or ""),
            action_statement=str(entry.get("action_statement", "") or ""),
            description=str(entry.get("description", "") or ""),
            aliases=[str(a) for a in (entry.get("aliases") or [])],
            fix_versions=[str(v) for v in (entry.get("fix_versions") or [])],
            severity=str(entry.get("severity", "") or "").upper(),
            known_exploited=bool(entry.get("known_exploited", False)),
        ))
    return doc


# ---------------------------------------------------------------------------
# OpenVEX
# ---------------------------------------------------------------------------

def to_openvex(doc: VexDocument) -> dict:
    """OpenVEX v0.2.0 (https://openvex.dev)."""
    require_valid(doc)

    statements = []
    for statement in doc.statements:
        vulnerability: dict = {"name": statement.vulnerability}
        if statement.aliases:
            vulnerability["aliases"] = statement.aliases
        if statement.description:
            vulnerability["description"] = statement.description

        product: dict = {"@id": doc.product.identifier}
        if statement.components:
            product["subcomponents"] = [{"@id": c} for c in statement.components]

        entry: dict = {
            "vulnerability": vulnerability,
            "products": [product],
            "status": statement.status,
        }
        # Justification applies only to not_affected, per the spec.
        if statement.status == STATUS_NOT_AFFECTED:
            if statement.justification:
                entry["justification"] = statement.justification
            if statement.impact_statement:
                entry["impact_statement"] = statement.impact_statement
        if statement.status == STATUS_AFFECTED and statement.action_statement:
            entry["action_statement"] = statement.action_statement

        statements.append(entry)

    return {
        "@context": OPENVEX_CONTEXT,
        "@id": f"https://openvex.dev/docs/{doc.document_id}",
        "author": doc.author,
        "role": "document creator",
        "timestamp": doc.timestamp or _now(),
        "version": doc.document_version,
        "tooling": f"{GENERATOR_NAME} {GENERATOR_VERSION}",
        "statements": statements,
    }


# ---------------------------------------------------------------------------
# CycloneDX VEX
# ---------------------------------------------------------------------------

def to_cyclonedx_vex(doc: VexDocument) -> dict:
    """CycloneDX 1.5 BOM carrying a `vulnerabilities` array.

    The referenced components are included in `components` with bom-refs, so
    each `affects[].ref` resolves inside the document rather than dangling.
    """
    require_valid(doc)

    seen_refs: set[str] = set()
    components = []
    for statement in doc.statements:
        for ref in statement.components:
            if ref in seen_refs:
                continue
            seen_refs.add(ref)
            components.append(_cdx_component(ref))

    vulnerabilities = []
    for statement in doc.statements:
        analysis: dict = {"state": CDX_STATE[statement.status]}
        if statement.status == STATUS_NOT_AFFECTED and statement.justification:
            mapped = CDX_JUSTIFICATION.get(statement.justification)
            if mapped:
                analysis["justification"] = mapped
        detail_parts = [p for p in (statement.impact_statement,
                                    statement.action_statement) if p]
        if detail_parts:
            analysis["detail"] = " ".join(detail_parts)
        if statement.status == STATUS_AFFECTED:
            analysis["response"] = ["update"] if statement.fix_versions else [
                "workaround_available"
            ]

        entry: dict = {
            "id": statement.vulnerability,
            "analysis": analysis,
        }
        if statement.vulnerability.upper().startswith("CVE-"):
            entry["source"] = {
                "name": "NVD",
                "url": ("https://nvd.nist.gov/vuln/detail/"
                        f"{statement.vulnerability}"),
            }
        if statement.description:
            entry["description"] = statement.description
        if statement.severity:
            entry["ratings"] = [{"severity": _cdx_severity(statement.severity)}]
        if statement.fix_versions:
            entry["recommendation"] = ("Upgrade to "
                                       + ", ".join(statement.fix_versions))
        if statement.components:
            entry["affects"] = [{"ref": c} for c in statement.components]
        vulnerabilities.append(entry)

    metadata: dict = {
        "timestamp": doc.timestamp or _now(),
        "tools": {"components": [{
            "type": "application",
            "name": GENERATOR_NAME,
            "version": GENERATOR_VERSION,
        }]},
        "component": {
            "type": "application",
            "bom-ref": doc.product.identifier,
            "name": doc.product.name,
        },
    }
    if doc.product.version:
        metadata["component"]["version"] = doc.product.version
    if doc.product.purl:
        metadata["component"]["purl"] = doc.product.purl
    if doc.author:
        metadata["authors"] = [{"name": doc.author}]

    return {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC,
        "serialNumber": f"urn:uuid:{_uuid_from(doc.document_id)}",
        "version": doc.document_version,
        "metadata": metadata,
        "components": components,
        "vulnerabilities": vulnerabilities,
    }


def _cdx_component(ref: str) -> dict:
    """A CycloneDX component entry for a component reference.

    The bom-ref is the reference itself so `affects[].ref` resolves. The name
    is taken from the purl where possible -- a name of "pkg:pypi/jinja2" would
    be a valid BOM but an ugly and unhelpful one.
    """
    entry: dict = {"type": "library", "bom-ref": ref}

    purl = None
    if ref.startswith("pkg:"):
        try:
            from coldlight_sbom import parse_purl
            purl = parse_purl(ref)
        except Exception:  # noqa: BLE001 - name extraction is best-effort
            purl = None

    if purl is not None:
        entry["name"] = purl.name
        if purl.namespace:
            # CycloneDX models a Maven groupId / npm scope as `group`.
            entry["group"] = purl.namespace
        if purl.version:
            entry["version"] = purl.version
        entry["purl"] = ref
        return entry

    name, _, version = ref.rpartition("@")
    entry["name"] = name or ref
    if name and version:
        entry["version"] = version
    if ref.startswith("pkg:"):
        entry["purl"] = ref
    return entry


_CDX_SEVERITY = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "MODERATE": "medium",
    "LOW": "low",
    "UNKNOWN": "unknown",
}


def _cdx_severity(severity: str) -> str:
    return _CDX_SEVERITY.get((severity or "").upper(), "unknown")


def _uuid_from(text: str) -> str:
    """A stable UUID for a document id, so re-emitting is reproducible."""
    try:
        # Reuse an embedded UUID when the id already carries one.
        return str(uuid.UUID(text.split("coldlight-vex-")[-1]))
    except (ValueError, IndexError):
        return str(uuid.uuid5(uuid.NAMESPACE_URL, text or "coldlight-vex"))


# ---------------------------------------------------------------------------
# CSAF 2.0 (VEX profile)
# ---------------------------------------------------------------------------

def to_csaf(doc: VexDocument, *, publisher_category: str = "vendor",
            publisher_namespace: str = "https://coldlight.invalid") -> dict:
    """CSAF 2.0 document with `category: csaf_vex`.

    The product tree models each component as a product related to the
    overall product via `default_component_of`, which is how CSAF expresses
    "this library, as shipped inside this product". Statements then reference
    the resulting relationship product id -- the correct granularity for VEX.
    """
    require_valid(doc)

    product_id = "CSAFPID-0001"
    full_product_names = [{
        "product_id": product_id,
        "name": doc.product.label,
    }]
    if doc.product.purl:
        full_product_names[0]["product_identification_helper"] = {
            "purl": doc.product.purl
        }

    relationships = []
    component_product_ids: dict[str, str] = {}

    for ref in _ordered_components(doc):
        index = len(component_product_ids) + 1
        comp_id = f"CSAFPID-C{index:04d}"
        rel_id = f"CSAFPID-R{index:04d}"

        comp_entry: dict = {"product_id": comp_id, "name": ref}
        if ref.startswith("pkg:"):
            comp_entry["product_identification_helper"] = {"purl": ref}
        full_product_names.append(comp_entry)

        relationships.append({
            "category": "default_component_of",
            "product_reference": comp_id,
            "relates_to_product_reference": product_id,
            "full_product_name": {
                "product_id": rel_id,
                "name": f"{ref} as a component of {doc.product.label}",
            },
        })
        component_product_ids[ref] = rel_id

    vulnerabilities = []
    for statement in doc.statements:
        ids = [component_product_ids[c] for c in statement.components
               if c in component_product_ids]
        bucket = CSAF_STATUS[statement.status]

        entry: dict = {"product_status": {bucket: ids}}
        if statement.vulnerability.upper().startswith("CVE-"):
            entry["cve"] = statement.vulnerability
        else:
            entry["ids"] = [{"system_name": "OSV", "text": statement.vulnerability}]
        if statement.description:
            entry["notes"] = [{
                "category": "description",
                "text": statement.description,
                "title": "Vulnerability description",
            }]

        # CSAF requires a machine-readable flag or a human-readable threat to
        # back a known_not_affected assertion.
        if statement.status == STATUS_NOT_AFFECTED:
            if statement.justification:
                entry["flags"] = [{
                    "label": statement.justification,
                    "product_ids": ids,
                }]
            if statement.impact_statement:
                entry.setdefault("threats", []).append({
                    "category": "impact",
                    "details": statement.impact_statement,
                    "product_ids": ids,
                })
        elif statement.status == STATUS_AFFECTED:
            entry["remediations"] = [{
                "category": "vendor_fix" if statement.fix_versions else "workaround",
                "details": statement.action_statement,
                "product_ids": ids,
            }]
        elif statement.status == STATUS_FIXED and statement.fix_versions:
            entry["remediations"] = [{
                "category": "vendor_fix",
                "details": "Fixed in " + ", ".join(statement.fix_versions),
                "product_ids": ids,
            }]

        vulnerabilities.append(entry)

    timestamp = doc.timestamp or _now()
    return {
        "document": {
            "category": "csaf_vex",
            "csaf_version": CSAF_VERSION,
            "title": f"VEX for {doc.product.label}",
            "publisher": {
                "category": publisher_category,
                "name": doc.author or "unspecified",
                "namespace": publisher_namespace,
            },
            "tracking": {
                "id": doc.document_id,
                "status": "final",
                "version": str(doc.document_version),
                "initial_release_date": timestamp,
                "current_release_date": timestamp,
                "revision_history": [{
                    "number": str(doc.document_version),
                    "date": timestamp,
                    "summary": "Generated from ColdLight scan findings",
                }],
                "generator": {
                    "engine": {
                        "name": GENERATOR_NAME,
                        "version": GENERATOR_VERSION,
                    },
                },
            },
        },
        "product_tree": {
            "full_product_names": full_product_names,
            **({"relationships": relationships} if relationships else {}),
        },
        "vulnerabilities": vulnerabilities,
    }


def _ordered_components(doc: VexDocument) -> list[str]:
    """Every distinct component, in first-seen order."""
    seen: list[str] = []
    for statement in doc.statements:
        for ref in statement.components:
            if ref not in seen:
                seen.append(ref)
    return seen


# ---------------------------------------------------------------------------
# Emission
# ---------------------------------------------------------------------------

FORMATS = ("openvex", "cyclonedx", "csaf")


def emit(doc: VexDocument, fmt: str) -> dict:
    key = (fmt or "").strip().lower()
    if key == "openvex":
        return to_openvex(doc)
    if key in ("cyclonedx", "cdx", "cyclonedx-vex"):
        return to_cyclonedx_vex(doc)
    if key == "csaf":
        return to_csaf(doc)
    raise VexError(f"unknown VEX format {fmt!r}; expected one of "
                   f"{', '.join(FORMATS)}")


def text_summary(doc: VexDocument) -> str:
    out: list[str] = []
    out.append(f"product    : {doc.product.label}")
    out.append(f"identifier : {doc.product.identifier}")
    out.append(f"author     : {doc.author or '(unset)'}")
    out.append(f"document   : {doc.document_id} v{doc.document_version}")
    if doc.source_label:
        out.append(f"findings   : {doc.source_label}")
    out.append(f"statements : {len(doc.statements)}")

    counts = doc.status_counts()
    if counts:
        out.append("  by status: "
                   + ", ".join(f"{k}={v}" for k, v in counts.items()))

    kev = [s for s in doc.statements if s.known_exploited]
    if kev:
        out.append(f"  known-exploited (triage first): {len(kev)}")

    pending = [s for s in doc.statements
               if s.status == STATUS_UNDER_INVESTIGATION]
    if pending:
        out.append("")
        out.append(f"{len(pending)} statement(s) still under investigation. "
                   f"VEX is a human assertion:")
        out.append("  edit the triage file, then re-run `coldlight vex emit`.")
        out.append("  not_affected -> needs a justification, one of:")
        for justification in JUSTIFICATIONS:
            out.append(f"      {justification}")
        out.append("  affected     -> needs an action_statement")

    return "\n".join(out)
