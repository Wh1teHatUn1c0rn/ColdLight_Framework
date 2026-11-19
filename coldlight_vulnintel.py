#!/usr/bin/env python3
"""
ColdLight vulnerability intelligence: pull KNOWN vulnerabilities for software and
dependencies from official, authoritative feeds.

Sources (all public, free, documented APIs -- no scraping, no API key required):
  * NVD 2.0   (NIST / MITRE CVE)  -- CVE records, CVSS scores, CWE classes
  * OSV.dev   (Google)            -- open-source dependency advisories
  * CISA KEV                      -- CVEs KNOWN to be exploited in the wild

SCOPE BOUNDARY: this module IDENTIFIES and REPORTS vulnerabilities so they can
be prioritised and fixed. It does not fetch, generate, or run exploit code.
Exploit-DB appears only as reference *links* already carried in the upstream
advisory records -- ColdLight never downloads or executes an exploit body.

Stdlib only. If `certifi` happens to be installed it is used for a current CA
bundle, because some systems carry an expired cross-signed root that breaks
verification against NVD. TLS verification is always ON -- there is
deliberately no switch to turn it off.
"""

from __future__ import annotations

import json
import os
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path

from coldlight_trust import ca_bundle, ssl_context  # noqa: F401 (re-export)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Generic client identifier. Deliberately carries no operator or org identity.
USER_AGENT = "ColdLight-VulnIntel/1.0"

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_API = "https://api.osv.dev/v1/query"
KEV_FEED = ("https://www.cisa.gov/sites/default/files/feeds/"
            "known_exploited_vulnerabilities.json")

EXPLOITDB_HOST = "exploit-db.com"

DEFAULT_TIMEOUT = 25
CACHE_TTL_HOURS = 24
MAX_ENRICH_LOOKUPS = 25  # cap NVD round-trips so a big scan can't hang for hours

SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MODERATE": 2,
    "MEDIUM": 2,
    "LOW": 1,
    "UNKNOWN": 0,
    "": 0,
}

# ---------------------------------------------------------------------------
# Severity provenance
# ---------------------------------------------------------------------------
# Severities in this framework come from several different kinds of authority,
# and a report that prints "4 critical" without saying which is which invites
# the reader to treat our opinion as a measurement. These values record where
# each severity actually came from.
#
# coldlight_codescan, coldlight_mail and coldlight_ioc set their own values as
# literals rather than importing this module; a test asserts those literals are
# members of this set, so the two cannot drift apart.

SEV_SRC_NVD = "nvd-cvss"          # NIST CVSS base severity -- measured
SEV_SRC_OSV = "osv-database"      # the advisory database's own rating (e.g. GHSA)
SEV_SRC_KEV = "cisa-kev"          # raised by us because CISA lists it exploited
SEV_SRC_RULE = "coldlight-rule"      # our code-scanner rule table -- our judgement
SEV_SRC_JUDGEMENT = "coldlight-judgement"   # our assessment (email, awareness)
# A third-party indicator pack's own tier, mapped onto our severity words by
# coldlight_ioc. Deliberately distinct from SEV_SRC_JUDGEMENT because we did
# not make the call: the pack author graded the indicator and is named in the
# finding. A reader who distrusts that author has to be able to see which
# severities came from them.
SEV_SRC_PACK = "indicator-pack"
SEV_SRC_UNSCORED = "unscored"     # no authority supplied a severity

SEVERITY_SOURCES = (SEV_SRC_NVD, SEV_SRC_OSV, SEV_SRC_KEV, SEV_SRC_RULE,
                    SEV_SRC_JUDGEMENT, SEV_SRC_PACK, SEV_SRC_UNSCORED)

# Which sources are an external measurement rather than a ColdLight opinion.
# SEV_SRC_PACK is deliberately absent: a pack's tier is someone else's
# judgement, which is neither our opinion nor a measurement. Counting it as
# measured would let an unverified third-party grade be reported with the
# authority of a CVSS score.
MEASURED_SOURCES = frozenset({SEV_SRC_NVD, SEV_SRC_OSV})

SEVERITY_SOURCE_LABELS = {
    SEV_SRC_NVD: "NVD CVSS base score",
    SEV_SRC_OSV: "advisory database rating",
    SEV_SRC_KEV: "raised by ColdLight: listed in CISA KEV",
    SEV_SRC_RULE: "ColdLight rule table",
    SEV_SRC_JUDGEMENT: "ColdLight assessment",
    SEV_SRC_PACK: "indicator pack's own tier",
    SEV_SRC_UNSCORED: "no severity published",
}


def is_measured(source: str) -> bool:
    """True when the severity came from an external authority, not from us."""
    return (source or "") in MEASURED_SOURCES


class VulnIntelError(RuntimeError):
    """Network/API problem talking to an upstream feed."""


# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """One known vulnerability affecting one thing we found."""

    identifier: str                                   # CVE-2021-44228 / GHSA-xxxx
    source: str = "osv"                               # osv | nvd
    severity: str = "UNKNOWN"
    # Where `severity` came from -- see SEVERITY_SOURCES. Without this, a
    # NIST CVSS 9.8 and our own opinion look identical in a report.
    severity_source: str = SEV_SRC_UNSCORED
    cvss_score: float | None = None
    cvss_vector: str = ""
    cwe: str = ""
    cwe_name: str = ""              # resolved from the bundled CWE catalogue
    summary: str = ""
    # The full advisory writeup. `summary` stays a one-line headline; this is
    # the technical detail -- what the flaw is and often how it was fixed --
    # which was previously truncated to 400 characters and thrown away.
    details: str = ""
    package: str = ""
    ecosystem: str = ""
    installed_version: str = ""
    fixed_versions: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    # References grouped by what they ARE: {"patch": [...], "exploit": [...]}.
    # NVD tags each reference ("Patch", "Exploit", "Vendor Advisory") and OSV
    # types them ("FIX", "ADVISORY", "REPORT"). Flattening both into a bare URL
    # list -- as this did -- made the commit that fixes the issue
    # indistinguishable from a blog post.
    reference_kinds: dict[str, list[str]] = field(default_factory=dict)
    exploitdb_refs: list[str] = field(default_factory=list)
    # Exploitation intelligence, attached by coldlight_exploitintel.
    epss_score: float | None = None
    epss_percentile: float | None = None
    exploits: list[dict] = field(default_factory=list)
    kev: bool = False                                 # in CISA Known Exploited catalog
    kev_due_date: str = ""
    ransomware: bool = False
    published: str = ""
    location: str = ""                                # manifest the package came from

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def rank(self) -> tuple:
        """Sort key: KEV first, then severity, then CVSS, then id."""
        return (
            0 if self.kev else 1,
            -SEVERITY_ORDER.get((self.severity or "").upper(), 0),
            -(self.cvss_score or 0.0),
            self.identifier,
        )


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: f.rank)


# ---------------------------------------------------------------------------
# Reference classification
# ---------------------------------------------------------------------------

KIND_PATCH = "patch"                 # the database said so
KIND_PATCH_LIKELY = "patch_likely"   # inferred from the URL, not asserted
KIND_EXPLOIT = "exploit"
KIND_MITIGATION = "mitigation"
KIND_ADVISORY = "advisory"
KIND_REPORT = "report"
KIND_OTHER = "other"

# Highest-value kind wins when a reference carries several tags.
KIND_PRIORITY = (KIND_PATCH, KIND_PATCH_LIKELY, KIND_EXPLOIT, KIND_MITIGATION,
                 KIND_ADVISORY, KIND_REPORT, KIND_OTHER)

# URL shapes that usually point at the change that fixed the issue. Needed
# because GHSA advisories in OSV only ever use ADVISORY/WEB/PACKAGE -- they
# never emit FIX -- so for Maven, npm and NuGet the explicit label is absent
# and the fix commit would otherwise sit anonymously among 70 "WEB" links.
# Anything matched this way is labelled patch_likely, never patch: it is our
# inference, not the database's statement.
_PATCH_URL_MARKERS = ("/commit/", "/commits/", "/pull/", "/pull-request/",
                      "/merge_requests/", "/releases/tag/", "/compare/",
                      "/changeset/", "/-/commit/", "/patch/")

# These hosts/repos match the shapes above but are NOT the project's fix --
# a pull request against an advisory database is a change to the advisory,
# not to the vulnerable code.
_NOT_A_PROJECT_FIX = (
    "github.com/github/advisory-database",
    "github.com/advisories",
    "github.com/pypa/advisory-database",
    "github.com/golang/vulndb",
    "github.com/rustsec/advisory-db",
    "gitlab.com/gitlab-org/advisories",
    "github.com/CVEProject",
    "github.com/distributedweaknessfiling",
)


def infer_patch_reference(url: str) -> bool:
    """True when a URL looks like the upstream change that fixed the issue."""
    lowered = (url or "").lower()
    if not any(marker in lowered for marker in _PATCH_URL_MARKERS):
        return False
    return not any(repo.lower() in lowered for repo in _NOT_A_PROJECT_FIX)

# OSV reference types -> our kinds. "FIX" is the one that matters most: it is
# the commit or release that resolved the issue.
_OSV_REF_KIND = {
    "FIX": KIND_PATCH,
    "GIT": KIND_PATCH,
    "ADVISORY": KIND_ADVISORY,
    "ARTICLE": KIND_ADVISORY,
    "DETECTION": KIND_REPORT,
    "REPORT": KIND_REPORT,
    "EVIDENCE": KIND_EXPLOIT,
    "WEB": KIND_OTHER,
    "PACKAGE": KIND_OTHER,
    "DISCUSSION": KIND_REPORT,
}


def classify_nvd_tags(tags) -> str:
    """Map NVD's reference tags onto one kind."""
    lowered = {str(t).strip().lower() for t in (tags or [])}
    if "patch" in lowered:
        return KIND_PATCH
    if "exploit" in lowered:
        return KIND_EXPLOIT
    if "mitigation" in lowered:
        return KIND_MITIGATION
    if any("advisory" in tag for tag in lowered):
        return KIND_ADVISORY
    if {"issue tracking", "mailing list", "vdb entry"} & lowered:
        return KIND_REPORT
    return KIND_OTHER


def classify_osv_type(reference_type: str) -> str:
    return _OSV_REF_KIND.get((reference_type or "").strip().upper(), KIND_OTHER)


def _group_references(pairs) -> dict[str, list[str]]:
    """pairs: iterable of (url, kind). Returns kinds in priority order.

    A reference the database left unlabelled is promoted to patch_likely when
    its URL has the shape of an upstream fix -- never to patch, which is
    reserved for what the database actually stated.
    """
    grouped: dict[str, list[str]] = {}
    for url, kind in pairs:
        if not url:
            continue
        kind = kind or KIND_OTHER
        if kind in (KIND_OTHER, KIND_REPORT) and infer_patch_reference(url):
            kind = KIND_PATCH_LIKELY
        bucket = grouped.setdefault(kind, [])
        if url not in bucket:
            bucket.append(url)
    return {k: grouped[k] for k in KIND_PRIORITY if k in grouped}


def _merge_reference_kinds(target: dict[str, list[str]],
                           incoming: dict[str, list[str]]) -> dict[str, list[str]]:
    combined = {k: list(v) for k, v in (target or {}).items()}
    for kind, urls in (incoming or {}).items():
        bucket = combined.setdefault(kind, [])
        for url in urls:
            if url not in bucket:
                bucket.append(url)
    return {k: combined[k] for k in KIND_PRIORITY if k in combined}


def _cwe_name(cwe: str) -> str:
    """Resolve a CWE id to its MITRE name, if we have it bundled."""
    if not cwe:
        return ""
    try:
        from coldlight_cwe import describe
        weakness = describe(cwe)
        return weakness.name if weakness else ""
    except Exception:  # noqa: BLE001 - enrichment must never break a scan
        return ""


def merge_findings(findings: list[Finding]) -> list[Finding]:
    """Collapse records describing the same vulnerability in the same package.

    OSV routinely returns SEVERAL advisories for one CVE -- a GHSA record and
    a PYSEC record, say. Both carry the same CVE alias, so both normalise to
    the same identifier. Without merging, every such CVE is counted twice and
    the thinner record (often with no severity at all) sits alongside the
    richer one, inflating counts and manufacturing an "unknown severity"
    bucket out of nothing.

    Merging keeps the best of each: the highest severity, any CVSS score, and
    the union of aliases, fixes and references.
    """
    merged: dict[tuple, Finding] = {}
    order: list[tuple] = []

    for finding in findings:
        key = (
            finding.identifier.upper(),
            finding.ecosystem,
            finding.package.lower(),
            finding.installed_version,
        )
        existing = merged.get(key)
        if existing is None:
            merged[key] = finding
            order.append(key)
            continue

        incoming_rank = SEVERITY_ORDER.get((finding.severity or "").upper(), 0)
        existing_rank = SEVERITY_ORDER.get((existing.severity or "").upper(), 0)
        if incoming_rank > existing_rank:
            existing.severity = finding.severity
            existing.severity_source = finding.severity_source

        if existing.cvss_score is None and finding.cvss_score is not None:
            existing.cvss_score = finding.cvss_score
        if not existing.cvss_vector:
            existing.cvss_vector = finding.cvss_vector
        if not existing.cwe:
            existing.cwe = finding.cwe
            existing.cwe_name = finding.cwe_name
        if not existing.cwe_name:
            existing.cwe_name = _cwe_name(existing.cwe)
        if not existing.published:
            existing.published = finding.published
        existing.kev = existing.kev or finding.kev

        # Keep the FULLER writeup: unlike the one-line summary, more detail is
        # better here, and the two databases often describe the same issue at
        # different lengths.
        if len(finding.details or "") > len(existing.details or ""):
            existing.details = finding.details

        existing.reference_kinds = _merge_reference_kinds(
            existing.reference_kinds, finding.reference_kinds)

        if existing.epss_score is None and finding.epss_score is not None:
            existing.epss_score = finding.epss_score
            existing.epss_percentile = finding.epss_percentile
        for exploit in finding.exploits:
            if exploit not in existing.exploits:
                existing.exploits.append(exploit)

        # OSV's `summary` is a one-liner and `details` a long blob, so the
        # shorter non-empty text is the better headline. Deterministic.
        if finding.summary and (
            not existing.summary or len(finding.summary) < len(existing.summary)
        ):
            existing.summary = finding.summary

        for attribute in ("aliases", "fixed_versions", "references",
                          "exploitdb_refs"):
            target = getattr(existing, attribute)
            for item in getattr(finding, attribute):
                if item not in target:
                    target.append(item)

    for key in order:
        merged[key].aliases.sort()
        merged[key].fixed_versions.sort()

    return [merged[key] for key in order]


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

# The trust store lives in `coldlight_trust` so that every module making a
# network call shares it. It used to be implemented here, which quietly made
# it vuln-intel's private property: `coldlight_mail` never imported this module,
# so `mail audit` used the system trust store while these lookups used the
# configured one. `ca_bundle` and `ssl_context` are re-exported because they
# are part of this module's published surface.
#
# Note there is deliberately no `_ssl_ctx` here any more. Leaving a dead copy
# of the cache behind would mean anything resetting it had no effect while
# appearing to -- exactly the failure mode this change removes. Use
# `coldlight_trust.reset()`.


def _http_json(url: str, *, payload: dict | None = None,
               headers: dict | None = None, timeout: int = DEFAULT_TIMEOUT,
               retries: int = 3) -> dict:
    """GET (or POST, if payload given) a JSON document, with polite retries."""
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if data is not None:
        hdrs["Content-Type"] = "application/json"
    if headers:
        hdrs.update(headers)

    last_err: Exception | None = None
    for attempt in range(retries):
        req = urllib.request.Request(url, data=data, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=timeout,
                                        context=ssl_context()) as resp:
                return json.loads(resp.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            last_err = exc
            if exc.code in (429, 503, 504) and attempt < retries - 1:
                time.sleep(2 ** attempt * 2)
                continue
            raise VulnIntelError(
                f"{urllib.parse.urlsplit(url).netloc} returned HTTP {exc.code}"
            ) from exc
        except urllib.error.URLError as exc:
            last_err = exc
            host = urllib.parse.urlsplit(url).netloc
            if isinstance(exc.reason, ssl.SSLCertVerificationError):
                # Retrying will not help a trust-store problem. Say what to do.
                detail = getattr(exc.reason, "verify_message", None) or exc.reason
                raise VulnIntelError(
                    f"TLS verification failed for {host}: {detail}. "
                    "This is usually a stale CA bundle on this machine, not a bad "
                    "server. Point ColdLight at a current one with "
                    "COLDLIGHT_CA_BUNDLE=/path/to/cacert.pem (or `pip install certifi`). "
                    "Do not disable certificate verification."
                ) from exc
            if attempt < retries - 1:
                time.sleep(2 ** attempt)
                continue
            raise VulnIntelError(f"cannot reach {host}: {exc.reason}") from exc
    raise VulnIntelError(str(last_err))


def cache_dir() -> Path:
    base = os.environ.get("COLDLIGHT_CACHE") or (Path.home() / ".coldlight" / "cache")
    path = Path(base)
    path.mkdir(parents=True, exist_ok=True)
    return path


# ---------------------------------------------------------------------------
# CISA KEV -- "is this actually being exploited right now?"
# ---------------------------------------------------------------------------

def load_kev(*, refresh: bool = False, ttl_hours: int = CACHE_TTL_HOURS) -> dict:
    """Fetch the CISA Known Exploited Vulnerabilities catalog (cached)."""
    path = cache_dir() / "cisa_kev.json"
    if path.is_file() and not refresh:
        age = time.time() - path.stat().st_mtime
        if age < ttl_hours * 3600:
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                pass

    data = _http_json(KEV_FEED)
    try:
        path.write_text(json.dumps(data), encoding="utf-8")
    except OSError:
        pass  # cache is an optimisation, not a requirement
    return data


def kev_index(data: dict | None = None) -> dict[str, dict]:
    """Map CVE id -> KEV entry."""
    if data is None:
        data = load_kev()
    out: dict[str, dict] = {}
    for entry in data.get("vulnerabilities", []) or []:
        cve = (entry.get("cveID") or "").upper()
        if cve:
            out[cve] = entry
    return out


def apply_kev(findings: list[Finding], index: dict[str, dict]) -> list[Finding]:
    """Flag findings that appear in the KEV catalog. This is the signal that
    turns a long CVE list into a prioritised one."""
    for f in findings:
        candidates = [f.identifier.upper()] + [a.upper() for a in f.aliases]
        for cid in candidates:
            entry = index.get(cid)
            if entry:
                f.kev = True
                f.kev_due_date = entry.get("dueDate", "") or ""
                f.ransomware = (
                    (entry.get("knownRansomwareCampaignUse") or "").lower() == "known"
                )
                if not f.severity or f.severity == "UNKNOWN":
                    # Our call, not a published rating: nothing scored this,
                    # but CISA confirms it is being exploited. Record that the
                    # severity is ours so it is never read as a CVSS score.
                    f.severity = "CRITICAL"
                    f.severity_source = SEV_SRC_KEV
                break
    return findings


# ---------------------------------------------------------------------------
# NVD (NIST / MITRE CVE)
# ---------------------------------------------------------------------------

_nvd_last_call = 0.0


def nvd_api_key() -> str:
    """Optional. Without a key NVD allows ~5 requests/30s; with one, ~50/30s."""
    return os.environ.get("NVD_API_KEY", "").strip()


def _nvd_throttle() -> None:
    global _nvd_last_call
    min_gap = 0.7 if nvd_api_key() else 6.5
    delta = time.monotonic() - _nvd_last_call
    if delta < min_gap:
        time.sleep(min_gap - delta)
    _nvd_last_call = time.monotonic()


def _nvd_get(params: dict) -> dict:
    _nvd_throttle()
    url = f"{NVD_API}?{urllib.parse.urlencode(params)}"
    key = nvd_api_key()
    return _http_json(url, headers={"apiKey": key} if key else None)


def _pick_cvss(metrics: dict) -> tuple[float | None, str, str]:
    """Return (base_score, vector, severity) preferring the newest CVSS version."""
    for bucket in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(bucket) or []
        if not entries:
            continue
        primary = next(
            (e for e in entries if (e.get("type") or "").upper() == "PRIMARY"), entries[0]
        )
        data = primary.get("cvssData", {}) or {}
        score = data.get("baseScore")
        vector = data.get("vectorString", "") or ""
        severity = (
            data.get("baseSeverity")
            or primary.get("baseSeverity")
            or ""
        ).upper()
        if score is not None:
            return float(score), vector, severity
    return None, "", ""


def parse_nvd_cve(obj: dict) -> Finding:
    """Turn one NVD `cve` object into a Finding."""
    cve = obj.get("cve", obj) or {}

    descriptions = cve.get("descriptions", []) or []
    summary = next(
        (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
        descriptions[0].get("value", "") if descriptions else "",
    )

    score, vector, severity = _pick_cvss(cve.get("metrics", {}) or {})

    cwe = ""
    for weakness in cve.get("weaknesses", []) or []:
        for desc in weakness.get("description", []) or []:
            value = desc.get("value", "") or ""
            if value.upper().startswith("CWE-"):
                cwe = value
                break
        if cwe:
            break

    raw_refs = cve.get("references", []) or []
    refs = [r.get("url", "") for r in raw_refs if r.get("url")]
    # NVD labels each reference; keep those labels instead of discarding them.
    kinds = _group_references(
        (r.get("url", ""), classify_nvd_tags(r.get("tags")))
        for r in raw_refs
    )
    edb = [u for u in refs if EXPLOITDB_HOST in u.lower()]

    return Finding(
        identifier=cve.get("id", "") or "",
        source="nvd",
        severity=severity or "UNKNOWN",
        severity_source=(SEV_SRC_NVD if severity else SEV_SRC_UNSCORED),
        cvss_score=score,
        cvss_vector=vector,
        cwe=cwe,
        cwe_name=_cwe_name(cwe),
        summary=summary.strip(),
        details=summary.strip(),
        references=refs,
        reference_kinds=kinds,
        exploitdb_refs=edb,
        published=(cve.get("published", "") or "")[:10],
    )


_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def is_cve_id(value: str) -> bool:
    return bool(_CVE_RE.match((value or "").strip()))


def nvd_lookup(cve_id: str) -> Finding | None:
    """Fetch a single CVE record from NVD."""
    if not is_cve_id(cve_id):
        raise ValueError(f"not a CVE id: {cve_id!r} (expected CVE-YYYY-NNNNN)")
    data = _nvd_get({"cveId": cve_id.upper()})
    items = data.get("vulnerabilities", []) or []
    return parse_nvd_cve(items[0]) if items else None


def nvd_search(keywords: str, *, limit: int = 20,
               exact: bool = False) -> list[Finding]:
    """Keyword-search NVD, e.g. 'apache struts' or 'openssh 9.1'."""
    params = {
        "keywordSearch": keywords,
        "resultsPerPage": max(1, min(int(limit), 100)),
    }
    if exact:
        params["keywordExactMatch"] = ""
    data = _nvd_get(params)
    return [parse_nvd_cve(v) for v in (data.get("vulnerabilities", []) or [])]


# ---------------------------------------------------------------------------
# OSV.dev -- dependency advisories
# ---------------------------------------------------------------------------

def osv_query(name: str, version: str, ecosystem: str) -> list[dict]:
    """Ask OSV which advisories affect this exact package version."""
    body = {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
    data = _http_json(OSV_API, payload=body)
    return (data or {}).get("vulns", []) or []


def parse_osv_vuln(vuln: dict, *, package: str, ecosystem: str,
                   version: str, location: str = "") -> Finding:
    """Turn one OSV advisory into a Finding."""
    osv_id = vuln.get("id", "") or ""
    aliases = [a for a in (vuln.get("aliases", []) or []) if a]

    # Prefer the CVE id for display -- it's what defenders and KEV key on.
    cve = next((a for a in aliases if a.upper().startswith("CVE-")), "")
    identifier = cve or osv_id
    other = [a for a in aliases if a != identifier]
    if osv_id and osv_id != identifier:
        other.append(osv_id)

    severity = ""
    vector = ""
    for sev in vuln.get("severity", []) or []:
        score = sev.get("score", "") or ""
        if score.upper().startswith("CVSS:"):
            vector = score
            break
    db = vuln.get("database_specific", {}) or {}
    severity = (db.get("severity") or "").upper()

    fixed: list[str] = []
    for affected in vuln.get("affected", []) or []:
        pkg = affected.get("package", {}) or {}
        if package and pkg.get("name") and pkg["name"].lower() != package.lower():
            continue
        if not severity:
            adb = affected.get("database_specific", {}) or {}
            severity = (adb.get("severity") or "").upper()
        for rng in affected.get("ranges", []) or []:
            # GIT ranges give commit hashes, not versions. A 40-char SHA in
            # "upgrade to ..." advice is noise -- keep ECOSYSTEM/SEMVER only.
            if (rng.get("type") or "").upper() == "GIT":
                continue
            for event in rng.get("events", []) or []:
                if event.get("fixed"):
                    fixed.append(event["fixed"])

    raw_refs = vuln.get("references", []) or []
    refs = [r.get("url", "") for r in raw_refs if r.get("url")]
    # OSV types each reference; "FIX" is the commit that resolved the issue.
    kinds = _group_references(
        (r.get("url", ""), classify_osv_type(r.get("type")))
        for r in raw_refs
    )
    edb = [u for u in refs if EXPLOITDB_HOST in u.lower()]

    # `summary` is the one-line headline; `details` is the full writeup and is
    # NOT truncated -- it is the best "what exactly is this" text available,
    # and clipping it to 400 characters threw that away.
    headline = (vuln.get("summary") or "").strip()
    body = (vuln.get("details") or "").strip()
    summary = headline or body
    if not headline and len(summary) > 400:
        summary = summary[:397].rstrip() + "..."
    details = body or headline

    return Finding(
        identifier=identifier,
        source="osv",
        severity=severity or "UNKNOWN",
        severity_source=(SEV_SRC_OSV if severity else SEV_SRC_UNSCORED),
        cvss_vector=vector,
        summary=summary,
        details=details,
        package=package,
        ecosystem=ecosystem,
        installed_version=version,
        fixed_versions=sorted(set(fixed)),
        aliases=sorted(set(other)),
        references=refs,
        reference_kinds=kinds,
        exploitdb_refs=edb,
        published=(vuln.get("published", "") or "")[:10],
        location=location,
    )


# ---------------------------------------------------------------------------
# Manifest parsers -- what is actually installed?
# ---------------------------------------------------------------------------

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "venv", ".venv", "env",
    "__pycache__", "dist", "build", ".tox", ".nox", ".mypy_cache",
    ".pytest_cache", "site-packages", ".idea", ".vscode", "vendor",
}

_REQ_RE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==\s*"
    r"(?P<version>[A-Za-z0-9][A-Za-z0-9.!+*-]*)"
)


def parse_requirements(text: str) -> list[tuple[str, str]]:
    """requirements.txt -> [(name, version)] for `==` pins only."""
    out: list[tuple[str, str]] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        line = line.split(";", 1)[0].strip()  # drop environment markers
        match = _REQ_RE.match(line)
        if match:
            out.append((match.group("name"), match.group("version")))
    return out


def parse_package_lock(text: str) -> list[tuple[str, str]]:
    """package-lock.json (v1, v2 and v3 layouts)."""
    data = json.loads(text)
    out: list[tuple[str, str]] = []

    packages = data.get("packages")
    if isinstance(packages, dict):  # lockfileVersion 2/3
        for path, meta in packages.items():
            if not path or not isinstance(meta, dict):
                continue  # "" is the root project itself
            name = meta.get("name") or path.split("node_modules/")[-1]
            version = meta.get("version")
            if name and version:
                out.append((name, version))

    if not out:  # lockfileVersion 1
        def walk(deps: dict) -> None:
            for name, meta in (deps or {}).items():
                if isinstance(meta, dict):
                    if meta.get("version"):
                        out.append((name, meta["version"]))
                    walk(meta.get("dependencies", {}))
        walk(data.get("dependencies", {}))

    return out


_SEMVER_PREFIX = re.compile(r"^[\^~>=<\s v]*")


def parse_package_json(text: str) -> list[tuple[str, str]]:
    """package.json -- ranges stripped to their base version (approximate)."""
    data = json.loads(text)
    out: list[tuple[str, str]] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, spec in (data.get(section) or {}).items():
            if not isinstance(spec, str):
                continue
            version = _SEMVER_PREFIX.sub("", spec).split(" ")[0].strip()
            if re.match(r"^\d+\.\d+", version):
                out.append((name, version))
    return out


def parse_go_mod(text: str) -> list[tuple[str, str]]:
    """go.mod -- both `require (...)` blocks and single-line requires."""
    out: list[tuple[str, str]] = []
    in_block = False
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if line.startswith("require "):
            line = line[len("require "):].strip()
        elif not in_block:
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[1].startswith("v"):
            out.append((parts[0], parts[1].lstrip("v")))
    return out


def parse_cargo_lock(text: str) -> list[tuple[str, str]]:
    """Cargo.lock -- [[package]] entries."""
    import tomllib

    data = tomllib.loads(text)
    out: list[tuple[str, str]] = []
    for pkg in data.get("package", []) or []:
        name, version = pkg.get("name"), pkg.get("version")
        if name and version:
            out.append((name, version))
    return out


# filename -> (OSV ecosystem, parser, precedence) -- higher precedence wins
# when two manifests in the same folder describe the same thing.
MANIFESTS: dict[str, tuple[str, object, int]] = {
    "package-lock.json": ("npm", parse_package_lock, 2),
    "package.json": ("npm", parse_package_json, 1),
    "go.mod": ("Go", parse_go_mod, 2),
    "Cargo.lock": ("crates.io", parse_cargo_lock, 2),
}


def discover_manifests(root: str | Path) -> list[tuple[Path, str, object]]:
    """Walk a tree and return the dependency manifests worth scanning."""
    root = Path(root)
    found: list[tuple[Path, str, object]] = []

    if root.is_file():
        eco_parser = _manifest_for(root)
        return [(root, *eco_parser)] if eco_parser else []

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        here = Path(dirpath)

        # npm: prefer the lockfile over package.json in the same folder
        names = set(filenames)
        if "package-lock.json" in names:
            names.discard("package.json")

        for name in sorted(names):
            entry = _manifest_for(here / name)
            if entry:
                found.append((here / name, *entry))

    return found


def _manifest_for(path: Path) -> tuple[str, object] | None:
    name = path.name
    if name in MANIFESTS:
        eco, parser, _ = MANIFESTS[name]
        return eco, parser
    if name == "requirements.txt" or (
        name.startswith("requirements") and name.endswith(".txt")
    ):
        return "PyPI", parse_requirements
    return None


# ---------------------------------------------------------------------------
# Dependency scan
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    manifests: list[str] = field(default_factory=list)
    packages_checked: int = 0
    unpinned_skipped: int = 0
    errors: list[str] = field(default_factory=list)
    # Where the inventory came from, e.g. "SBOM: CycloneDX 1.5 via syft".
    source_label: str = ""
    # Components present in the inventory that could NOT be checked. These are
    # reported as unknown, never as clean.
    not_checked: int = 0
    not_checked_reasons: dict[str, int] = field(default_factory=dict)


def scan_dependencies(root: str | Path, *, workers: int = 8,
                      progress=None) -> ScanResult:
    """Find dependency manifests under `root` and check every pinned package
    against OSV. Pure lookup: nothing is installed, executed or modified."""
    result = ScanResult()
    manifests = discover_manifests(root)
    if not manifests:
        return result

    jobs: list[tuple[str, str, str, str]] = []  # name, version, ecosystem, location
    for path, ecosystem, parser in manifests:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            packages = parser(text)
        except Exception as exc:  # noqa: BLE001 - one bad manifest must not kill the scan
            result.errors.append(f"{path}: {exc}")
            continue

        result.manifests.append(str(path))
        rel = str(path)
        for name, version in packages:
            jobs.append((name, version, ecosystem, rel))

    return scan_components(jobs, workers=workers, progress=progress,
                           result=result)


def scan_components(jobs, *, workers: int = 8, progress=None,
                    result: ScanResult | None = None) -> ScanResult:
    """Check a list of (name, version, ecosystem, location) against OSV.

    Shared by the manifest scanner and the SBOM scanner, so both get identical
    de-duplication, parallelism and error handling.
    """
    result = result if result is not None else ScanResult()

    # De-duplicate identical (package, version, ecosystem) across sources.
    seen: set[tuple[str, str, str]] = set()
    unique_jobs = []
    for name, version, eco, loc in jobs:
        key = (eco, name.lower(), version)
        if key in seen:
            continue
        seen.add(key)
        unique_jobs.append((name, version, eco, loc))

    result.packages_checked = len(unique_jobs)
    if not unique_jobs:
        return result

    def probe(job):
        name, version, eco, loc = job
        try:
            vulns = osv_query(name, version, eco)
        except VulnIntelError as exc:
            return [], f"{name}=={version}: {exc}"
        return [
            parse_osv_vuln(v, package=name, ecosystem=eco, version=version, location=loc)
            for v in vulns
        ], None

    done = 0
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        for findings, error in pool.map(probe, unique_jobs):
            done += 1
            if progress:
                progress(done, len(unique_jobs))
            if error:
                result.errors.append(error)
            result.findings.extend(findings)

    # Merge before sorting: OSV returns multiple advisories per CVE.
    result.findings = sort_findings(merge_findings(result.findings))
    return result


def scan_sbom(path, *, workers: int = 8, progress=None):
    """Scan the components listed in a CycloneDX or SPDX SBOM.

    Returns (ScanResult, Sbom). Components the SBOM lists but that cannot be
    mapped to an OSV ecosystem are carried on the result as `not_checked` --
    they are unknown, not clean.
    """
    import coldlight_sbom

    sbom = coldlight_sbom.load_sbom(path)

    result = ScanResult()
    result.source_label = f"SBOM: {sbom.label}"
    result.manifests = [sbom.path or str(path)]
    result.not_checked = len(sbom.skipped)
    result.not_checked_reasons = sbom.skip_summary()

    scan_components(coldlight_sbom.to_jobs(sbom), workers=workers,
                    progress=progress, result=result)
    return result, sbom


def enrich_with_nvd(findings: list[Finding], *,
                    limit: int = MAX_ENRICH_LOOKUPS) -> int:
    """Fill in CVSS score / CWE from NVD for findings that lack them.

    Rate-limited by NVD, so this is capped and opt-in. Returns how many
    findings were enriched.
    """
    enriched = 0
    for finding in findings:
        if enriched >= limit:
            break
        if finding.cvss_score is not None or not is_cve_id(finding.identifier):
            continue
        try:
            detail = nvd_lookup(finding.identifier)
        except (VulnIntelError, ValueError):
            continue
        if not detail:
            continue
        finding.cvss_score = detail.cvss_score
        finding.cvss_vector = finding.cvss_vector or detail.cvss_vector
        finding.cwe = finding.cwe or detail.cwe
        if (not finding.severity or finding.severity == "UNKNOWN") and detail.severity:
            finding.severity = detail.severity
            finding.severity_source = SEV_SRC_NVD
        if not finding.summary:
            finding.summary = detail.summary
        for url in detail.exploitdb_refs:
            if url not in finding.exploitdb_refs:
                finding.exploitdb_refs.append(url)
        enriched += 1
    return enriched


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        key = (f.severity or "UNKNOWN").upper()
        counts[key] = counts.get(key, 0) + 1
    return counts


def meets_threshold(findings: list[Finding], threshold: str) -> bool:
    """True if any finding is at or above `threshold` (for CI gating)."""
    floor = SEVERITY_ORDER.get((threshold or "").upper())
    if floor is None:
        raise ValueError(f"unknown severity threshold: {threshold!r}")
    return any(
        SEVERITY_ORDER.get((f.severity or "UNKNOWN").upper(), 0) >= floor
        for f in findings
    )


def format_finding(f: Finding, *, verbose: bool = False) -> str:
    flag = "[KEV] " if f.kev else ""
    head = f"{flag}{(f.severity or 'UNKNOWN').upper():<8} {f.identifier}"
    if f.package:
        head += f"  {f.package} {f.installed_version} ({f.ecosystem})"

    lines = [head]
    if f.summary:
        lines.append(f"    {f.summary}")

    bits = []
    if f.cvss_score is not None:
        bits.append(f"cvss {f.cvss_score}")
    if f.epss_score is not None:
        from coldlight_exploitintel import epss_band
        bits.append(f"epss {f.epss_score:.3f} ({epss_band(f.epss_score)})")
    if f.cwe:
        bits.append(f"{f.cwe} {f.cwe_name}".strip() if f.cwe_name else f.cwe)
    if f.fixed_versions:
        bits.append("fixed in " + ", ".join(f.fixed_versions[:4]))
    if f.published:
        bits.append(f"published {f.published}")
    if bits:
        lines.append("    " + "  |  ".join(bits))

    if f.exploits:
        verified = sum(1 for e in f.exploits if e.get("verified"))
        earliest = min((e.get("date", "") for e in f.exploits if e.get("date")),
                       default="")
        note = (f"    PUBLIC EXPLOIT: {len(f.exploits)} listed on Exploit-DB"
                + (f", {verified} verified" if verified else "")
                + (f", earliest {earliest}" if earliest else ""))
        lines.append(note)
        lead = f.exploits[0]
        lines.append(f"        EDB-{lead.get('edb_id', '?')} "
                     f"({lead.get('type', '?')}/{lead.get('platform', '?')}) "
                     f"{lead.get('url', '')}")

    # The patch is the actionable reference; show it ahead of everything else,
    # and distinguish what the database stated from what we inferred.
    for url in (f.reference_kinds.get(KIND_PATCH) or [])[:2]:
        lines.append(f"    patch: {url}")
    for url in (f.reference_kinds.get(KIND_PATCH_LIKELY) or [])[:2]:
        lines.append(f"    likely patch: {url}")
    for url in (f.reference_kinds.get(KIND_MITIGATION) or [])[:1]:
        lines.append(f"    mitigation: {url}")

    if f.kev:
        note = "    KNOWN EXPLOITED (CISA KEV)"
        if f.kev_due_date:
            note += f" -- federal remediation due {f.kev_due_date}"
        if f.ransomware:
            note += "  [used in ransomware campaigns]"
        lines.append(note)

    if f.exploitdb_refs:
        lines.append(f"    public exploit referenced: {f.exploitdb_refs[0]}")

    if verbose:
        if f.cvss_vector:
            lines.append(f"    vector: {f.cvss_vector}")
        if f.details and f.details != f.summary:
            lines.append("    detail:")
            for line in f.details.strip().splitlines():
                lines.append(f"      {line}")
        if f.cwe:
            try:
                from coldlight_cwe import describe
                weakness = describe(f.cwe)
            except Exception:  # noqa: BLE001
                weakness = None
            if weakness:
                lines.append(f"    weakness: {weakness.name}")
                lines.append(f"      {weakness.description}")
                for mitigation in weakness.mitigations:
                    lines.append(f"      fix: {mitigation}")
        if f.aliases:
            lines.append(f"    aliases: {', '.join(f.aliases[:6])}")
        if f.location:
            lines.append(f"    from: {f.location}")
        for url in f.references[:5]:
            lines.append(f"    ref: {url}")

    return "\n".join(lines)


def text_report(result: ScanResult, *, verbose: bool = False) -> str:
    out: list[str] = []
    counts = severity_counts(result.findings)
    kev_count = sum(1 for f in result.findings if f.kev)

    out.append("=" * 68)
    out.append("ColdLight dependency vulnerability scan")
    out.append("=" * 68)
    if result.source_label:
        out.append(f"source            : {result.source_label}")
        out.append(f"inventory         : {result.manifests[0]}"
                   if result.manifests else "")
    else:
        out.append(f"manifests scanned : {len(result.manifests)}")
    out.append(f"packages checked  : {result.packages_checked}")
    out.append(f"vulnerabilities   : {len(result.findings)}")
    if counts:
        ordered = sorted(
            counts.items(), key=lambda kv: -SEVERITY_ORDER.get(kv[0], 0)
        )
        out.append("  by severity     : " +
                   ", ".join(f"{k.lower()}={v}" for k, v in ordered))
    if kev_count:
        out.append(f"  KNOWN EXPLOITED : {kev_count}  <-- fix these first")

    if result.not_checked:
        out.append("")
        out.append(f"!! {result.not_checked} component(s) in the inventory were "
                   f"NOT CHECKED.")
        out.append("   Treat these as UNKNOWN, not as clean:")
        for reason, count in result.not_checked_reasons.items():
            out.append(f"     {count:>5}  {reason}")

    if result.findings:
        out.append("")
        for finding in result.findings:
            out.append(format_finding(finding, verbose=verbose))
            out.append("")

    if result.errors:
        out.append(f"{len(result.errors)} lookup error(s):")
        for err in result.errors[:10]:
            out.append(f"  - {err}")

    if not result.manifests:
        out.append("")
        out.append("No dependency manifests found. Supported: requirements*.txt, "
                   "package-lock.json, package.json, go.mod, Cargo.lock")

    return "\n".join(out)


def json_report(result: ScanResult) -> dict:
    return {
        "tool": "coldlight vulnintel",
        "sources": ["osv.dev", "nvd.nist.gov", "cisa.gov/kev"],
        "inventory_source": result.source_label or "dependency manifests",
        "manifests": result.manifests,
        "packages_checked": result.packages_checked,
        "not_checked": result.not_checked,
        "not_checked_reasons": result.not_checked_reasons,
        "severity_counts": severity_counts(result.findings),
        "known_exploited": sum(1 for f in result.findings if f.kev),
        "findings": [f.to_dict() for f in result.findings],
        "errors": result.errors,
    }
