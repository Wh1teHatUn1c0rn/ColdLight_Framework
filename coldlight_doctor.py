#!/usr/bin/env python3
"""
Preflight dependency check: what works on THIS machine, and what does not.

ColdLight is stdlib-only at runtime, but it is not self-contained. It leans on a
git binary, a current CA bundle, public DNS-over-HTTPS resolvers, four
vulnerability and exploit feeds, and optionally GnuPG or OpenSSL. When one of
those is
absent or blocked, the failure usually surfaces halfway through an engagement
as a confusing error from whichever stage happened to need it first. This
module asks the questions up front and answers them in terms of commands:

    git is not on PATH      ->  `scan history` will not run
    cloudflare-dns is blocked, dns.google answers  ->  `mail audit` is fine

Two rules shape the design.

First, every check goes through the SAME code path as the command it stands in
for: TLS uses `coldlight_trust.ssl_context()` -- the one context every network
call in ColdLight shares, so a stale trust store fails here exactly as it would
there -- and DNS uses `coldlight_mail.doh_query()`. A doctor that opened its own
socket with its own context could report a healthy machine while the real
commands fail, which is worse than having no check at all.

Second, the reachability probes carry a FIXED payload. They send nothing about
the engagement: no target list, no domain under test, no package names from the
project, no file paths. A preflight that leaked the scope to five external
services before the assessment started would be a defect, not a feature.

Nothing here is a judgement about a remote service's health. A probe says
whether this machine can reach it right now, from this network, with this trust
store. That is the only question a preflight can honestly answer.

Stdlib only.
"""

from __future__ import annotations

import importlib.util
import json
import os
import platform
import shutil
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path

from coldlight_config import __version__

# Generic client identifier. Like the rest of the project's user agents, it
# deliberately carries no operator, host or organisation identity.
USER_AGENT = "ColdLight-Doctor/1.0"

DEFAULT_TIMEOUT = 8        # a reachability probe, not a data fetch
DEFAULT_WORKERS = 8

MIN_PYTHON = (3, 11)       # stdlib tomllib

# ---------------------------------------------------------------------------
# Status vocabulary
# ---------------------------------------------------------------------------

STATUS_OK = "ok"
STATUS_DEGRADED = "degraded"      # usable, with a caveat worth knowing
STATUS_MISSING = "missing"        # absent; the commands it serves cannot run
STATUS_FAILED = "failed"          # present but broken, or unreachable
STATUS_SKIPPED = "skipped"        # NOT CHECKED -- never evidence of health

# Worst first, for sorting and for the summary line.
STATUS_ORDER = {
    STATUS_FAILED: 4,
    STATUS_MISSING: 3,
    STATUS_DEGRADED: 2,
    STATUS_SKIPPED: 1,
    STATUS_OK: 0,
}

# How each status prints. Anything needing attention is upper-case, matching
# the convention the rest of the project uses for NOT ASSESSED / FAILED.
STATUS_LABEL = {
    STATUS_OK: "ok",
    STATUS_DEGRADED: "DEGRADED",
    STATUS_MISSING: "UNAVAILABLE",
    STATUS_FAILED: "FAILED",
    STATUS_SKIPPED: "not checked",
}

GROUP_RUNTIME = "Python runtime"
GROUP_TRUST = "TLS trust"
GROUP_TOOLS = "External tools"
GROUP_STORAGE = "Local storage"
GROUP_NETWORK = "External services"

GROUP_ORDER = (GROUP_RUNTIME, GROUP_TRUST, GROUP_TOOLS, GROUP_STORAGE,
               GROUP_NETWORK)


class DoctorError(RuntimeError):
    """A preflight could not be set up (bad profile, unreadable file)."""


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------

@dataclass
class Check:
    """One dependency, and what its absence costs."""

    name: str
    group: str = GROUP_RUNTIME
    status: str = STATUS_OK
    detail: str = ""
    # Commands that stop working when this check is MISSING or FAILED. Written
    # as the operator would type them, so the report is copy-pasteable.
    affects: tuple[str, ...] = ()
    remedy: str = ""
    # True only when the whole tool is unusable without it. A missing `git`
    # costs one command; a Python without tomllib costs all of them.
    fatal: bool = False
    path: str = ""          # resolved location, for the JSON artifact

    @property
    def blocking(self) -> bool:
        return self.status in (STATUS_MISSING, STATUS_FAILED)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["affects"] = list(self.affects)
        return data


@dataclass
class DoctorResult:
    checks: list[Check] = field(default_factory=list)
    offline: bool = False
    # Set when a profile narrowed the run: the stages it configures, and the
    # stages among them with no external dependency to check.
    profile: str = ""
    profile_stages: list[str] = field(default_factory=list)
    duration_s: float = 0.0

    def by_group(self, group: str) -> list[Check]:
        return [c for c in self.checks if c.group == group]

    def with_status(self, status: str) -> list[Check]:
        return [c for c in self.checks if c.status == status]

    @property
    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for check in self.checks:
            out[check.status] = out.get(check.status, 0) + 1
        return out

    @property
    def unchecked(self) -> list[Check]:
        return self.with_status(STATUS_SKIPPED)

    @property
    def unavailable(self) -> list[tuple[str, str]]:
        """(command, reason) for every command a blocking check takes out.

        Ordered worst-first and de-duplicated on the command, so a command
        broken by two separate causes is named once, by the worse one.
        """
        seen: dict[str, str] = {}
        for check in sorted(self.checks,
                            key=lambda c: -STATUS_ORDER.get(c.status, 0)):
            if not check.blocking:
                continue
            for command in check.affects:
                seen.setdefault(command, check.detail or check.name)
        return sorted(seen.items())

    @property
    def fatal_checks(self) -> list[Check]:
        return [c for c in self.checks if c.fatal and c.blocking]

    @property
    def exit_code(self) -> int:
        """0 everything checked is healthy, 1 some commands will not work,
        2 ColdLight cannot run here at all."""
        if self.fatal_checks:
            return 2
        if any(c.status in (STATUS_FAILED, STATUS_MISSING, STATUS_DEGRADED)
               for c in self.checks):
            return 1
        return 0

    @property
    def healthy(self) -> bool:
        """Every check that ran came back clean. Says nothing about the ones
        that did not run -- read `unchecked` for those."""
        return not any(c.status != STATUS_OK and c.status != STATUS_SKIPPED
                       for c in self.checks)


# ---------------------------------------------------------------------------
# External services
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Endpoint:
    name: str
    urls: tuple[str, ...]           # tried in order; the first to answer wins
    method: str = "GET"
    payload: dict | None = None     # fixed, engagement-free (see module docs)
    affects: tuple[str, ...] = ()
    note: str = ""


def _endpoints() -> tuple[Endpoint, ...]:
    """Build the endpoint table from the modules that actually call them.

    Imported late so the URLs can never drift from the code that uses them,
    and so a Python built without `ssl` reaches the ssl check below rather
    than dying on an import.
    """
    import coldlight_exploitintel as ei
    import coldlight_vulnintel as vi

    return (
        Endpoint(
            name="NVD (CVE records)",
            urls=(f"{vi.NVD_API}?resultsPerPage=1",),
            affects=("cve", "vulns", "scan deps --enrich"),
            note="severity and description enrichment",
        ),
        Endpoint(
            name="OSV.dev (advisories)",
            urls=(vi.OSV_API,),
            method="POST",
            # A fixed query for a well-known public package. Nothing from the
            # project under assessment is sent.
            payload={"package": {"name": "requests", "ecosystem": "PyPI"},
                     "version": "2.31.0"},
            affects=("scan deps", "scan sbom"),
            note="the advisory source both dependency scans depend on",
        ),
        Endpoint(
            name="CISA KEV catalog",
            urls=(vi.KEV_FEED,),
            method="HEAD",          # multi-MB feed; reachability is the question
            affects=("kev",),
            note="known-exploited flags on every scan",
        ),
        Endpoint(
            name="EPSS (FIRST.org)",
            urls=(f"{ei.EPSS_API}?cve=CVE-2021-44228",),
            affects=(),
            note="exploitation-probability scores; scans degrade without it",
        ),
        Endpoint(
            name="Exploit-DB index",
            urls=ei.EXPLOITDB_INDEX_URLS,
            method="HEAD",          # ~10MB CSV
            affects=(),
            note="public-exploit availability; mirror used if the primary "
                 "is blocked",
        ),
    )


def _reach(url: str, *, method: str = "GET", payload: dict | None = None,
           timeout: int = DEFAULT_TIMEOUT) -> tuple[int | None, str]:
    """Probe one URL. Returns (http_status, error_detail).

    Deliberately NOT `coldlight_vulnintel._http_json`: that retries with backoff
    and parses a body, which is right for fetching data and wrong for a
    preflight. The TLS context is the shared one, which is the part that
    matters -- a trust-store problem has to reproduce here.

    An HTTP status of any value proves DNS, TCP and TLS all worked, so the
    status is returned rather than raised on.
    """
    import coldlight_trust as trust

    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if data is not None:
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(url, data=data, headers=headers,
                                     method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout,
                                    context=trust.ssl_context()) as response:
            return int(getattr(response, "status", 0) or 0), ""
    except urllib.error.HTTPError as exc:
        return int(exc.code), ""
    except urllib.error.URLError as exc:
        return None, _url_error_detail(exc)
    except (OSError, ValueError) as exc:
        return None, f"{type(exc).__name__}: {exc}"


def _url_error_detail(exc: urllib.error.URLError) -> str:
    """Turn a URLError into something an operator can act on."""
    import ssl

    reason = getattr(exc, "reason", exc)
    if isinstance(reason, ssl.SSLCertVerificationError):
        detail = getattr(reason, "verify_message", None) or reason
        return (f"TLS verification failed: {detail} -- usually a stale CA "
                f"bundle on this machine, not a bad server")
    if isinstance(reason, TimeoutError):
        return "timed out"
    return str(reason) or f"{type(exc).__name__}"


def check_endpoint(endpoint: Endpoint, *, timeout: int = DEFAULT_TIMEOUT,
                   reach=None) -> Check:
    """Probe an endpoint's URLs in order; the first that answers decides."""
    probe = reach or _reach
    attempts: list[str] = []

    for index, url in enumerate(endpoint.urls):
        host = urllib.parse.urlsplit(url).netloc or url
        status, error = probe(url, method=endpoint.method,
                             payload=endpoint.payload, timeout=timeout)
        if status is None:
            attempts.append(f"{host}: {error}")
            continue

        if 200 <= status < 400:
            detail = f"{host} answered HTTP {status}"
            if index:
                detail += f" (primary unreachable: {attempts[0]})"
            return Check(name=endpoint.name, group=GROUP_NETWORK,
                         status=STATUS_DEGRADED if index else STATUS_OK,
                         detail=detail, affects=endpoint.affects,
                         remedy=(_with_note("the primary source is blocked "
                                            "here; the mirror is in use",
                                            endpoint) if index else ""),
                         path=url)

        # The host answered, so the network path is fine -- it is refusing us.
        return Check(
            name=endpoint.name, group=GROUP_NETWORK, status=STATUS_DEGRADED,
            detail=f"{host} answered HTTP {status} (reachable, but refusing)",
            affects=endpoint.affects,
            remedy=_with_note(
                "rate limiting or a filtering proxy, not a connectivity "
                "problem" if status in (403, 429) else
                "the service is reachable but not serving this request",
                endpoint),
            path=url)

    return Check(name=endpoint.name, group=GROUP_NETWORK, status=STATUS_FAILED,
                 detail="; ".join(attempts) or "unreachable",
                 affects=endpoint.affects,
                 remedy=_with_note(
                     "check egress, a proxy, or the TLS trust store above",
                     endpoint),
                 path=endpoint.urls[0] if endpoint.urls else "")


def _with_note(remedy: str, endpoint: Endpoint) -> str:
    """Append what this endpoint is for, so a failure says what it costs.

    Several feeds (EPSS, Exploit-DB) block no command outright -- they only
    reduce what a scan can say. Without the note, such a failure would read as
    unexplained noise.
    """
    return f"{remedy}. Used for: {endpoint.note}" if endpoint.note else remedy


def check_doh(*, resolve=None) -> Check:
    """One check for DNS-over-HTTPS, covering every configured resolver.

    `mail audit` tries them in order and needs only one, so reporting them as
    separate checks would flag a blocked Cloudflare as a broken command when
    Google is answering. Each resolver's own result still appears in the
    detail, because knowing WHICH one is blocked is what you act on.

    This probe takes no timeout of its own: it uses the mail module's, so a
    resolver slow enough to break `mail audit` is slow enough to fail here.
    """
    import coldlight_mail as mail

    query = resolve or _resolve_one
    working: list[str] = []
    broken: list[str] = []

    for resolver in mail.DOH_RESOLVERS:
        host = urllib.parse.urlsplit(resolver).netloc or resolver
        error = query(resolver)
        if error:
            broken.append(f"{host}: {error}")
        else:
            working.append(host)

    affects = ("mail audit",)
    if working and not broken:
        return Check(name="DNS-over-HTTPS", group=GROUP_NETWORK,
                     status=STATUS_OK,
                     detail=f"{len(working)} of {len(working)} resolvers "
                            f"answered ({', '.join(working)})",
                     affects=affects)
    if working:
        return Check(name="DNS-over-HTTPS", group=GROUP_NETWORK,
                     status=STATUS_DEGRADED,
                     detail=f"{', '.join(working)} answered; "
                            f"{'; '.join(broken)}",
                     affects=affects,
                     remedy="one resolver is enough, so `mail audit` works -- "
                            "but a filtered resolver may also be rewriting "
                            "answers")
    # Now that DNS shares the one trust store, a bad CA bundle takes the
    # resolvers down too -- so do not assert a network block we cannot see.
    # Blaming the firewall for a trust-store problem sends someone to argue
    # with their network team about a file on their own disk.
    if _looks_like_tls("; ".join(broken)):
        remedy = ("this is the trust store above, not the network -- DNS "
                  "fails here for the same reason every other TLS call does")
    else:
        remedy = ("DNS-over-HTTPS is blocked on this network; `mail audit` "
                  "cannot resolve anything")
    return Check(name="DNS-over-HTTPS", group=GROUP_NETWORK,
                 status=STATUS_FAILED,
                 detail="; ".join(broken) or "no resolver answered",
                 affects=affects, remedy=remedy)


def _looks_like_tls(text: str) -> bool:
    """Whether a transport error is a certificate problem rather than reach.

    Pattern-matching an error string is crude, and it only ever changes which
    remedy is suggested -- never whether the check failed.
    """
    lowered = (text or "").lower()
    return any(marker in lowered for marker in
               ("x509", "certificate", "sslerror", "ssl:", "ca_cert",
                "crl found"))


def _resolve_one(resolver: str) -> str:
    """Ask one resolver a fixed question. Returns "" on success, else why not.

    The name queried is `example.com` -- reserved by IANA, constant, and
    unrelated to whatever domain is actually under assessment. Either NOERROR
    or NXDOMAIN proves the resolver answered, which is the whole question; the
    records themselves are not inspected.

    Calls `doh_query` unmodified rather than adjusting its timeout, because
    mutating another module's global from inside a thread pool is a race, and
    because matching what `mail audit` does is the point of the check.
    """
    import coldlight_mail as mail

    try:
        mail.doh_query("example.com", "TXT", resolvers=(resolver,))
        return ""
    except mail.MailAuditError as exc:
        # Strip the module's own prefix; the caller adds the resolver name.
        text = str(exc)
        marker = "resolver: "
        return text.split(marker, 1)[1] if marker in text else text
    except Exception as exc:  # noqa: BLE001 - a preflight never raises
        return f"{type(exc).__name__}: {exc}"


# ---------------------------------------------------------------------------
# Python runtime
# ---------------------------------------------------------------------------

def check_python() -> Check:
    current = sys.version_info[:3]
    pretty = ".".join(str(p) for p in current)
    wanted = ".".join(str(p) for p in MIN_PYTHON)
    if current[:2] < MIN_PYTHON:
        return Check(
            name="Python", group=GROUP_RUNTIME, status=STATUS_FAILED,
            detail=f"{pretty} -- ColdLight needs {wanted} or newer",
            affects=("every command",), fatal=True,
            remedy=f"install Python {wanted}+; the config and profile loaders "
                   f"use the stdlib tomllib added in {wanted}",
            path=sys.executable)
    return Check(name="Python", group=GROUP_RUNTIME, status=STATUS_OK,
                 detail=f"{pretty} on {platform.system() or 'unknown'}",
                 path=sys.executable)


def check_tomllib() -> Check:
    """Checked as an import rather than inferred from the version: a stripped
    or vendored build can satisfy the version and still lack the module."""
    if importlib.util.find_spec("tomllib") is None:
        return Check(
            name="tomllib", group=GROUP_RUNTIME, status=STATUS_MISSING,
            detail="not importable, so no TOML file can be read",
            affects=("validate", "build", "assess --profile", "scope"),
            fatal=True,
            remedy="this Python is missing a stdlib module; reinstall it")
    return Check(name="tomllib", group=GROUP_RUNTIME, status=STATUS_OK,
                 detail="available (campaign, profile and scope files)")


def check_ssl() -> Check:
    try:
        import ssl
    except ImportError:
        return Check(
            name="ssl module", group=GROUP_RUNTIME, status=STATUS_MISSING,
            detail="this Python was built without TLS support",
            affects=("cve", "vulns", "kev", "scan deps", "scan sbom",
                     "mail audit", "probe"),
            remedy="reinstall Python with OpenSSL; the local scans "
                   "(scan code, scan ai, scan history) still work")
    return Check(name="ssl module", group=GROUP_RUNTIME, status=STATUS_OK,
                 detail=ssl.OPENSSL_VERSION)


def check_sqlite() -> Check:
    """Prove it opens, not just that it imports -- a sqlite3 that cannot open
    a database is a different failure from one that is absent."""
    try:
        with sqlite3.connect(":memory:") as connection:
            connection.execute("SELECT 1").fetchone()
    except Exception as exc:  # noqa: BLE001
        return Check(
            name="sqlite3", group=GROUP_RUNTIME, status=STATUS_FAILED,
            detail=f"cannot open a database: {type(exc).__name__}: {exc}",
            affects=("serve", "report", "purge", "detect validate"),
            remedy="the awareness collector and its reports store hits in "
                   "SQLite")
    return Check(name="sqlite3", group=GROUP_RUNTIME, status=STATUS_OK,
                 detail=f"SQLite {sqlite3.sqlite_version}")


# ---------------------------------------------------------------------------
# TLS trust
# ---------------------------------------------------------------------------

def check_ca_bundle() -> Check:
    """Report which trust store ColdLight will actually use.

    This catches a misconfiguration that currently fails silently: the loader
    ignores COLDLIGHT_CA_BUNDLE and SSL_CERT_FILE when they point at a file that
    is not there, falling back without a word. Someone who set the variable to
    fix a verification error would never learn it had no effect.
    """
    try:
        import coldlight_trust as trust
    except ImportError as exc:
        return Check(name="TLS trust store", group=GROUP_TRUST,
                     status=STATUS_SKIPPED,
                     detail=f"not checked: {exc}")

    # The precedence rules are asked for, not re-derived. A doctor that
    # reimplemented them could describe a trust store other than the one in
    # use, which is the opposite of the point.
    active = trust.ca_bundle()
    source = trust.ca_bundle_source()
    detail = (f"{source} -> {active}" if active
              else "the system default trust store")

    ignored = trust.ignored_ca_bundle_vars()
    if ignored:
        stale = "; ".join(
            f"{var} points at {os.environ[var].strip()}, which does not exist"
            for var in ignored)
        return Check(
            name="TLS trust store", group=GROUP_TRUST, status=STATUS_DEGRADED,
            detail=f"{stale}; falling back to {detail}",
            remedy="the variable is being ignored -- fix the path or unset it, "
                   "so the fallback is a choice rather than a surprise",
            path=active or "")

    # Loading the context is the real test: a malformed bundle fails here.
    try:
        trust.ssl_context()
    except Exception as exc:  # noqa: BLE001
        return Check(
            name="TLS trust store", group=GROUP_TRUST, status=STATUS_FAILED,
            detail=f"{detail} could not be loaded: {type(exc).__name__}: {exc}",
            # Every network call shares this context, email auditing included.
            affects=("cve", "vulns", "kev", "scan deps", "scan sbom",
                     "mail audit", "probe"),
            remedy="point ColdLight at a current bundle with COLDLIGHT_CA_BUNDLE, "
                   "or install certifi. Never disable certificate checking",
            path=active or "")

    return Check(name="TLS trust store", group=GROUP_TRUST, status=STATUS_OK,
                 detail=detail, path=active or "")


def check_certifi() -> Check:
    if importlib.util.find_spec("certifi") is None:
        return Check(
            name="certifi", group=GROUP_TRUST, status=STATUS_MISSING,
            detail="not installed (optional)",
            remedy="only needed if this machine's own trust store is stale: "
                   "pip install 'coldlight[certs]'")
    try:
        import certifi
        where = certifi.where()
    except Exception as exc:  # noqa: BLE001
        return Check(name="certifi", group=GROUP_TRUST, status=STATUS_DEGRADED,
                     detail=f"installed but unusable: {exc}")
    return Check(name="certifi", group=GROUP_TRUST, status=STATUS_OK,
                 detail="installed", path=where)


# ---------------------------------------------------------------------------
# External tools and optional packages
# ---------------------------------------------------------------------------

def _tool_version(path: str, args: tuple[str, ...], *,
                  timeout: int = 10) -> str:
    """First line of `<tool> <args>`. No shell, fixed argument list."""
    if not args:
        return ""
    try:
        completed = subprocess.run(
            [path, *args], capture_output=True, text=True, timeout=timeout,
            check=False, encoding="utf-8", errors="replace")
    except (OSError, subprocess.SubprocessError):
        return ""
    text = (completed.stdout or completed.stderr or "").strip()
    return text.splitlines()[0].strip() if text else ""


def check_tool(binary: str, *, label: str = "", affects: tuple[str, ...] = (),
               remedy: str = "", version_args: tuple[str, ...] = ("--version",),
               applicable: bool = True, skip_reason: str = "") -> Check:
    name = label or binary
    if not applicable:
        return Check(name=name, group=GROUP_TOOLS, status=STATUS_SKIPPED,
                     detail=skip_reason or "not applicable on this platform",
                     affects=affects)
    path = shutil.which(binary)
    if not path:
        return Check(name=name, group=GROUP_TOOLS, status=STATUS_MISSING,
                     detail=f"{binary} is not installed or not on PATH",
                     affects=affects, remedy=remedy)
    return Check(name=name, group=GROUP_TOOLS, status=STATUS_OK,
                 detail=_tool_version(path, version_args) or "found",
                 path=path)


def check_module(module: str, *, label: str = "",
                 affects: tuple[str, ...] = (), remedy: str = "") -> Check:
    name = label or module
    if importlib.util.find_spec(module) is None:
        return Check(name=name, group=GROUP_TOOLS, status=STATUS_MISSING,
                     detail=f"{module} is not installed", affects=affects,
                     remedy=remedy)
    return Check(name=name, group=GROUP_TOOLS, status=STATUS_OK,
                 detail="installed")


def check_git() -> Check:
    return check_tool(
        "git", label="git",
        affects=("scan history",),
        remedy="install git, or run the scan where the repository lives. "
               "Without it, secrets committed and later deleted stay invisible")


def check_gpg() -> Check:
    return check_tool(
        "gpg", label="GnuPG",
        affects=("attest create --sign-with gpg",),
        remedy="install GnuPG to sign attestations, or use the hmac backend")


def check_openssl_tool() -> Check:
    return check_tool(
        "openssl", label="OpenSSL (CLI)",
        affects=("attest create --sign-with openssl",),
        # `openssl version`, not `--version`: the dash form is rejected by
        # OpenSSL 1.x and by LibreSSL, which printed its usage error into the
        # report as though it were a version string.
        version_args=("version",),
        remedy="install the OpenSSL command-line tool, or use another "
               "signing backend")


def check_signtool() -> Check:
    windows = sys.platform.startswith("win")
    return check_tool(
        "signtool", label="signtool (Authenticode)",
        affects=("sign",),
        version_args=(),        # signtool has no --version
        applicable=windows,
        skip_reason="Authenticode signing is Windows-only; not applicable on "
                    f"{sys.platform}",
        remedy="install the Windows SDK, or skip Authenticode signing")


def check_pyinstaller() -> Check:
    return check_module(
        "PyInstaller", label="PyInstaller",
        affects=("build",),
        remedy="pip install 'coldlight[build]' -- needed only to compile the "
               "awareness payload")


def check_qrcode() -> Check:
    return check_module(
        "qrcode", label="qrcode",
        affects=("qr",),
        remedy="pip install 'coldlight[qr]' -- needed only for the QR poster")


# ---------------------------------------------------------------------------
# Local storage
# ---------------------------------------------------------------------------

def check_cache_dir() -> Check:
    """The feed cache. Unwritable is slow, not broken -- say which."""
    try:
        import coldlight_vulnintel as vi
    except ImportError as exc:
        # The cache itself may be perfectly fine; we just cannot ask where it
        # is. Reporting that as DEGRADED would blame the wrong thing.
        return Check(name="feed cache", group=GROUP_STORAGE,
                     status=STATUS_SKIPPED, detail=f"not checked: {exc}")

    try:
        directory = vi.cache_dir()
    except OSError as exc:
        configured = os.environ.get("COLDLIGHT_CACHE") or "~/.coldlight/cache"
        return Check(
            name="feed cache", group=GROUP_STORAGE, status=STATUS_DEGRADED,
            detail=f"{configured} cannot be created: {exc.strerror or exc}",
            remedy="scans still work, but the KEV, EPSS and Exploit-DB feeds "
                   "are re-downloaded every run")

    probe = directory / ".coldlight-doctor-write-test"
    try:
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
    except OSError as exc:
        return Check(
            name="feed cache", group=GROUP_STORAGE, status=STATUS_DEGRADED,
            detail=f"{directory} is not writable: {exc.strerror or exc}",
            remedy="scans still work, but every run re-downloads the feeds. "
                   "Set COLDLIGHT_CACHE to a writable directory",
            path=str(directory))
    return Check(name="feed cache", group=GROUP_STORAGE, status=STATUS_OK,
                 detail=f"writable ({_cache_size(directory)})",
                 path=str(directory))


def _cache_size(directory: Path) -> str:
    try:
        files = [p for p in directory.iterdir() if p.is_file()]
    except OSError:
        return "size unknown"
    if not files:
        return "empty; feeds will be fetched on first use"
    total = sum(p.stat().st_size for p in files)
    return f"{len(files)} cached feed(s), {total / 1024:.0f} KiB"


# ---------------------------------------------------------------------------
# Which checks a profile actually needs
# ---------------------------------------------------------------------------

# Keyed by `coldlight_assess.Profile.configured_stages`. A stage absent from a
# value's list is not an oversight: several stages are purely local, and saying
# so is more useful than leaving them out of the report.
STAGE_NEEDS: dict[str, tuple[str, ...]] = {
    "dependencies": ("OSV.dev (advisories)", "NVD (CVE records)",
                     "CISA KEV catalog", "EPSS (FIRST.org)",
                     "Exploit-DB index", "feed cache"),
    "sbom": ("OSV.dev (advisories)", "CISA KEV catalog", "feed cache"),
    "source code": (),
    "AI/ML systems": (),
    "git history": ("git",),
    "AI runtime behaviour": (),
    "email posture": ("DNS-over-HTTPS",),
    "awareness": ("sqlite3",),
    "detection artifacts": (),
}

# Run whatever the profile says: these underpin every command.
ALWAYS = ("Python", "tomllib", "ssl module", "TLS trust store")


def needed_checks(stages) -> set[str]:
    """Check names the given assessment stages depend on."""
    wanted = set(ALWAYS)
    for stage in stages:
        wanted.update(STAGE_NEEDS.get(stage, ()))
    return wanted


def local_stages(stages) -> list[str]:
    """Stages with no external dependency a preflight could check."""
    return [s for s in stages
            if s in STAGE_NEEDS and not STAGE_NEEDS[s]]


def failing_stages(result: DoctorResult, stages) -> list[tuple[str, str]]:
    """(stage, reason) for configured stages whose dependencies are broken.

    The inverse of STAGE_NEEDS. `assess` thinks in stages, so a preflight that
    reported broken commands would leave the operator to do this mapping in
    their head.
    """
    broken = {c.name: (c.detail or c.name)
              for c in result.checks if c.blocking}
    out: list[tuple[str, str]] = []
    for stage in stages:
        for need in STAGE_NEEDS.get(stage, ()):
            if need in broken:
                out.append((stage, f"{need}: {broken[need]}"))
                break
    return out


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def local_checks() -> list[Check]:
    return [
        check_python(),
        check_tomllib(),
        check_ssl(),
        check_sqlite(),
        check_ca_bundle(),
        check_certifi(),
        check_git(),
        check_gpg(),
        check_openssl_tool(),
        check_signtool(),
        check_pyinstaller(),
        check_qrcode(),
        check_cache_dir(),
    ]


def network_checks(*, timeout: int = DEFAULT_TIMEOUT,
                   workers: int = DEFAULT_WORKERS,
                   reach=None, resolve=None) -> list[Check]:
    """Probe every external service, in parallel.

    Order is restored afterwards so two runs of the same machine produce the
    same report -- a diffable artifact beats a marginally faster one.
    """
    jobs: list = [
        (endpoint.name,
         lambda e=endpoint: check_endpoint(e, timeout=timeout, reach=reach))
        for endpoint in _endpoints()
    ]
    jobs.append(("DNS-over-HTTPS", lambda: check_doh(resolve=resolve)))

    results: dict[str, Check] = {}
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {pool.submit(fn): name for name, fn in jobs}
        for future in futures:
            name = futures[future]
            try:
                results[name] = future.result()
            except Exception as exc:  # noqa: BLE001 - a probe never raises
                results[name] = Check(
                    name=name, group=GROUP_NETWORK, status=STATUS_FAILED,
                    detail=f"the check itself failed: "
                           f"{type(exc).__name__}: {exc}")
    return [results[name] for name, _ in jobs if name in results]


def skipped_network_checks(reason: str) -> list[Check]:
    """Placeholders so the report still lists what was NOT looked at."""
    try:
        endpoints = _endpoints()
    except ImportError:
        # Reached when this Python has no `ssl`: the modules that own the URLs
        # cannot even be imported, so name the services generically rather
        # than hard-coding a second copy of the table.
        return [Check(name="external services", group=GROUP_NETWORK,
                      status=STATUS_SKIPPED, detail=reason,
                      affects=("cve", "vulns", "kev", "scan deps",
                               "scan sbom", "mail audit"))]

    checks = [
        Check(name=endpoint.name, group=GROUP_NETWORK, status=STATUS_SKIPPED,
              detail=reason, affects=endpoint.affects)
        for endpoint in endpoints
    ]
    checks.append(Check(name="DNS-over-HTTPS", group=GROUP_NETWORK,
                        status=STATUS_SKIPPED, detail=reason,
                        affects=("mail audit",)))
    return checks


def run(*, offline: bool = False, timeout: int = DEFAULT_TIMEOUT,
        workers: int = DEFAULT_WORKERS, stages=None, profile: str = "",
        reach=None, resolve=None) -> DoctorResult:
    """Check this machine. Never raises: a broken check is a finding."""
    started = time.monotonic()
    checks = local_checks()

    no_tls = any(c.name == "ssl module" and c.blocking for c in checks)
    if offline:
        checks += skipped_network_checks("not checked (--offline)")
    elif no_tls:
        checks += skipped_network_checks(
            "not checked: this Python has no ssl module, so nothing can be "
            "reached over TLS")
    else:
        checks += network_checks(timeout=timeout, workers=workers,
                                 reach=reach, resolve=resolve)

    stage_list = list(stages or [])
    if stage_list:
        wanted = needed_checks(stage_list)
        checks = [c for c in checks if c.name in wanted]

    return DoctorResult(checks=checks, offline=offline, profile=profile,
                        profile_stages=stage_list,
                        duration_s=round(time.monotonic() - started, 2))


def stages_for_profile(path: str | Path) -> tuple[list[str], str]:
    """The stages an assessment profile configures, for a narrowed run."""
    import coldlight_assess as ra

    try:
        profile = ra.load_profile(path)
    except ra.AssessError as exc:
        raise DoctorError(str(exc)) from exc
    except OSError as exc:
        raise DoctorError(f"cannot read {path}: {exc.strerror or exc}") from exc
    return profile.configured_stages, str(path)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def _summary_line(result: DoctorResult) -> str:
    counts = result.counts
    parts = []
    for status in (STATUS_OK, STATUS_DEGRADED, STATUS_MISSING, STATUS_FAILED,
                   STATUS_SKIPPED):
        if counts.get(status):
            label = {STATUS_OK: "ok", STATUS_DEGRADED: "degraded",
                     STATUS_MISSING: "unavailable", STATUS_FAILED: "failed",
                     STATUS_SKIPPED: "not checked"}[status]
            parts.append(f"{counts[status]} {label}")
    return ", ".join(parts) + f"  ({result.duration_s}s)"


_HEADER_WIDTH = 16


def text_report(result: DoctorResult) -> str:
    out: list[str] = []
    out.append("=" * 70)
    out.append("ColdLight preflight")
    out.append("=" * 70)
    # Padded, not hand-spaced: hand-spacing went crooked the moment the
    # tool's own name changed length.
    def row(label: str, value: str) -> str:
        return f"{label.ljust(_HEADER_WIDTH)}: {value}"

    out.append(row("coldlight", __version__))
    out.append(row("python", f"{sys.version.split()[0]} ({sys.executable})"))
    out.append(row("platform", platform.platform()))

    if result.profile:
        out.append(row("profile", result.profile))
        stages = ", ".join(result.profile_stages) or "none configured"
        out.append(row("stages", stages))
        out.append("")
        out.append("Checking only what this profile needs.")

    out.append("")
    out.append(_summary_line(result))

    width = max((len(c.name) for c in result.checks), default=10)
    for group in GROUP_ORDER:
        checks = result.by_group(group)
        if not checks:
            continue
        out.append("")
        out.append(f"{group}")
        out.append("-" * 70)
        for check in checks:
            label = STATUS_LABEL.get(check.status, check.status)
            out.append(f"  {check.name.ljust(width)}  {label.ljust(12)} "
                       f"{check.detail}")
            if check.remedy and check.status != STATUS_OK:
                out.append(f"  {' ' * width}  {'':12} -> {check.remedy}")

    unavailable = result.unavailable
    if unavailable:
        out.append("")
        out.append("Commands that will not work on this machine")
        out.append("-" * 70)
        command_width = max(len(c) for c, _ in unavailable)
        for command, reason in unavailable:
            out.append(f"  {command.ljust(command_width)}   {reason}")

    if result.profile_stages:
        local = local_stages(result.profile_stages)
        if local:
            out.append("")
            out.append("Stages with no external dependency: "
                       + ", ".join(local))

    unchecked = result.unchecked
    if unchecked:
        out.append("")
        out.append(f"NOT CHECKED ({len(unchecked)}): "
                   + ", ".join(c.name for c in unchecked))
        out.append("  Nothing was learned about these. A clean report above "
                   "does not cover them.")

    out.append("")
    if result.fatal_checks:
        out.append("ColdLight cannot run on this machine.")
        for check in result.fatal_checks:
            out.append(f"  {check.name}: {check.detail}")
    elif unavailable:
        count = len(unavailable)
        noun = "command" if count == 1 else "commands"
        out.append(f"ColdLight runs here, but the {count} {noun} listed above "
                   "will not.")
    elif result.healthy and not unchecked:
        out.append("Every dependency checked out.")
    elif result.healthy:
        out.append("Everything that was checked is healthy. See NOT CHECKED "
                   "above for what was not.")
    else:
        out.append("Every command is available; see the caveats above.")

    return "\n".join(out)


def json_report(result: DoctorResult) -> dict:
    return {
        "tool": "coldlight-doctor",
        "coldlight_version": __version__,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "python": {
            "version": sys.version.split()[0],
            "executable": sys.executable,
            "implementation": platform.python_implementation(),
        },
        "platform": platform.platform(),
        "offline": result.offline,
        "profile": result.profile,
        "profile_stages": result.profile_stages,
        "duration_s": result.duration_s,
        "exit_code": result.exit_code,
        "healthy": result.healthy,
        "counts": result.counts,
        "unavailable_commands": [
            {"command": command, "reason": reason}
            for command, reason in result.unavailable
        ],
        "not_checked": [c.name for c in result.unchecked],
        "checks": [c.to_dict() for c in result.checks],
    }


def preflight_lines(result: DoctorResult) -> list[str]:
    """A few lines for the start of an `assess` run.

    Short on purpose: the point is to name what will fail before ten minutes
    of scanning, not to reproduce the full report.
    """
    lines: list[str] = []
    problems = [c for c in result.checks
                if c.status in (STATUS_FAILED, STATUS_MISSING,
                                STATUS_DEGRADED)]

    if not problems:
        lines.append(f"preflight: {len(result.checks)} dependencies checked, "
                     "all healthy")
        return lines

    for check in sorted(problems, key=lambda c: -STATUS_ORDER.get(c.status, 0)):
        label = STATUS_LABEL.get(check.status, check.status)
        lines.append(f"preflight: {check.name} {label} -- {check.detail}")

    doomed = failing_stages(result, result.profile_stages)
    if doomed:
        lines.append("preflight: these stages will fail: "
                     + ", ".join(sorted({stage for stage, _ in doomed})))
        lines.append("preflight: running anyway -- a failed stage is reported "
                     "as FAILED, never as clean")
    return lines
