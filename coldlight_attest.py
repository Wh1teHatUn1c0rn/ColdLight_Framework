#!/usr/bin/env python3
"""
ColdLight attestation: make an assessment report verifiable.

A pentest report today is a PDF emailed around with no integrity whatsoever.
Nothing stops a finding being deleted between the assessor sending it and the
board reading it, and nothing records which tool and which inputs produced it.

This emits an in-toto Statement binding the report to:
  * the SHA-256 of every report file (the subjects),
  * the SHA-256 of every scan artifact behind it (the inputs),
  * the ASSURANCE LEDGER -- so the attestation covers SCOPE, not just content.

That last part is the point. Signing "here are 17 findings" is near-worthless
if nobody can tell whether 17 came from assessing everything or from assessing
one directory. The statement records which check classes were examined, which
were only partial, and which nobody looked at -- so a recipient can verify the
claim *and* its limits.

NO CRYPTOGRAPHY IS IMPLEMENTED HERE. Hand-rolled signature code is how a tool
ends up looking verified while being forgeable. ColdLight canonicalises the
document and hashes files with stdlib `hashlib`; signing and signature
verification are delegated to established tooling (GnuPG, OpenSSL). Private
key material is never read, held or logged by this module -- only a key
identifier or path is passed through, and passphrases are left to the external
tool's own prompt or an environment variable it reads itself.

TRUST MODEL, stated plainly because an unverifiable signature is worse than
none: a detached signature only means something if the recipient already has
your public key through a channel they trust. ColdLight does not distribute keys
and cannot establish that trust for you.

Stdlib only.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://coldlight.invalid/attestation/assessment/v1"

ATTESTATION_NAME = "attestation.json"

# Files treated as the thing being attested TO, rather than evidence for it.
SUBJECT_NAMES = ("report.html", "report.md", "report.json")

# Artifacts recorded as inputs. Anything else in the directory is ignored.
INPUT_GLOBS = ("deps*.json", "sbom*.json", "code*.json", "mail*.json",
               "run.json", "assurance.json", "assurance.md",
               "attack_layer.json", "blue_team_checklist.md",
               "sigma/*.yml")

BACKEND_GPG = "gpg"
BACKEND_OPENSSL = "openssl"
BACKEND_HMAC = "hmac"
BACKENDS = (BACKEND_GPG, BACKEND_OPENSSL, BACKEND_HMAC)


class AttestError(RuntimeError):
    """The attestation could not be produced or verified."""


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Hashing and canonical serialisation
# ---------------------------------------------------------------------------

def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def serialise(statement: dict) -> bytes:
    """Deterministic bytes for the statement.

    Sorted keys and a fixed separator, so re-serialising the same statement
    always yields identical bytes. Readable indentation is kept deliberately:
    this is a document a recipient may want to inspect, and the signature
    covers the file exactly as written.
    """
    text = json.dumps(statement, indent=2, sort_keys=True,
                      ensure_ascii=False) + "\n"
    return text.encode("utf-8")


# ---------------------------------------------------------------------------
# Building the statement
# ---------------------------------------------------------------------------

def _tool_source_digest() -> str:
    """SHA-256 over ColdLight' own modules, when running from a checkout.

    Ties the report to the exact code that produced it. Best-effort: an
    installed wheel or the single-file build may not expose the sources here.
    """
    here = Path(__file__).resolve().parent
    modules = sorted(here.glob("coldlight*.py"))
    if not modules:
        return ""
    digest = hashlib.sha256()
    for path in modules:
        digest.update(path.name.encode("utf-8"))
        digest.update(path.read_bytes())
    return digest.hexdigest()


def _digest_entry(path: Path, root: Path) -> dict:
    return {
        "name": path.relative_to(root).as_posix(),
        "digest": {"sha256": sha256_file(path)},
        "bytes": path.stat().st_size,
    }


def _assurance_summary(out_dir: Path) -> dict:
    """The coverage claim, so the attestation covers scope and not just text."""
    path = out_dir / "assurance.json"
    if not path.is_file():
        return {"present": False,
                "note": "no assurance ledger: the scope of this assessment is "
                        "not attested"}
    try:
        ledger = json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        return {"present": False, "note": "assurance ledger unreadable"}

    return {
        "present": True,
        "classesExamined": ledger.get("classes_examined"),
        "classesInToolScope": ledger.get("classes_in_tool_scope"),
        "classesTotal": ledger.get("classes_total"),
        "unitsChecked": ledger.get("units_checked"),
        "unitsTotal": ledger.get("units_total"),
        "unexamined": ledger.get("unexamined") or [],
        "failed": ledger.get("failed") or [],
    }


def _findings_summary(out_dir: Path) -> dict:
    path = out_dir / "report.json"
    if not path.is_file():
        return {}
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        return {}
    return {
        "total": report.get("finding_count"),
        "rawItems": report.get("raw_item_count"),
        "knownExploited": report.get("known_exploited"),
        "bySeverity": report.get("severity_counts") or {},
    }


def _run_summary(out_dir: Path) -> dict:
    path = out_dir / "run.json"
    if not path.is_file():
        return {}
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        return {}
    return {
        "exitCode": manifest.get("exit_code"),
        "incomplete": manifest.get("incomplete"),
        "stagesOk": manifest.get("stages_ok"),
        "stagesFailed": manifest.get("stages_failed"),
    }


def build_statement(out_dir: str | Path, *, engagement: dict | None = None,
                    tool_version: str = "") -> dict:
    """Build the in-toto Statement for an assessment output directory."""
    directory = Path(out_dir)
    if not directory.is_dir():
        raise AttestError(f"no such directory: {directory}")

    subjects = [
        _digest_entry(directory / name, directory)
        for name in SUBJECT_NAMES
        if (directory / name).is_file()
    ]
    if not subjects:
        raise AttestError(
            f"{directory} contains no report to attest to "
            f"(looked for: {', '.join(SUBJECT_NAMES)})"
        )

    seen: set[Path] = {directory / n for n in SUBJECT_NAMES}
    inputs: list[dict] = []
    for pattern in INPUT_GLOBS:
        for path in sorted(directory.glob(pattern)):
            if path.is_file() and path not in seen and path.name != ATTESTATION_NAME:
                seen.add(path)
                inputs.append(_digest_entry(path, directory))

    if not tool_version:
        try:
            from coldlight_config import __version__
            tool_version = __version__
        except Exception:  # noqa: BLE001
            tool_version = "unknown"

    predicate = {
        "generatedAt": _now(),
        "tool": {
            "name": "ColdLight",
            "version": tool_version,
            "sourceDigest": _tool_source_digest(),
        },
        "assurance": _assurance_summary(directory),
        "findings": _findings_summary(directory),
        "run": _run_summary(directory),
        "inputs": inputs,
        "disclaimer": (
            "Findings are based on identification, not exploitation. This "
            "attestation records what was assessed and what was not; a check "
            "class listed under assurance.unexamined was NOT assessed and is "
            "unknown rather than clean."
        ),
    }
    if engagement:
        predicate["engagement"] = engagement

    return {
        "_type": STATEMENT_TYPE,
        "subject": subjects,
        "predicateType": PREDICATE_TYPE,
        "predicate": predicate,
    }


def write_statement(statement: dict, out_dir: str | Path) -> Path:
    path = Path(out_dir) / ATTESTATION_NAME
    path.write_bytes(serialise(statement))
    return path


# ---------------------------------------------------------------------------
# Signing -- delegated, never implemented here
# ---------------------------------------------------------------------------

@dataclass
class SignResult:
    backend: str
    signature_path: str = ""
    command: list[str] = field(default_factory=list)
    detail: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _require(tool: str) -> str:
    path = shutil.which(tool)
    if not path:
        raise AttestError(
            f"{tool} is not on PATH. Install it, or choose another backend "
            f"({', '.join(BACKENDS)})."
        )
    return path


def gpg_sign_command(statement_path: Path, *, key: str = "") -> list[str]:
    """Detached, armoured signature. The passphrase is left to gpg-agent --
    never passed on the command line."""
    command = [_require("gpg"), "--batch", "--yes", "--armor",
               "--detach-sign", "--output", str(statement_path) + ".asc"]
    if key:
        command += ["--local-user", key]
    command.append(str(statement_path))
    return command


def openssl_sign_command(statement_path: Path, *, key: str,
                         passphrase_env: str = "") -> list[str]:
    if not key:
        raise AttestError("the openssl backend needs --key <private-key.pem>")
    command = [_require("openssl"), "dgst", "-sha256", "-sign", key,
               "-out", str(statement_path) + ".sig"]
    if passphrase_env:
        # openssl reads the variable itself; the value never passes through
        # our process arguments.
        command += ["-passin", f"env:{passphrase_env}"]
    command.append(str(statement_path))
    return command


def hmac_sign(statement_path: Path, *, key_env: str) -> str:
    """Symmetric MAC over the statement bytes.

    DELIBERATELY LIMITED: anyone who can verify this can also forge it, so it
    proves nothing to a third party. Useful only where one party checks its
    own artifact has not been altered in storage or transit.
    """
    secret = os.environ.get(key_env, "")
    if not secret:
        raise AttestError(
            f"environment variable {key_env} is unset or empty; the hmac "
            f"backend reads its key from the environment only"
        )
    digest = hmac.new(secret.encode("utf-8"),
                      statement_path.read_bytes(), hashlib.sha256)
    return digest.hexdigest()


def sign(statement_path: str | Path, backend: str, *, key: str = "",
         key_env: str = "", passphrase_env: str = "",
         dry_run: bool = False) -> SignResult:
    """Produce a signature for the statement, delegating to external tooling."""
    path = Path(statement_path)
    if not path.is_file():
        raise AttestError(f"no statement at {path}")

    if backend == BACKEND_HMAC:
        if dry_run:
            return SignResult(backend=backend,
                              detail=f"would HMAC-SHA256 using ${key_env}")
        mac = hmac_sign(path, key_env=key_env)
        signature_path = path.with_suffix(path.suffix + ".hmac")
        signature_path.write_text(
            json.dumps({"alg": "HMAC-SHA256", "value": mac,
                        "keyEnv": key_env,
                        "warning": "symmetric: verifiable only by a holder of "
                                   "the same secret, who could equally forge "
                                   "it"}, indent=2) + "\n",
            encoding="utf-8")
        return SignResult(backend=backend, signature_path=str(signature_path),
                          detail="symmetric MAC (not third-party verifiable)")

    if backend == BACKEND_GPG:
        command = gpg_sign_command(path, key=key)
        signature_path = str(path) + ".asc"
    elif backend == BACKEND_OPENSSL:
        command = openssl_sign_command(path, key=key,
                                       passphrase_env=passphrase_env)
        signature_path = str(path) + ".sig"
    else:
        raise AttestError(f"unknown backend {backend!r}; expected one of "
                          f"{', '.join(BACKENDS)}")

    if dry_run:
        return SignResult(backend=backend, command=command,
                          signature_path=signature_path,
                          detail="dry run: not executed")

    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        raise AttestError(
            f"{backend} signing failed (exit {result.returncode}): "
            f"{(result.stderr or result.stdout).strip()[:400]}"
        )
    return SignResult(backend=backend, command=command,
                      signature_path=signature_path,
                      detail="signed")


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

@dataclass
class VerifyResult:
    statement: str = ""
    digests_ok: bool = False
    checked: int = 0
    mismatched: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    signature_backend: str = ""
    signature_ok: bool | None = None       # None = no signature present
    signature_detail: str = ""
    assurance: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        if not self.digests_ok:
            return False
        return self.signature_ok is not False

    def to_dict(self) -> dict:
        return asdict(self)


def _verify_digests(statement: dict, directory: Path) -> VerifyResult:
    result = VerifyResult(statement=str(directory / ATTESTATION_NAME))
    entries = list(statement.get("subject") or [])
    entries += list((statement.get("predicate") or {}).get("inputs") or [])

    for entry in entries:
        name = entry.get("name", "")
        expected = (entry.get("digest") or {}).get("sha256", "")
        path = directory / name
        if not path.is_file():
            result.missing.append(name)
            continue
        result.checked += 1
        if sha256_file(path) != expected:
            result.mismatched.append(name)

    result.digests_ok = not result.mismatched and not result.missing
    return result


def _verify_signature(directory: Path, *, key: str = "",
                      key_env: str = "") -> tuple[str, bool | None, str]:
    statement_path = directory / ATTESTATION_NAME

    asc = Path(str(statement_path) + ".asc")
    if asc.is_file():
        gpg = shutil.which("gpg")
        if not gpg:
            return BACKEND_GPG, None, "gpg not on PATH; signature not checked"
        run = subprocess.run([gpg, "--verify", str(asc), str(statement_path)],
                             capture_output=True, text=True)
        detail = (run.stderr or run.stdout).strip().splitlines()
        return (BACKEND_GPG, run.returncode == 0,
                detail[-1] if detail else "")

    sig = Path(str(statement_path) + ".sig")
    if sig.is_file():
        openssl = shutil.which("openssl")
        if not openssl:
            return (BACKEND_OPENSSL, None,
                    "openssl not on PATH; signature not checked")
        if not key:
            return (BACKEND_OPENSSL, None,
                    "pass --key <public-key.pem> to verify this signature")
        run = subprocess.run(
            [openssl, "dgst", "-sha256", "-verify", key,
             "-signature", str(sig), str(statement_path)],
            capture_output=True, text=True)
        return (BACKEND_OPENSSL, run.returncode == 0,
                (run.stdout or run.stderr).strip()[:200])

    mac_path = Path(str(statement_path) + ".hmac")
    if mac_path.is_file():
        if not key_env:
            return (BACKEND_HMAC, None,
                    "pass --hmac-env <VAR> to verify this MAC")
        try:
            expected = json.loads(mac_path.read_text(encoding="utf-8"))
        except ValueError:
            return BACKEND_HMAC, False, "malformed MAC file"
        actual = hmac_sign(statement_path, key_env=key_env)
        matched = hmac.compare_digest(actual, str(expected.get("value", "")))
        return (BACKEND_HMAC, matched,
                "symmetric MAC: proves nothing to a third party")

    return "", None, "no signature file alongside the attestation"


def verify(out_dir: str | Path, *, key: str = "",
           key_env: str = "") -> VerifyResult:
    """Recompute every digest, then check the signature if one is present."""
    directory = Path(out_dir)
    statement_path = directory / ATTESTATION_NAME
    if not statement_path.is_file():
        raise AttestError(f"no attestation at {statement_path}")

    try:
        statement = json.loads(statement_path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise AttestError(f"{statement_path} is not valid JSON: {exc}") from exc

    result = _verify_digests(statement, directory)
    (result.signature_backend, result.signature_ok,
     result.signature_detail) = _verify_signature(directory, key=key,
                                                  key_env=key_env)
    result.assurance = ((statement.get("predicate") or {})
                        .get("assurance") or {})
    return result


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def verify_report(result: VerifyResult) -> str:
    out: list[str] = []
    out.append("=" * 68)
    out.append("Attestation verification")
    out.append("=" * 68)
    out.append(f"statement : {result.statement}")

    if result.digests_ok:
        out.append(f"contents  : OK — {result.checked} file(s) match their "
                   f"recorded digest")
    else:
        out.append(f"contents  : FAILED — {result.checked} file(s) checked")
        for name in result.mismatched:
            out.append(f"    ALTERED : {name}")
        for name in result.missing:
            out.append(f"    MISSING : {name}")

    if result.signature_ok is True:
        out.append(f"signature : OK ({result.signature_backend}) "
                   f"{result.signature_detail}")
    elif result.signature_ok is False:
        out.append(f"signature : FAILED ({result.signature_backend}) "
                   f"{result.signature_detail}")
    else:
        out.append(f"signature : not checked — {result.signature_detail}")

    assurance = result.assurance or {}
    if assurance.get("present"):
        unexamined = assurance.get("unexamined") or []
        out.append(
            f"scope     : {assurance.get('classesExamined')} of "
            f"{assurance.get('classesInToolScope')} class(es) examined"
            + (f"; NOT assessed: {', '.join(unexamined)}" if unexamined else "")
        )
    else:
        out.append("scope     : no assurance ledger — the breadth of this "
                   "assessment is not attested")

    out.append("")
    if result.ok and result.signature_ok is True:
        out.append("VERIFIED: contents match and the signature is valid.")
        out.append("Note: a valid signature only means something if you "
                   "obtained the signer's")
        out.append("public key through a channel you trust. ColdLight does not "
                   "establish that.")
    elif result.ok:
        out.append("CONTENTS OK, SIGNATURE UNVERIFIED — the files match the "
                   "attestation, but")
        out.append("nothing proves who produced it. Treat as unsigned.")
    else:
        out.append("VERIFICATION FAILED — do not rely on this report.")
    return "\n".join(out)
