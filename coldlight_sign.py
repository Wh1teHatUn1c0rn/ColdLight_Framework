#!/usr/bin/env python3
"""
Authenticode code-signing helper for the built payload exe (Windows).

An unsigned PyInstaller exe trips SmartScreen/AV, which confounds "did the person
run it" with "did their AV catch it". Signing with your org's code-signing cert
makes the binary trusted — this is signing for *trust*, not evasion.

Usage:
    # cert in the Windows store (no password on the command line):
    python coldlight.py sign dist\\coldlight_awareness.exe --thumbprint <SHA1>

    # PFX file, password read from an env var (never passed on the CLI):
    set COLDLIGHT_PFX_PASS=...   &  python coldlight.py sign dist\\coldlight_awareness.exe \\
        --pfx mycert.pfx --password-env COLDLIGHT_PFX_PASS

    # preview the exact signtool command without running it:
    python coldlight.py sign dist\\coldlight_awareness.exe --thumbprint <SHA1> --dry-run

Requires `signtool.exe` from the Windows SDK (auto-located, or pass --signtool).
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
from pathlib import Path

DEFAULT_TIMESTAMP_URL = "http://timestamp.digicert.com"


def find_signtool() -> str | None:
    """Locate signtool.exe on PATH or in a Windows 10/11 SDK bin directory."""
    found = shutil.which("signtool") or shutil.which("signtool.exe")
    if found:
        return found

    bases = [
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Windows Kits" / "10" / "bin",
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Windows Kits" / "10" / "bin",
    ]
    candidates: list[Path] = []
    for base in bases:
        if base.is_dir():
            candidates += list(base.glob("*/x64/signtool.exe"))
            candidates += list(base.glob("x64/signtool.exe"))
    candidates.sort()  # highest SDK version last
    return str(candidates[-1]) if candidates else None


def build_signtool_cmd(signtool: str, exe: str | Path, *, pfx: str | None = None,
                       password: str | None = None, thumbprint: str | None = None,
                       timestamp_url: str = DEFAULT_TIMESTAMP_URL) -> list[str]:
    """Assemble the signtool argv. Requires a PFX or a store thumbprint."""
    if not pfx and not thumbprint:
        raise ValueError("provide either a PFX file (pfx=) or a cert thumbprint (thumbprint=)")
    cmd = [signtool, "sign", "/fd", "SHA256", "/tr", timestamp_url, "/td", "SHA256"]
    if pfx:
        cmd += ["/f", str(pfx)]
        if password:
            cmd += ["/p", password]
    if thumbprint:
        cmd += ["/sha1", thumbprint]
    cmd.append(str(exe))
    return cmd


def build_verify_cmd(signtool: str, exe: str | Path) -> list[str]:
    return [signtool, "verify", "/pa", str(exe)]


def _redacted(cmd: list[str]) -> str:
    disp = list(cmd)
    if "/p" in disp:
        disp[disp.index("/p") + 1] = "***"
    return " ".join(disp)


def sign(exe: str | Path, *, pfx: str | None = None, password: str | None = None,
         thumbprint: str | None = None, timestamp_url: str = DEFAULT_TIMESTAMP_URL,
         verify: bool = True, dry_run: bool = False, signtool: str | None = None) -> int:
    exe = Path(exe)
    if not exe.is_file():
        raise SystemExit(f"exe not found: {exe}")

    tool = signtool or find_signtool()
    if not tool:
        raise SystemExit("signtool.exe not found. Install the Windows SDK, or pass --signtool PATH.")

    cmd = build_signtool_cmd(tool, exe, pfx=pfx, password=password,
                             thumbprint=thumbprint, timestamp_url=timestamp_url)
    print("->", _redacted(cmd))
    if dry_run:
        print("[dry-run] not executing.")
        return 0

    rc = subprocess.run(cmd).returncode
    if rc != 0:
        print("signing failed.")
        return rc
    if verify:
        vcmd = build_verify_cmd(tool, exe)
        print("->", " ".join(vcmd))
        subprocess.run(vcmd)
    print("signed OK.")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Authenticode-sign the ColdLight payload exe.")
    ap.add_argument("exe")
    ap.add_argument("--pfx", help="path to a .pfx/.p12 code-signing certificate")
    ap.add_argument("--password-env",
                    help="name of an env var holding the PFX password (not the password itself)")
    ap.add_argument("--thumbprint", help="SHA1 thumbprint of a cert in the Windows store")
    ap.add_argument("--timestamp-url", default=DEFAULT_TIMESTAMP_URL)
    ap.add_argument("--no-verify", action="store_true")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the signtool command without running it")
    ap.add_argument("--signtool", help="explicit path to signtool.exe")
    args = ap.parse_args(argv)

    password = os.environ.get(args.password_env) if args.password_env else None
    return sign(args.exe, pfx=args.pfx, password=password, thumbprint=args.thumbprint,
                timestamp_url=args.timestamp_url, verify=not args.no_verify,
                dry_run=args.dry_run, signtool=args.signtool)


if __name__ == "__main__":
    raise SystemExit(main())
