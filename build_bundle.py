#!/usr/bin/env python3
"""
Build a single-file, dependency-free ColdLight you can drop on any box.

    python build_bundle.py                    # -> dist/coldlight-standalone.py
    python build_bundle.py --out /tmp/ro.py
    python build_bundle.py --verify           # build, then prove it round-trips

The output is one .py that needs nothing but Python 3.11+: no pip, no venv, no
site-packages. Useful when you are handed a jump box and told "assess this".

HOW IT WORKS: every module is zlib-compressed and base64-encoded into a dict,
and a meta-path finder serves those sources to the import system on demand. So
imports inside the bundled code (`import coldlight_config`,
`import coldlight_report as rr`) resolve exactly as they do from real files, with
no rewriting of the sources and no dependency on load order.

WHY base64 RATHER THAN INLINING THE SOURCE AS TEXT: these modules are full of
regexes and Windows paths. Any text-embedding scheme has to escape them, and a
bundler that silently mangles one backslash produces a scanner whose rules
quietly match nothing -- a corrupted security tool that still reports "clean".
Compressed base64 cannot corrupt the payload, and `--verify` proves extraction
is byte-identical to the sources the test suite ran against.

The campaign templates are embedded too, so `new` and `build` work from the
standalone file (an installed wheel cannot do that -- see README).

This script is a development tool; it is not shipped in the package.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import shutil
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent

# Order is irrelevant at runtime (imports are lazy), but a stable list keeps
# the generated file diffable.
MODULES = [
    "coldlight",
    "coldlight_aisec",
    "coldlight_doctor",
    "coldlight_trust",
    "coldlight_scope",
    "coldlight_canary",
    "coldlight_history",
    "coldlight_assess",
    "coldlight_assurance",
    "coldlight_attest",
    "coldlight_awareness",
    "coldlight_baseline",
    "coldlight_codescan",
    "coldlight_collector",
    "coldlight_config",
    "coldlight_cwe",
    "coldlight_exploitintel",
    "coldlight_detect",
    "coldlight_ioc",
    "coldlight_engagement",
    "coldlight_mail",
    "coldlight_qr",
    "coldlight_report",
    "coldlight_safelist",
    "coldlight_sbom",
    "coldlight_sign",
    "coldlight_stix",
    "coldlight_vex",
    "coldlight_vulnintel",
]

# Non-module files the CLI needs on disk for `new` and `build`.
ASSETS = ["campaign.toml", "awareness_message.html"]

DEFAULT_OUT = HERE / "dist" / "coldlight-standalone.py"


def _encode(data: bytes) -> str:
    return base64.b64encode(zlib.compress(data, 9)).decode("ascii")


def _chunk(text: str, width: int = 96) -> list[str]:
    return [text[i:i + width] for i in range(0, len(text), width)]


STUB = '''#!/usr/bin/env python3
"""
ColdLight {version} -- single-file build.

A benign security assessment framework: awareness testing, vulnerability and
SBOM scanning, email authentication posture, purple-team validation, VEX and
reporting. Everything identifies and reports; nothing exploits.

Needs only Python 3.11+. No pip, no venv, no dependencies.

    python coldlight-standalone.py --help
    python coldlight-standalone.py scan code .
    python coldlight-standalone.py mail audit example.com

Generated from {count} modules by build_bundle.py. The original sources are
embedded verbatim (zlib + base64) and can be written back out for audit:

    python coldlight-standalone.py --extract ./coldlight-src

Source SHA-256 (the concatenated modules this was built from):
{digest}
"""

import base64
import importlib.util
import sys
import zlib
from pathlib import Path

if sys.version_info < (3, 11):
    sys.exit("ColdLight needs Python 3.11 or newer (it uses stdlib tomllib).")

__version__ = "{version}"
_BUNDLE_DIGEST = "{digest}"

# ---------------------------------------------------------------------------
# Embedded sources: name -> zlib+base64 of the original file bytes
# ---------------------------------------------------------------------------

_SOURCES = {{
{sources}
}}

_ASSETS = {{
{assets}
}}


def _blob(table, name):
    return zlib.decompress(base64.b64decode("".join(table[name])))


# ---------------------------------------------------------------------------
# Serve the embedded sources to the import system, on demand
# ---------------------------------------------------------------------------

class _BundleLoader:
    """Executes an embedded module's source into a real module object."""

    def __init__(self, name):
        self.name = name

    def create_module(self, spec):
        return None                      # use the default module object

    def exec_module(self, module):
        source = _blob(_SOURCES, self.name)
        filename = f"<coldlight-standalone:{{self.name}}.py>"
        module.__file__ = filename
        # nosec - This exec IS the bundler: it runs ColdLight' own embedded
        # modules, which is inherent to any single-file build. The source is
        # not external input -- it is baked in at build time and verified
        # byte-identical against the repository (build_bundle.py --verify).
        # Extract and read it yourself with: --extract <dir>
        exec(compile(source, filename, "exec"), module.__dict__)  # nosec


class _BundleFinder:
    """Meta-path finder: resolves `import coldlight_*` from the bundle.

    Lazy, so load order does not matter and a module nobody imports is never
    decompressed.
    """

    def find_spec(self, fullname, path=None, target=None):
        if fullname in _SOURCES:
            return importlib.util.spec_from_loader(
                fullname, _BundleLoader(fullname))
        return None


sys.meta_path.insert(0, _BundleFinder())


# ---------------------------------------------------------------------------
# Audit / asset support
# ---------------------------------------------------------------------------

def _extract(destination):
    """Write every embedded source and asset back out, verbatim."""
    out = Path(destination)
    out.mkdir(parents=True, exist_ok=True)
    written = []
    for name in sorted(_SOURCES):
        path = out / f"{{name}}.py"
        path.write_bytes(_blob(_SOURCES, name))
        written.append(path)
    for name in sorted(_ASSETS):
        path = out / name
        path.write_bytes(_blob(_ASSETS, name))
        written.append(path)
    return written


def _materialise_assets():
    """`new` and `build` read templates from disk, so put them somewhere real.

    Only called for those two commands -- a scan should not write anything.
    Output still goes to the current directory, not here.
    """
    import tempfile

    assets = Path(tempfile.gettempdir()) / f"coldlight-assets-{{_BUNDLE_DIGEST[:12]}}"
    assets.mkdir(parents=True, exist_ok=True)
    for name in _ASSETS:
        target = assets / name
        if not target.is_file():
            target.write_bytes(_blob(_ASSETS, name))
    # The payload and its shared config must be real files for PyInstaller.
    for name in ("coldlight_awareness", "coldlight_config"):
        target = assets / f"{{name}}.py"
        if not target.is_file():
            target.write_bytes(_blob(_SOURCES, name))
    return assets


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)

    if argv and argv[0] == "--extract":
        if len(argv) < 2:
            print("usage: --extract <directory>")
            return 2
        for path in _extract(argv[1]):
            print(path)
        print(f"\\n{{len(_SOURCES)}} module(s) and {{len(_ASSETS)}} asset(s) "
              f"extracted verbatim.")
        return 0

    import coldlight as _cli

    if argv and argv[0] in ("new", "build"):
        assets = _materialise_assets()
        # Templates come from the bundle; output goes to the working directory.
        _cli.HERE = Path.cwd()
        _cli.CAMPAIGN_TEMPLATE = assets / "campaign.toml"
        _cli.TRAINING_SRC = assets / "awareness_message.html"
        _cli.PAYLOAD_SRC = assets / "coldlight_awareness.py"
        _cli.CONFIG_SRC = assets / "coldlight_config.py"

    return _cli.main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
'''


def read_sources() -> tuple[dict[str, bytes], dict[str, bytes]]:
    modules: dict[str, bytes] = {}
    for name in MODULES:
        path = HERE / f"{name}.py"
        if not path.is_file():
            raise SystemExit(f"error: missing module {path}")
        modules[name] = path.read_bytes()

    assets: dict[str, bytes] = {}
    for name in ASSETS:
        path = HERE / name
        if not path.is_file():
            raise SystemExit(f"error: missing asset {path}")
        assets[name] = path.read_bytes()
    return modules, assets


def source_digest(modules: dict[str, bytes]) -> str:
    """A digest over the exact module bytes that went in."""
    digest = hashlib.sha256()
    for name in sorted(modules):
        digest.update(name.encode("utf-8"))
        digest.update(modules[name])
    return digest.hexdigest()


def render_table(table: dict[str, bytes], indent: str = "    ") -> str:
    lines: list[str] = []
    for name in sorted(table):
        chunks = _chunk(_encode(table[name]))
        lines.append(f'{indent}"{name}": [')
        for chunk in chunks:
            lines.append(f'{indent}    "{chunk}",')
        lines.append(f"{indent}],")
    return "\n".join(lines)


def detected_version() -> str:
    sys.path.insert(0, str(HERE))
    try:
        from coldlight_config import __version__
        return __version__
    finally:
        sys.path.pop(0)


def build(out_path: Path) -> Path:
    modules, assets = read_sources()
    digest = source_digest(modules)

    bundle = STUB.format(
        version=detected_version(),
        count=len(modules),
        digest=digest,
        sources=render_table(modules),
        assets=render_table(assets),
    )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(bundle, encoding="utf-8", newline="\n")
    return out_path


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def verify(bundle_path: Path) -> int:
    """Prove the bundle contains exactly the code the tests ran against."""
    modules, assets = read_sources()
    failures: list[str] = []

    with tempfile.TemporaryDirectory(prefix="coldlight_bundle_") as tmp:
        work = Path(tmp)
        extract_dir = work / "extracted"

        result = subprocess.run(
            [sys.executable, str(bundle_path), "--extract", str(extract_dir)],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            print(result.stdout, result.stderr)
            return 1

        # 1. byte-identical round trip
        for name, original in modules.items():
            produced = (extract_dir / f"{name}.py").read_bytes()
            if produced != original:
                failures.append(f"{name}.py differs after round-trip")
        for name, original in assets.items():
            produced = (extract_dir / name).read_bytes()
            if produced != original:
                failures.append(f"{name} differs after round-trip")

        print(f"[1/3] round-trip: "
              f"{len(modules)} module(s) + {len(assets)} asset(s) "
              f"{'OK -- byte-identical' if not failures else 'FAILED'}")
        if failures:
            for item in failures:
                print(f"      {item}")
            return 1

        # 2. the extracted sources pass the whole suite
        shutil.copytree(HERE / "tests", extract_dir / "tests")
        suite = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "--rootdir", str(extract_dir),
             "-p", "no:cacheprovider", str(extract_dir / "tests")],
            capture_output=True, text=True, cwd=str(extract_dir),
        )
        tail = [ln for ln in suite.stdout.strip().splitlines() if ln.strip()]
        print(f"[2/3] test suite against extracted sources: "
              f"{tail[-1] if tail else 'no output'}")
        if suite.returncode != 0:
            print(suite.stdout[-3000:])
            print(suite.stderr[-2000:])
            return 1

        # 3. the single file actually runs
        checks = [
            (["--version"], "ColdLight"),
            (["scan", "code", str(work)], "files scanned"),
            (["detect", "map"], "T1091"),
        ]
        for argv, expected in checks:
            run = subprocess.run(
                [sys.executable, str(bundle_path), *argv],
                capture_output=True, text=True, cwd=str(work),
            )
            if run.returncode != 0 or expected not in run.stdout:
                print(f"[3/3] FAILED: {' '.join(argv)}")
                print(run.stdout[-1500:], run.stderr[-1500:])
                return 1
        print(f"[3/3] CLI smoke tests: {len(checks)} passed")

    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Build a single-file, dependency-free ColdLight.")
    parser.add_argument("--out", default=str(DEFAULT_OUT),
                        help=f"output path (default: {DEFAULT_OUT})")
    parser.add_argument("--verify", action="store_true",
                        help="after building, prove the bundle round-trips "
                             "byte-identically and passes the test suite")
    args = parser.parse_args(argv)

    out_path = build(Path(args.out))
    size = out_path.stat().st_size
    print(f"Built {out_path}  ({size / 1024:.0f} KiB, "
          f"{len(MODULES)} modules + {len(ASSETS)} assets)")

    if args.verify:
        print()
        return verify(out_path)

    print("Run with --verify to prove it round-trips and passes the suite.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
