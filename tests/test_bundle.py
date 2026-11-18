"""Tests for build_bundle.py (the single-file build).

The deep verification -- byte-identical extraction plus the whole suite run
against the extracted sources -- lives in `build_bundle.py --verify`, which CI
runs. These tests cover the encoding, the digest and the generated file's
validity cheaply enough to belong in the normal suite.
"""

import importlib.util
import zlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
BUNDLER = ROOT / "build_bundle.py"


@pytest.fixture(scope="module")
def bundler():
    if not BUNDLER.is_file():
        pytest.skip("build_bundle.py not present (not running from a checkout)")
    spec = importlib.util.spec_from_file_location("_bundler_under_test", BUNDLER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# Encoding: must be incapable of corrupting the payload
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("payload", [
    b"",
    b"plain ascii",
    # The cases a text-embedding bundler gets wrong:
    rb'_RE = re.compile(r"^[D-Z]:\\")',
    rb"path = 'C:\\Windows\\System32'",
    b'triple """ quotes \'\'\' both kinds',
    b"trailing backslash \\",
    b"null \x00 and \x01 control bytes",
    "unicode \u2014 em dash \u00e9\u00fc".encode("utf-8"),
    b"\r\n mixed \n line \r endings",
    b"%s %r {braces} {{doubled}}",
])
def test_encode_round_trips_exactly(bundler, payload):
    encoded = bundler._encode(payload)
    assert zlib.decompress(__import__("base64").b64decode(encoded)) == payload


def test_encode_output_is_safe_to_embed(bundler):
    """The encoded form must contain nothing that could break out of the
    string literal it is written into."""
    nasty = rb'''"""  \'\'\'  \\  {} %s '''
    encoded = bundler._encode(nasty)
    for forbidden in ('"', "'", "\\", "\n", "\r", "{", "}"):
        assert forbidden not in encoded


def test_chunking_preserves_content(bundler):
    text = "x" * 500
    chunks = bundler._chunk(text, 96)
    assert all(len(c) <= 96 for c in chunks)
    assert "".join(chunks) == text


def test_chunking_handles_short_and_empty(bundler):
    assert bundler._chunk("", 96) == []
    assert bundler._chunk("abc", 96) == ["abc"]


# ---------------------------------------------------------------------------
# Digest: identifies exactly what went in
# ---------------------------------------------------------------------------

def test_digest_is_stable(bundler):
    modules = {"a": b"one", "b": b"two"}
    assert bundler.source_digest(modules) == bundler.source_digest(dict(modules))


def test_digest_is_order_independent(bundler):
    assert (bundler.source_digest({"a": b"1", "b": b"2"})
            == bundler.source_digest({"b": b"2", "a": b"1"}))


def test_digest_changes_with_content(bundler):
    base = bundler.source_digest({"a": b"1"})
    assert bundler.source_digest({"a": b"2"}) != base


def test_digest_changes_when_a_module_is_renamed(bundler):
    """Renaming must change the digest, or the bundle could claim to be built
    from sources it was not."""
    assert (bundler.source_digest({"a": b"same"})
            != bundler.source_digest({"b": b"same"}))


# ---------------------------------------------------------------------------
# The generated file
# ---------------------------------------------------------------------------

def test_module_and_asset_lists_are_present_on_disk(bundler):
    for name in bundler.MODULES:
        assert (ROOT / f"{name}.py").is_file(), name
    for name in bundler.ASSETS:
        assert (ROOT / name).is_file(), name


def test_read_sources_collects_everything(bundler):
    modules, assets = bundler.read_sources()
    assert set(modules) == set(bundler.MODULES)
    assert set(assets) == set(bundler.ASSETS)
    assert all(data for data in modules.values())


def test_build_emits_valid_python(bundler, tmp_path):
    """A template typo would otherwise only surface when someone runs the
    bundle on a jump box."""
    out = bundler.build(tmp_path / "standalone.py")
    text = out.read_text(encoding="utf-8")
    compile(text, str(out), "exec")          # raises on any syntax error


def test_build_output_is_self_contained(bundler, tmp_path):
    text = bundler.build(tmp_path / "standalone.py").read_text(encoding="utf-8")
    # Only stdlib imports at the top level of the stub.
    assert "import base64" in text
    assert "import zlib" in text
    assert "importlib.util" in text
    # Every module must be embedded.
    for name in bundler.MODULES:
        assert f'"{name}": [' in text, name
    for name in bundler.ASSETS:
        assert f'"{name}": [' in text, name


def test_build_records_the_version_and_digest(bundler, tmp_path):
    from coldlight_config import __version__

    modules, _assets = bundler.read_sources()
    text = bundler.build(tmp_path / "standalone.py").read_text(encoding="utf-8")
    assert f'__version__ = "{__version__}"' in text
    assert bundler.source_digest(modules) in text


def test_build_guards_the_python_version(bundler, tmp_path):
    text = bundler.build(tmp_path / "standalone.py").read_text(encoding="utf-8")
    assert "sys.version_info < (3, 11)" in text


def test_build_documents_how_to_audit(bundler, tmp_path):
    text = bundler.build(tmp_path / "standalone.py").read_text(encoding="utf-8")
    assert "--extract" in text


def test_bundle_exec_is_suppressed_with_a_justification(bundler, tmp_path):
    """The loader's exec() is a true positive for our own scanner. It must
    carry a suppression AND an explanation, not be left as a mystery hit."""
    text = bundler.build(tmp_path / "standalone.py").read_text(encoding="utf-8")
    exec_lines = [ln for ln in text.splitlines()
                  if "exec(compile(" in ln and "nosec" in ln]
    assert exec_lines, "the bundler's exec should be suppressed explicitly"
    assert "inherent to any single-file build" in text


def test_bundle_is_not_absurdly_large(bundler, tmp_path):
    """It is meant to be dropped on a box; keep an eye on the size."""
    size = bundler.build(tmp_path / "standalone.py").stat().st_size
    assert size < 1_000_000, f"{size} bytes is larger than expected"


def test_missing_module_is_reported(bundler, monkeypatch):
    monkeypatch.setattr(bundler, "MODULES", bundler.MODULES + ["coldlight_ghost"])
    with pytest.raises(SystemExit, match="missing module"):
        bundler.read_sources()


def test_missing_asset_is_reported(bundler, monkeypatch):
    monkeypatch.setattr(bundler, "ASSETS", bundler.ASSETS + ["nope.html"])
    with pytest.raises(SystemExit, match="missing asset"):
        bundler.read_sources()
