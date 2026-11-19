"""CLI-level tests: exit codes and graceful failure.

These cover the paths that only break when the tool is run from somewhere
other than a checkout -- which is exactly how an installed wheel behaves.
"""

import pytest

import coldlight
from coldlight_config import __version__


def run(argv, capsys):
    """Invoke main() and return (exit_code, stdout)."""
    code = coldlight.main(argv)
    return code, capsys.readouterr().out


# ---------------------------------------------------------------------------
# Version / help
# ---------------------------------------------------------------------------

def test_version_flag_exits_zero(capsys):
    with pytest.raises(SystemExit) as exc:
        coldlight.main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def _pyproject():
    """The repo's packaging metadata, or skip.

    These two tests assert a property of the repository. They are skipped when
    the suite runs outside one -- which is exactly what happens against the
    sources extracted from the single-file build.
    """
    from pathlib import Path

    path = Path(__file__).resolve().parent.parent / "pyproject.toml"
    if not path.is_file():
        pytest.skip("no pyproject.toml: not running from a checkout")
    import tomllib
    return path.parent, tomllib.loads(path.read_text(encoding="utf-8"))


def test_version_matches_pyproject():
    """One source of truth: coldlight_config.__version__ and the packaging
    metadata must not drift apart."""
    _root, data = _pyproject()
    assert data["project"]["version"] == __version__


def test_every_declared_module_exists():
    """py-modules in pyproject must match the modules actually shipped, or the
    wheel silently omits one."""
    root, data = _pyproject()
    declared = set(data["tool"]["setuptools"]["py-modules"])
    on_disk = {p.stem for p in root.glob("coldlight*.py")}
    assert declared == on_disk, (
        f"missing from pyproject: {on_disk - declared}; "
        f"declared but absent: {declared - on_disk}"
    )


def test_bundle_module_list_matches_the_package():
    """build_bundle.py has its own module list; if it drifts from pyproject the
    single-file build silently omits a module."""
    root, data = _pyproject()
    bundler = root / "build_bundle.py"
    if not bundler.is_file():
        pytest.skip("build_bundle.py not present")

    import importlib.util

    spec = importlib.util.spec_from_file_location("_bundler", bundler)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    assert set(module.MODULES) == set(data["tool"]["setuptools"]["py-modules"])


def test_subcommand_required(capsys):
    with pytest.raises(SystemExit) as exc:
        coldlight.main([])
    assert exc.value.code != 0


# ---------------------------------------------------------------------------
# Missing campaign config -- must not traceback
# ---------------------------------------------------------------------------

def test_validate_without_a_config_fails_cleanly(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    code, out = run(["validate"], capsys)
    assert code == 2
    assert "no campaign config" in out
    assert "coldlight new" in out          # tells you what to do instead


def test_build_without_a_config_fails_cleanly(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    code, out = run(["build"], capsys)
    assert code == 2
    assert "no campaign config" in out


def test_validate_with_an_explicit_missing_path(tmp_path, capsys):
    code, out = run(["validate", str(tmp_path / "nope.toml")], capsys)
    assert code == 2
    assert "nope.toml" in out


def test_new_without_templates_fails_cleanly(tmp_path, monkeypatch, capsys):
    """An installed wheel has no campaign.toml beside the modules. Writing an
    empty config and reporting success would be worse than refusing."""
    monkeypatch.setattr(coldlight, "CAMPAIGN_TEMPLATE", tmp_path / "absent.toml")
    monkeypatch.setattr(coldlight, "HERE", tmp_path)

    code, out = run(["new", "some-campaign"], capsys)
    assert code == 2
    assert "template not found" in out
    assert "checkout" in out
    # And it must not have left a half-made directory behind.
    assert not (tmp_path / "campaigns" / "some-campaign").exists()


# ---------------------------------------------------------------------------
# Optional dependencies -- must explain, not traceback
# ---------------------------------------------------------------------------

def test_qr_without_qrcode_points_at_the_extra(monkeypatch, capsys):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "qrcode":
            raise ImportError("no qrcode")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    code, out = run(["qr", "--base-url", "https://x/land",
                     "--campaign", "E1"], capsys)
    assert code == 1
    assert 'pip install "coldlight[qr]"' in out


def test_build_without_pyinstaller_points_at_the_extra(tmp_path, monkeypatch,
                                                       capsys):
    import importlib.util

    config = tmp_path / "campaign.toml"
    config.write_text(
        '[campaign]\nengagement_id = "E1"\nauthorization_reference = "RoE"\n',
        encoding="utf-8")

    real_find_spec = importlib.util.find_spec
    monkeypatch.setattr(
        importlib.util, "find_spec",
        lambda name, *a, **k: (None if name == "PyInstaller"
                               else real_find_spec(name, *a, **k)))

    code, out = run(["build", str(config)], capsys)
    assert code == 1
    assert 'pip install "coldlight[build]"' in out


# ---------------------------------------------------------------------------
# Engagement with no inputs
# ---------------------------------------------------------------------------

def test_engagement_without_inputs_explains_itself(capsys):
    code, out = run(["engagement"], capsys)
    assert code == 1
    assert "no inputs given" in out
    assert "--vuln" in out and "--hits" in out


# ---------------------------------------------------------------------------
# Read-only commands run from anywhere (the installed-wheel case)
# ---------------------------------------------------------------------------

def test_scan_code_runs_outside_a_checkout(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "sample.py").write_text("import os\nos.system(x)\n",
                                        encoding="utf-8")
    code, out = run(["scan", "code", str(tmp_path)], capsys)
    assert code == 0
    assert "CMD-OS-SYSTEM" in out


def test_detect_map_runs_outside_a_checkout(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    code, out = run(["detect", "map"], capsys)
    assert code == 0
    assert "T1091" in out


def test_detect_validate_without_a_db_fails_cleanly(tmp_path, monkeypatch,
                                                    capsys):
    monkeypatch.chdir(tmp_path)
    code, out = run(["detect", "validate"], capsys)
    assert code == 1
    assert "no database" in out


def test_assess_refuses_half_a_configured_indicator_stage(tmp_path, capsys):
    """--ioc without --ioc-pack would scan a tree for nothing at all, and
    report the same 'no markers' as a scan that found none."""
    code, out = run(["assess", "--ioc", str(tmp_path), "--client", "Acme",
                     "--out-dir", str(tmp_path / "out"), "--no-preflight"],
                    capsys)
    assert code == 2
    assert "nothing would be looked for" in out


def _example_bundle_path():
    from pathlib import Path as _Path

    path = (_Path(__file__).resolve().parent.parent / "examples" / "ioc"
            / "example-bundle.json")
    if not path.is_file():
        pytest.skip("no examples/: not running from a checkout")
    return path


def test_ioc_import_writes_a_pack_and_loads_it_back(tmp_path, capsys):
    out = tmp_path / "pack.toml"
    code, printed = run(["ioc", "import", str(_example_bundle_path()),
                         "--out", str(out)], capsys)

    assert code == 0
    assert out.is_file()
    assert "verified:" in printed
    # The refusal list is the point of the command's output.
    assert "NOT imported" in printed


def test_ioc_import_refuses_a_bundle_with_nothing_usable(tmp_path, capsys):
    bundle = tmp_path / "b.json"
    bundle.write_text(
        '{"type": "bundle", "objects": [{"type": "indicator", '
        '"id": "indicator--1", "pattern": "[ipv4-addr:value = \'1.2.3.4\']",'
        ' "pattern_type": "stix", "confidence": 50}]}', encoding="utf-8")
    code, printed = run(["ioc", "import", str(bundle),
                         "--out", str(tmp_path / "pack.toml")], capsys)

    assert code == 2
    assert "no indicator this tool can evaluate" in printed
    assert not (tmp_path / "pack.toml").exists()


def test_ioc_import_fails_loudly_if_it_writes_a_pack_that_does_not_load(
        tmp_path, capsys, monkeypatch):
    """The command loads its own output back before claiming success. A
    generated pack the scanner refuses is worse than an import that failed:
    the operator keeps a file that looks like intel and finds out at scan
    time."""
    import coldlight_stix as sx

    monkeypatch.setattr(sx, "render_pack",
                        lambda imported: "[pack]\nname = 'broken'\n")
    out = tmp_path / "pack.toml"
    code, printed = run(["ioc", "import", str(_example_bundle_path()),
                         "--out", str(out)], capsys)

    assert code == 2
    assert "does not load" in printed
    assert "bug in the importer" in printed
