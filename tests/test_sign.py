import pytest

import coldlight_sign as rs


def test_build_cmd_pfx():
    cmd = rs.build_signtool_cmd("signtool.exe", "a.exe", pfx="c.pfx", password="pw")
    assert "sign" in cmd and "/f" in cmd and "c.pfx" in cmd
    assert "/p" in cmd and cmd[-1] == "a.exe"
    assert "/fd" in cmd and "SHA256" in cmd


def test_build_cmd_thumbprint():
    cmd = rs.build_signtool_cmd("signtool.exe", "a.exe", thumbprint="ABCD")
    assert "/sha1" in cmd and "ABCD" in cmd
    assert "/p" not in cmd


def test_build_cmd_requires_cert():
    with pytest.raises(ValueError):
        rs.build_signtool_cmd("signtool.exe", "a.exe")


def test_find_signtool_returns_str_or_none():
    result = rs.find_signtool()
    assert result is None or isinstance(result, str)


def test_sign_dry_run(tmp_path, capsys):
    exe = tmp_path / "a.exe"
    exe.write_text("stub")
    rc = rs.sign(exe, thumbprint="AB", dry_run=True, signtool="signtool.exe")
    assert rc == 0
    out = capsys.readouterr().out
    assert "dry-run" in out


def test_sign_redacts_password(tmp_path, capsys):
    exe = tmp_path / "a.exe"
    exe.write_text("stub")
    rs.sign(exe, pfx="c.pfx", password="SECRET", dry_run=True, signtool="signtool.exe")
    out = capsys.readouterr().out
    assert "SECRET" not in out
    assert "***" in out
