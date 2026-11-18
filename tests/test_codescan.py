"""Tests for coldlight_codescan (static analysis). No network, no execution."""

import json

import pytest

import coldlight_codescan as cs


def _scan(tmp_path, name, content):
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return cs.scan_file(path)


def _rule_ids(findings):
    return {f.rule_id for f in findings}


# ---------------------------------------------------------------------------
# Secrets
# ---------------------------------------------------------------------------

def test_detects_aws_access_key(tmp_path):
    findings = _scan(tmp_path, "conf.py", 'KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    assert "SECRET-AWS-AKID" in _rule_ids(findings)
    assert findings[0].severity == "CRITICAL"
    assert findings[0].cwe == "CWE-798"


def test_detects_hardcoded_password(tmp_path):
    findings = _scan(tmp_path, "db.py", 'password = "SuperSecret123!"\n')
    assert "SECRET-PRIVATE-TOKEN" in _rule_ids(findings)


def test_detects_private_key_block(tmp_path):
    findings = _scan(tmp_path, "id_rsa", "-----BEGIN RSA PRIVATE KEY-----\n")
    # .pem/no-extension files still scan when passed directly
    assert "SECRET-PRIVATE-KEY" in _rule_ids(findings)


def test_detects_github_token(tmp_path):
    findings = _scan(
        tmp_path, "ci.yml", "token: ghp_abcdefghij0123456789ABCDEFGHIJKLMNOP\n"
    )
    assert "SECRET-GITHUB-PAT" in _rule_ids(findings)


def test_detects_credentials_in_connection_uri(tmp_path):
    findings = _scan(
        tmp_path, "settings.py",
        'DB = "postgresql://admin:hunter2@db.internal:5432/app"\n',
    )
    assert "SECRET-CONN-STRING" in _rule_ids(findings)


def test_secret_value_is_redacted_in_the_report(tmp_path):
    secret = "SuperSecret123!"
    findings = _scan(tmp_path, "db.py", f'password = "{secret}"\n')
    assert findings, "expected a finding"
    for f in findings:
        assert secret not in f.snippet, "the raw secret leaked into the report"
        assert "***REDACTED***" in f.snippet


def test_aws_key_redacted_even_unquoted(tmp_path):
    findings = _scan(tmp_path, ".env", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
    assert findings
    assert "AKIAIOSFODNN7EXAMPLE" not in findings[0].snippet


def test_redact_masks_uri_password_only():
    out = cs.redact("url = postgresql://admin:hunter2@host/db")
    assert "hunter2" not in out
    assert "admin" in out


def test_placeholders_are_not_flagged(tmp_path):
    findings = _scan(tmp_path, "example.py", 'password = "${DB_PASSWORD}"\n')
    assert "SECRET-PRIVATE-TOKEN" not in _rule_ids(findings)


# ---------------------------------------------------------------------------
# Injection sinks
# ---------------------------------------------------------------------------

def test_detects_shell_true(tmp_path):
    findings = _scan(
        tmp_path, "run.py", "subprocess.run(cmd, shell=True)\n"
    )
    ids = _rule_ids(findings)
    assert "CMD-SHELL-TRUE" in ids
    assert next(f for f in findings if f.rule_id == "CMD-SHELL-TRUE").cwe == "CWE-78"


def test_detects_os_system(tmp_path):
    findings = _scan(tmp_path, "run.py", 'os.system("ls " + target)\n')
    assert "CMD-OS-SYSTEM" in _rule_ids(findings)


def test_detects_eval(tmp_path):
    findings = _scan(tmp_path, "calc.py", "result = eval(user_input)\n")
    assert "CODE-EVAL" in _rule_ids(findings)


def test_eval_not_flagged_on_attribute_access(tmp_path):
    findings = _scan(tmp_path, "safe.py", "model.eval()\n")
    assert "CODE-EVAL" not in _rule_ids(findings)


def test_detects_pickle_loads(tmp_path):
    findings = _scan(tmp_path, "cache.py", "obj = pickle.loads(blob)\n")
    assert "DESER-PICKLE" in _rule_ids(findings)
    assert next(f for f in findings if f.rule_id == "DESER-PICKLE").cwe == "CWE-502"


def test_detects_unsafe_yaml_load(tmp_path):
    findings = _scan(tmp_path, "conf.py", "cfg = yaml.load(stream)\n")
    assert "DESER-YAML-LOAD" in _rule_ids(findings)


def test_safe_yaml_load_is_clean(tmp_path):
    findings = _scan(tmp_path, "conf.py", "cfg = yaml.load(stream, Loader=yaml.SafeLoader)\n")
    assert "DESER-YAML-LOAD" not in _rule_ids(findings)
    findings = _scan(tmp_path, "conf2.py", "cfg = yaml.safe_load(stream)\n")
    assert "DESER-YAML-LOAD" not in _rule_ids(findings)


def test_detects_sql_string_interpolation(tmp_path):
    findings = _scan(
        tmp_path, "dao.py",
        'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n',
    )
    assert "SQLI-FSTRING" in _rule_ids(findings)


def test_non_sql_fstring_call_is_not_flagged(tmp_path):
    """A function named `query` taking an f-string is not SQL injection --
    this fired on coldlight_mail's DNS lookups before the rule was tightened."""
    findings = _scan(tmp_path, "dns.py",
                     'answer = query(f"_dmarc.{domain}", "TXT")\n')
    assert "SQLI-FSTRING" not in _rule_ids(findings)

    findings = _scan(tmp_path, "dns2.py",
                     'resp = execute(f"/api/{path}", timeout=5)\n')
    assert "SQLI-FSTRING" not in _rule_ids(findings)


def test_sql_fstring_is_still_flagged(tmp_path):
    for line in (
        'cursor.execute(f"SELECT * FROM t WHERE id={x}")\n',
        'conn.execute(f"DELETE FROM t WHERE id={x}")\n',
        'db.query(f"insert into t values ({x})")\n',
    ):
        assert "SQLI-FSTRING" in _rule_ids(_scan(tmp_path, "dao.py", line)), line


def test_parameterised_query_is_clean(tmp_path):
    findings = _scan(
        tmp_path, "dao.py",
        'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))\n',
    )
    assert "SQLI-FSTRING" not in _rule_ids(findings)


# ---------------------------------------------------------------------------
# Transport / crypto / config
# ---------------------------------------------------------------------------

def test_detects_tls_verification_disabled(tmp_path):
    findings = _scan(tmp_path, "client.py", "requests.get(url, verify=False)\n")
    assert "TLS-VERIFY-OFF" in _rule_ids(findings)
    assert next(f for f in findings if f.rule_id == "TLS-VERIFY-OFF").cwe == "CWE-295"


def test_detects_reject_unauthorized_false(tmp_path):
    findings = _scan(tmp_path, "client.js", "const o = { rejectUnauthorized: false };\n")
    assert "TLS-VERIFY-OFF" in _rule_ids(findings)


def test_detects_weak_hash(tmp_path):
    findings = _scan(tmp_path, "hash.py", "digest = hashlib.md5(pw).hexdigest()\n")
    assert "CRYPTO-WEAK-HASH" in _rule_ids(findings)
    assert next(f for f in findings if f.rule_id == "CRYPTO-WEAK-HASH").cwe == "CWE-327"


def test_weak_random_only_flags_security_context(tmp_path):
    flagged = _scan(tmp_path, "a.py", "token = random.randint(0, 999999)\n")
    assert "CRYPTO-WEAK-RANDOM" in _rule_ids(flagged)

    clean = _scan(tmp_path, "b.py", "pick = random.choice(colours)\n")
    assert "CRYPTO-WEAK-RANDOM" not in _rule_ids(clean)


def test_detects_debug_enabled(tmp_path):
    findings = _scan(tmp_path, "app.py", "app.run(debug=True)\n")
    assert "CONF-DEBUG-ON" in _rule_ids(findings)


def test_detects_wildcard_allowed_hosts(tmp_path):
    findings = _scan(tmp_path, "settings.py", 'ALLOWED_HOSTS = ["*"]\n')
    assert "CONF-WILDCARD-HOSTS" in _rule_ids(findings)


def test_detects_assert_for_auth(tmp_path):
    findings = _scan(tmp_path, "views.py", "assert user.is_staff, 'nope'\n")
    assert "CONF-ASSERT-AUTH" in _rule_ids(findings)


# ---------------------------------------------------------------------------
# Language scoping, suppression, traversal
# ---------------------------------------------------------------------------

def test_python_only_rule_does_not_fire_on_js(tmp_path):
    findings = _scan(tmp_path, "thing.js", "obj = pickle.loads(blob)\n")
    assert "DESER-PICKLE" not in _rule_ids(findings)


def test_js_only_rule_does_not_fire_on_python(tmp_path):
    findings = _scan(tmp_path, "thing.py", "el.innerHTML = value\n")
    assert "XSS-INNERHTML" not in _rule_ids(findings)


def test_js_rule_fires_on_js(tmp_path):
    findings = _scan(tmp_path, "thing.js", "el.innerHTML = value;\n")
    assert "XSS-INNERHTML" in _rule_ids(findings)


@pytest.mark.parametrize("comment", ["# nosec", "# coldlight:ignore"])
def test_suppression_comments(tmp_path, comment):
    findings = _scan(tmp_path, "run.py", f"subprocess.run(c, shell=True)  {comment}\n")
    assert findings == []


def test_commented_out_code_is_not_flagged(tmp_path):
    findings = _scan(tmp_path, "run.py", "# subprocess.run(cmd, shell=True)\n")
    assert findings == []


def test_line_numbers_are_reported(tmp_path):
    content = "import os\n\n\nos.system(cmd)\n"
    findings = _scan(tmp_path, "run.py", content)
    assert findings[0].line == 4


def test_minified_bundle_lines_are_skipped(tmp_path):
    findings = _scan(tmp_path, "bundle.js", "x=1;" * 2000 + "eval(a)\n")
    assert findings == []


# ---------------------------------------------------------------------------
# Tree walking
# ---------------------------------------------------------------------------

def test_scan_code_skips_vendored_trees(tmp_path):
    (tmp_path / "app.py").write_text("os.system(cmd)\n")

    vendored = tmp_path / "node_modules" / "pkg"
    vendored.mkdir(parents=True)
    (vendored / "index.js").write_text("eval(x)\n")

    cached = tmp_path / "__pycache__"
    cached.mkdir()
    (cached / "junk.py").write_text("eval(x)\n")

    result = cs.scan_code(tmp_path)
    assert result.files_scanned == 1
    assert len(result.findings) == 1
    assert result.findings[0].file.endswith("app.py")


def test_scan_code_ignores_unknown_extensions(tmp_path):
    (tmp_path / "notes.md").write_text("os.system(cmd)\n")
    (tmp_path / "data.bin").write_text("eval(x)\n")
    result = cs.scan_code(tmp_path)
    assert result.files_scanned == 0
    assert result.findings == []


def test_scan_code_accepts_a_single_file(tmp_path):
    target = tmp_path / "app.py"
    target.write_text("eval(x)\n")
    result = cs.scan_code(target)
    assert result.files_scanned == 1
    assert len(result.findings) == 1


def test_exclude_skips_a_subtree(tmp_path):
    (tmp_path / "app.py").write_text("eval(x)\n")
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_thing.py").write_text("eval(x)\n")

    assert cs.scan_code(tmp_path).files_scanned == 2

    result = cs.scan_code(tmp_path, exclude=["tests/*"])
    assert result.files_scanned == 1
    assert result.findings[0].file.endswith("app.py")

    # a bare directory name means the whole subtree too
    assert cs.scan_code(tmp_path, exclude=["tests"]).files_scanned == 1


def test_exclude_matches_a_single_file_glob(tmp_path):
    (tmp_path / "app.py").write_text("eval(x)\n")
    (tmp_path / "rules.py").write_text("eval(x)\n")
    result = cs.scan_code(tmp_path, exclude=["rules.py"])
    assert result.files_scanned == 1
    assert result.findings[0].file.endswith("app.py")


def test_exclude_accepts_several_patterns(tmp_path):
    (tmp_path / "app.py").write_text("eval(x)\n")
    (tmp_path / "a.py").write_text("eval(x)\n")
    (tmp_path / "b.py").write_text("eval(x)\n")
    result = cs.scan_code(tmp_path, exclude=["a.py", "b.py"])
    assert result.files_scanned == 1


def test_no_exclude_scans_everything(tmp_path):
    (tmp_path / "app.py").write_text("eval(x)\n")
    assert cs.scan_code(tmp_path, exclude=None).files_scanned == 1
    assert cs.scan_code(tmp_path, exclude=[]).files_scanned == 1


def test_findings_sorted_by_severity(tmp_path):
    (tmp_path / "app.py").write_text(
        'host = "0.0.0.0"\n'            # LOW
        'key = "AKIAIOSFODNN7EXAMPLE"\n'  # CRITICAL
        "requests.get(u, verify=False)\n"  # HIGH
    )
    result = cs.scan_code(tmp_path)
    severities = [f.severity for f in result.findings]
    assert severities == sorted(
        severities, key=lambda s: -cs.SEVERITY_ORDER[s.upper()]
    )
    assert result.findings[0].severity == "CRITICAL"


# ---------------------------------------------------------------------------
# Reporting / gating
# ---------------------------------------------------------------------------

def test_meets_threshold():
    findings = [cs.CodeFinding("R", "MEDIUM", "CWE-1", "t", "f.py", 1, "x")]
    assert cs.meets_threshold(findings, "medium")
    assert not cs.meets_threshold(findings, "critical")
    with pytest.raises(ValueError):
        cs.meets_threshold(findings, "nonsense")


def test_counts_helpers():
    findings = [
        cs.CodeFinding("A", "HIGH", "CWE-78", "t", "f.py", 1, "x"),
        cs.CodeFinding("B", "HIGH", "CWE-78", "t", "f.py", 2, "x"),
        cs.CodeFinding("C", "LOW", "CWE-16", "t", "f.py", 3, "x"),
    ]
    assert cs.severity_counts(findings) == {"HIGH": 2, "LOW": 1}
    assert cs.cwe_counts(findings) == {"CWE-78": 2, "CWE-16": 1}


def test_text_report_includes_remediation_when_asked(tmp_path):
    (tmp_path / "app.py").write_text("subprocess.run(c, shell=True)\n")
    result = cs.scan_code(tmp_path)

    with_fix = cs.text_report(result, show_remediation=True)
    assert "fix:" in with_fix
    assert "CWE-78" in with_fix

    without = cs.text_report(result, show_remediation=False)
    assert "fix:" not in without


def test_json_report_is_serialisable(tmp_path):
    (tmp_path / "app.py").write_text("eval(x)\n")
    result = cs.scan_code(tmp_path)
    report = cs.json_report(result)
    assert report["tool"] == "coldlight codescan"
    assert report["files_scanned"] == 1
    assert report["findings"][0]["cwe"] == "CWE-95"
    json.dumps(report)


def test_empty_scan_reports_cleanly(tmp_path):
    result = cs.scan_code(tmp_path)
    text = cs.text_report(result)
    assert "findings      : 0" in text
