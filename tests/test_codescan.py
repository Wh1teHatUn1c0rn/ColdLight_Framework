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


# ---------------------------------------------------------------------------
# CI secret handling
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("step", [
    'echo "${{ secrets.DEPLOY_KEY }}" | base64',
    'printf %s "$NPM_TOKEN" | base64 -w0',
    'base64 <<< "${{ secrets.AWS_SECRET_ACCESS_KEY }}"',
    'echo "$CI_JOB_TOKEN" | gzip | base64',
    'echo "$DB_PASSWORD" | xxd',
    'echo "${{ secrets.TOKEN }}" | rev',
    'openssl base64 -in /dev/stdin <<< "$SIGNING_SECRET"',
])
def test_a_secret_encoded_in_a_build_step_is_a_finding(tmp_path, step):
    """A CI platform masks a secret by matching its literal value in the
    output, so an encoded copy prints in full. This is the shape the Barracuda
    intrusion used and the one masking cannot catch."""
    findings = _scan(tmp_path, "ci.yml", f"      - run: {step}\n")
    assert "CI-SECRET-ENCODED" in _rule_ids(findings)
    finding = next(f for f in findings if f.rule_id == "CI-SECRET-ENCODED")
    assert (finding.severity, finding.cwe) == ("HIGH", "CWE-532")


@pytest.mark.parametrize("step", [
    'echo "${{ secrets.GPG_KEY }}" | base64 -d > key.gpg',
    'echo "${{ secrets.KEYSTORE }}" | base64 --decode > ks.jks',
    'echo "$SIGNING_CERT" | base64 -D > cert.p12',
    'openssl enc -d -aes-256-cbc -in blob -pass env:PASSWORD',
    'echo "$ARCHIVE_TOKEN" | gzip -d > out.tar',
    'xxd -r -p <<< "$HEX_SECRET" > blob',
])
def test_decoding_a_secret_into_the_job_is_not_a_finding(tmp_path, step):
    """The distinction the rule lives or dies by. `base64 -d` pulls a stored
    binary secret INTO the build -- the ordinary way to carry a GPG key or a
    keystore -- and is the opposite of hiding one on the way out. Without the
    decode exclusion this rule would fire on half the release workflows in
    existence and be turned off within a day."""
    findings = _scan(tmp_path, "ci.yml", f"      - run: {step}\n")
    assert "CI-SECRET-ENCODED" not in _rule_ids(findings)


@pytest.mark.parametrize("step", [
    'curl -H "Authorization: Bearer ${{ secrets.TOKEN }}" "$URL"',
    'docker login -u u -p "${{ secrets.REGISTRY_PASSWORD }}"',
    'cat payload.bin | base64 > payload.b64',
    'aws s3 cp build.zip s3://bucket --sse',
])
def test_ordinary_secret_use_and_ordinary_encoding_stay_quiet(tmp_path, step):
    """Using a secret is the point of having one, and encoding something that
    is not a secret is routine. Only the two together are the finding."""
    findings = _scan(tmp_path, "ci.yml", f"      - run: {step}\n")
    assert "CI-SECRET-ENCODED" not in _rule_ids(findings)


def test_the_encoded_value_is_redacted_in_the_finding(tmp_path):
    """The snippet goes into a report someone shares, and a build step can
    carry the value inline rather than by reference. The command shape is
    what makes the finding, so masking the quoted value costs nothing: the
    file and line still name the step exactly."""
    findings = _scan(
        tmp_path, "ci.yml",
        '      - run: echo "${{ secrets.DEPLOY_KEY }}" | base64\n')
    snippet = next(f.snippet for f in findings
                   if f.rule_id == "CI-SECRET-ENCODED")
    assert "REDACTED" in snippet
    assert "base64" in snippet, "the shape of the command has to survive"


def test_a_literal_secret_in_a_build_step_is_still_caught(tmp_path):
    """By the secret rules, not this one. CI-SECRET-ENCODED is about a secret
    REFERENCE being transformed; a key pasted into a workflow is a different
    weakness with a different fix, and SECRET-AWS-AKID already names it."""
    findings = _scan(tmp_path, "ci.yml",
                     '      - run: echo "AKIAIOSFODNN7EXAMPLE" | base64\n')
    assert "SECRET-AWS-AKID" in _rule_ids(findings)
    assert "AKIAIOSFODNN7EXAMPLE" not in findings[0].snippet


@pytest.mark.parametrize("step", ["env | base64", "printenv | gzip",
                                  "env | xxd"])
def test_encoding_the_whole_environment_is_a_finding(tmp_path, step):
    """A CI job's environment holds every secret injected into it, so this
    prints all of them at once in a form masking will not catch."""
    findings = _scan(tmp_path, "ci.yml", f"      - run: {step}\n")
    assert "CI-ENV-DUMP" in _rule_ids(findings)


@pytest.mark.parametrize("step", ["env", "env | sort", "printenv PATH",
                                  "env | grep -c NODE"])
def test_reading_the_environment_without_encoding_it_stays_quiet(tmp_path,
                                                                 step):
    findings = _scan(tmp_path, "ci.yml", f"      - run: {step}\n")
    assert "CI-ENV-DUMP" not in _rule_ids(findings)


def test_the_ci_rules_do_not_fire_on_application_code(tmp_path):
    """`extensions` keeps these two to config and shell.

    The lines below are ones the patterns DO match -- they build exactly the
    shell command the rules look for -- so what stops the findings is the
    extension gate and nothing else. A rule whose title says "build step"
    must not fire outside a build; application code that shells out is a
    different weakness, and CMD-SHELL-TRUE is the rule for it."""
    findings = _scan(tmp_path, "util.py",
                     'CMD = "echo $DEPLOY_TOKEN | base64"\n'
                     'DUMP = "env | gzip"\n')
    assert not {"CI-SECRET-ENCODED", "CI-ENV-DUMP"} & _rule_ids(findings)


def test_a_shell_script_is_a_build_step_too(tmp_path):
    findings = _scan(tmp_path, "release.sh",
                     'echo "$GITHUB_TOKEN" | base64 > /tmp/t\n')
    assert "CI-SECRET-ENCODED" in _rule_ids(findings)


# ---------------------------------------------------------------------------
# Container privilege and host mounts
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("line", [
    "        privileged: true",
    '        "privileged": true',
    "      - privileged: True",
])
def test_a_privileged_container_is_a_finding(tmp_path, line):
    findings = _scan(tmp_path, "pod.yaml", line + "\n")
    assert "CONTAINER-PRIVILEGED" in _rule_ids(findings)
    finding = next(f for f in findings
                   if f.rule_id == "CONTAINER-PRIVILEGED")
    assert (finding.severity, finding.cwe) == ("HIGH", "CWE-250")


@pytest.mark.parametrize("line", [
    "        privileged: false",
    "    # privileged: true",
])
def test_an_unprivileged_or_commented_container_stays_quiet(tmp_path, line):
    findings = _scan(tmp_path, "pod.yaml", line + "\n")
    assert "CONTAINER-PRIVILEGED" not in _rule_ids(findings)


@pytest.mark.parametrize("path", [
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/var/run/containerd/containerd.sock",
    "/run/podman/podman.sock",
])
def test_mounting_the_runtime_socket_is_a_finding(tmp_path, path):
    """Anything holding this socket can start a privileged container on the
    node, which is root on the node."""
    findings = _scan(tmp_path, "compose.yml", f'      - "{path}:{path}"\n')
    assert "CONTAINER-RUNTIME-SOCKET" in _rule_ids(findings)
    finding = next(f for f in findings
                   if f.rule_id == "CONTAINER-RUNTIME-SOCKET")
    assert (finding.severity, finding.cwe) == ("HIGH", "CWE-250")


def test_the_runtime_socket_is_a_finding_in_a_shell_script(tmp_path):
    findings = _scan(tmp_path, "build.sh",
                     "docker run -v /var/run/docker.sock:/var/run/docker.sock b\n")
    assert "CONTAINER-RUNTIME-SOCKET" in _rule_ids(findings)


@pytest.mark.parametrize("line", [
    "          - hostPath:",
    '        "hostPath":',
    "      - /:/host",
    "      - /etc:/host-etc",
    "      - /root:/r",
])
def test_a_host_mount_is_a_finding(tmp_path, line):
    """The credential-harvest shape: a container reading the node's
    filesystem. Line-based, so the key itself is what is matched -- the
    `path:` under it is on the next line and out of reach."""
    findings = _scan(tmp_path, "pod.yaml", line + "\n")
    assert "CONTAINER-HOST-MOUNT" in _rule_ids(findings)
    finding = next(f for f in findings
                   if f.rule_id == "CONTAINER-HOST-MOUNT")
    assert (finding.severity, finding.cwe) == ("MEDIUM", "CWE-668")


@pytest.mark.parametrize("line", [
    "      - ./src:/app/src",
    "      - app-data:/var/lib/app",
    "      - /home/app/config:/config",
    "      - /opt/project/data:/data",
])
def test_an_ordinary_volume_is_not_a_host_mount_finding(tmp_path, line):
    """A compose file mounting a project directory is the normal case. Only a
    sensitive host root earns the finding, or the `hostPath` key itself."""
    findings = _scan(tmp_path, "compose.yml", line + "\n")
    assert "CONTAINER-HOST-MOUNT" not in _rule_ids(findings)


def test_a_manifest_that_documents_the_risk_is_not_a_finding(tmp_path):
    """A line that talks about the setting is not the setting. Both rules are
    anchored to the key position, so prose inside a manifest -- an annotation,
    a description field, a help string -- does not fire them."""
    findings = _scan(
        tmp_path, "pod.yaml",
        '        description: "never set privileged: true in a workload"\n'
        '        notes: "a hostPath: mount needs review"\n')
    assert not {"CONTAINER-PRIVILEGED",
                "CONTAINER-HOST-MOUNT"} & _rule_ids(findings)


def test_the_container_rules_do_not_fire_on_application_code(tmp_path):
    """Same gate, same reasoning. A Python dict declaring a container spec
    matches the manifest patterns exactly -- quoted key, colon, value -- so
    only the extension list keeps a rule about manifests inside manifests.

    Declaring a privileged container from application code is therefore not
    covered. That is a deliberate boundary, not an oversight: the fix for a
    manifest is a manifest change, and these rules exist to point at the file
    a reviewer edits."""
    findings = _scan(tmp_path, "deploy.py",
                     '    spec = {\n'
                     '        "privileged": True,\n'
                     '        "hostPath": {"path": "/"},\n'
                     '    }\n')
    assert not {"CONTAINER-PRIVILEGED",
                "CONTAINER-HOST-MOUNT"} & _rule_ids(findings)


# ---------------------------------------------------------------------------
# Structural: a rule's CWE has to be one the report can describe
# ---------------------------------------------------------------------------

def test_every_rule_cites_a_weakness_the_catalogue_knows():
    """A rule citing a CWE the bundled catalogue has never heard of still
    produces findings -- with no description and no mitigations behind them.
    That degradation is silent, which is why it needs a test rather than a
    convention. CWE-532 and CWE-250 were added to the catalogue with the CI
    and container rules for exactly this reason."""
    import coldlight_cwe as cwe

    unknown = sorted({r.cwe for r in cs.RULES} - cwe.known())
    assert not unknown, f"rules cite CWEs with no catalogue entry: {unknown}"


def test_every_aisec_rule_cites_a_weakness_the_catalogue_knows():
    import coldlight_aisec as ai
    import coldlight_cwe as cwe

    cited = {r.cwe for r in ai.RULES if getattr(r, "cwe", "")}
    unknown = sorted(cited - cwe.known())
    assert not unknown, f"AI rules cite CWEs with no catalogue entry: {unknown}"


def test_rule_ids_are_unique():
    ids = [r.rule_id for r in cs.RULES]
    assert len(ids) == len(set(ids))


def test_every_rule_carries_a_remediation():
    """A finding without a fix is a complaint."""
    missing = [r.rule_id for r in cs.RULES if not r.remediation.strip()]
    assert not missing, missing
