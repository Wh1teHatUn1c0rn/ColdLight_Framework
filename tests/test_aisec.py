"""Tests for coldlight_aisec (AI/ML security assessment).

No network, no model loading, no execution. The central claim this module
makes is that it inspects model artifacts WITHOUT deserialising them, so that
claim is tested directly rather than assumed.

NOTE FOR SCANNERS AND REVIEWERS: this file is full of insecure-looking code --
torch.load, joblib.load, eval, subprocess with shell=True, API keys. Every one
is a STRING fixture written to a temp file for the scanner to match against,
and none is ever executed or imported. The API keys are syntactically valid
but fabricated. A scanner flagging this file is behaving correctly; the
patterns are the point.
"""

import json

import pytest

import coldlight_aisec as ai


def _scan(tmp_path, name, content):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return ai.scan_file(path)


def _ids(findings):
    return {f.rule_id for f in findings}


def _by_id(findings, rule_id):
    return [f for f in findings if f.rule_id == rule_id]


# ---------------------------------------------------------------------------
# Rule table integrity
#
# A mapping to a published standard has to be a real identifier: an invented
# ATLAS technique or CWE number is worse than none, because it looks
# authoritative to the reader of the report.
# ---------------------------------------------------------------------------

def test_rule_ids_are_unique():
    ids = [r.rule_id for r in ai.RULES]
    assert len(ids) == len(set(ids))


def test_every_owasp_mapping_is_a_real_identifier():
    for rule in ai.RULES:
        if rule.owasp:
            assert rule.owasp in ai.OWASP_LLM, rule.rule_id


def test_every_atlas_mapping_is_a_real_identifier():
    for rule in ai.RULES:
        if rule.atlas:
            assert rule.atlas in ai.ATLAS, rule.rule_id


def test_every_severity_is_known():
    from coldlight_codescan import SEVERITY_ORDER
    for rule in ai.RULES:
        assert rule.severity.upper() in SEVERITY_ORDER, rule.rule_id


def test_every_rule_has_remediation():
    for rule in ai.RULES:
        assert rule.remediation.strip(), rule.rule_id


def test_cwe_identifiers_are_well_formed():
    for rule in ai.RULES:
        if rule.cwe:
            assert rule.cwe.startswith("CWE-"), rule.rule_id
            assert rule.cwe[4:].isdigit(), rule.rule_id


def test_severity_source_is_declared_as_our_own_judgement():
    """These severities are ColdLight' judgement, not a measured CVSS score."""
    assert ai.SEVERITY_SOURCE == "coldlight-rule"
    assert ai.AiFinding("X", "LOW", "t", "f.py", 1).severity_source == (
        "coldlight-rule")


# ---------------------------------------------------------------------------
# LLM03 supply chain: loading code disguised as data
# ---------------------------------------------------------------------------

def test_torch_load_without_weights_only(tmp_path):
    findings = _scan(tmp_path, "m.py", 'm = torch.load("ckpt.pt")\n')
    assert "AI-TORCH-LOAD-UNSAFE" in _ids(findings)
    assert _by_id(findings, "AI-TORCH-LOAD-UNSAFE")[0].cwe == "CWE-502"


def test_torch_load_with_weights_only_is_not_flagged(tmp_path):
    findings = _scan(
        tmp_path, "m.py", 'm = torch.load("ckpt.pt", weights_only=True)\n')
    assert "AI-TORCH-LOAD-UNSAFE" not in _ids(findings)


def test_trust_remote_code(tmp_path):
    findings = _scan(
        tmp_path, "m.py",
        'M.from_pretrained("o/m", trust_remote_code=True, revision="abc")\n')
    assert "AI-TRUST-REMOTE-CODE" in _ids(findings)


def test_pickle_and_joblib_loads(tmp_path):
    for call in ("joblib.load(p)", "pickle.loads(blob)", "dill.load(f)"):
        findings = _scan(tmp_path, "m.py", f"x = {call}\n")
        assert "AI-PICKLE-MODEL-LOAD" in _ids(findings), call


def test_numpy_allow_pickle(tmp_path):
    findings = _scan(tmp_path, "m.py", 'np.load("a.npy", allow_pickle=True)\n')
    assert "AI-NUMPY-ALLOW-PICKLE" in _ids(findings)


def test_keras_load_without_safe_mode(tmp_path):
    findings = _scan(tmp_path, "m.py", 'keras.models.load_model("m.h5")\n')
    assert "AI-KERAS-UNSAFE-LOAD" in _ids(findings)


def test_keras_load_with_safe_mode_is_not_flagged(tmp_path):
    findings = _scan(
        tmp_path, "m.py", 'keras.models.load_model("m.h5", safe_mode=True)\n')
    assert "AI-KERAS-UNSAFE-LOAD" not in _ids(findings)


def test_unpinned_model_reference(tmp_path):
    findings = _scan(tmp_path, "m.py", 'M.from_pretrained("org/model")\n')
    assert "AI-UNPINNED-MODEL-REF" in _ids(findings)


def test_pinned_model_reference_is_not_flagged(tmp_path):
    findings = _scan(
        tmp_path, "m.py", 'M.from_pretrained("org/m", revision="9f8e7d")\n')
    assert "AI-UNPINNED-MODEL-REF" not in _ids(findings)


# ---------------------------------------------------------------------------
# LLM05 improper output handling: the model is just another untrusted source
# ---------------------------------------------------------------------------

def test_model_output_into_eval_is_critical(tmp_path):
    findings = _scan(tmp_path, "a.py", "result = eval(completion)\n")
    hits = _by_id(findings, "AI-OUTPUT-TO-EVAL")
    assert hits and hits[0].severity == "CRITICAL"
    assert hits[0].owasp == "LLM05"


def test_model_output_into_shell_is_critical(tmp_path):
    findings = _scan(
        tmp_path, "a.py", 'subprocess.run("echo " + completion, shell=True)\n')
    hits = _by_id(findings, "AI-OUTPUT-TO-SHELL")
    assert hits and hits[0].severity == "CRITICAL"


def test_model_output_interpolated_into_quoted_sql(tmp_path):
    """Regression: the quoting that makes this injectable is precisely what
    stopped an earlier version of the rule from matching it."""
    line = """cursor.execute(f"SELECT * FROM n WHERE b = '{response}'")\n"""
    findings = _scan(tmp_path, "a.py", line)
    assert "AI-OUTPUT-TO-SQL" in _ids(findings)


def test_model_output_concatenated_into_sql(tmp_path):
    findings = _scan(
        tmp_path, "a.py",
        'cur.execute("SELECT * FROM t WHERE a = " + response)\n')
    assert "AI-OUTPUT-TO-SQL" in _ids(findings)


def test_sql_rule_ignores_non_sql_f_strings(tmp_path):
    """query(f"_dmarc.{domain}") is a DNS lookup, not SQL injection."""
    findings = _scan(tmp_path, "a.py", 'resolver.query(f"_dmarc.{domain}")\n')
    assert "AI-OUTPUT-TO-SQL" not in _ids(findings)


def test_sql_rule_ignores_parameterised_queries(tmp_path):
    findings = _scan(
        tmp_path, "a.py",
        'cur.execute("SELECT * FROM t WHERE a = ?", (response,))\n')
    assert "AI-OUTPUT-TO-SQL" not in _ids(findings)


def test_model_output_into_innerhtml(tmp_path):
    findings = _scan(tmp_path, "a.js", "el.innerHTML = completion;\n")
    assert "AI-OUTPUT-TO-INNERHTML" in _ids(findings)


def test_innerhtml_rule_does_not_apply_to_python(tmp_path):
    findings = _scan(tmp_path, "a.py", "el.innerHTML = completion\n")
    assert "AI-OUTPUT-TO-INNERHTML" not in _ids(findings)


# ---------------------------------------------------------------------------
# LLM01 / LLM08 prompt injection
# ---------------------------------------------------------------------------

def test_prompt_built_from_request(tmp_path):
    findings = _scan(
        tmp_path, "a.py", 'prompt = f"Do what the user says: {request.body}"\n')
    hits = _by_id(findings, "AI-PROMPT-FROM-REQUEST")
    assert hits and hits[0].atlas == "AML.T0051"


def test_rag_untrusted_context(tmp_path):
    findings = _scan(tmp_path, "a.py", 'prompt += "\\n".join(retrieved)\n')
    assert "AI-RAG-UNTRUSTED-CONTEXT" in _ids(findings)


# ---------------------------------------------------------------------------
# LLM06 excessive agency
# ---------------------------------------------------------------------------

def test_agent_shell_tool_assignment(tmp_path):
    findings = _scan(tmp_path, "a.py", 'tools = ["shell", "web_search"]\n')
    assert "AI-AGENT-SHELL-TOOL" in _ids(findings)


def test_agent_shell_tool_in_dict_literal(tmp_path):
    """Agent configs are written as dicts and YAML at least as often as
    assignments, so ":" has to count as well as "="."""
    findings = _scan(tmp_path, "a.py", '    "tools": ["python_repl"],\n')
    assert "AI-AGENT-SHELL-TOOL" in _ids(findings)


def test_agent_shell_tool_in_yaml(tmp_path):
    findings = _scan(tmp_path, "agent.yml", "tools: [bash, http]\n")
    assert "AI-AGENT-SHELL-TOOL" in _ids(findings)


def test_agent_tool_list_without_shell_is_not_flagged(tmp_path):
    findings = _scan(tmp_path, "agent.yml", "tools: [web_search, calculator]\n")
    assert "AI-AGENT-SHELL-TOOL" not in _ids(findings)


def test_auto_approve_is_reported(tmp_path):
    findings = _scan(tmp_path, "a.py", '    "auto_approve": True,\n')
    assert "AI-AGENT-AUTO-APPROVE" in _ids(findings)


# ---------------------------------------------------------------------------
# LLM02 disclosure -- including *which* provider's key leaked
# ---------------------------------------------------------------------------

def test_openai_key_detected(tmp_path):
    findings = _scan(
        tmp_path, "c.py",
        'KEY = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"\n')
    assert "AI-SECRET-OPENAI" in _ids(findings)
    assert _by_id(findings, "AI-SECRET-OPENAI")[0].severity == "CRITICAL"


def test_anthropic_key_is_not_reported_as_an_openai_key(tmp_path):
    """Regression: "sk-ant-..." also begins "sk-", so the OpenAI pattern
    matched it too and would send the reader to revoke the wrong key."""
    findings = _scan(
        tmp_path, "c.py",
        'KEY = "sk-ant-api03-ZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"\n')
    assert "AI-SECRET-ANTHROPIC" in _ids(findings)
    assert "AI-SECRET-OPENAI" not in _ids(findings)


def test_huggingface_token_detected(tmp_path):
    findings = _scan(
        tmp_path, "c.py", 'T = "hf_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456"\n')
    assert "AI-SECRET-HUGGINGFACE" in _ids(findings)


def test_generic_provider_credential_detected(tmp_path):
    findings = _scan(tmp_path, "c.py", 'cohere_api_key = "abcdefghijklmnop"\n')
    assert "AI-SECRET-GENERIC-LLM" in _ids(findings)


def test_generic_credential_ignores_placeholders(tmp_path):
    for value in ('"${OPENAI_KEY}"', '"<your-key-here>"'):
        findings = _scan(tmp_path, "c.py", f"openai_api_key = {value}\n")
        assert "AI-SECRET-GENERIC-LLM" not in _ids(findings), value


def test_secret_snippets_are_redacted(tmp_path):
    secret = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
    findings = _scan(tmp_path, "c.py", f'KEY = "{secret}"\n')
    assert findings
    for finding in findings:
        assert secret not in finding.snippet


def test_prompt_logging_reported(tmp_path):
    findings = _scan(tmp_path, "a.py", 'log.info("prompt=%s", prompt)\n')
    assert "AI-PROMPT-LOGS-PII" in _ids(findings)


# ---------------------------------------------------------------------------
# LLM10 unbounded consumption
# ---------------------------------------------------------------------------

def test_missing_token_ceiling(tmp_path):
    findings = _scan(
        tmp_path, "a.py", 'c.chat.completions.create(model="x", messages=m)\n')
    assert "AI-NO-TOKEN-LIMIT" in _ids(findings)


def test_token_ceiling_present_is_not_flagged(tmp_path):
    findings = _scan(
        tmp_path, "a.py",
        'c.chat.completions.create(model="x", max_tokens=256)\n')
    assert "AI-NO-TOKEN-LIMIT" not in _ids(findings)


# ---------------------------------------------------------------------------
# Scanner mechanics
# ---------------------------------------------------------------------------

def test_comment_lines_are_skipped(tmp_path):
    findings = _scan(tmp_path, "a.py", '# m = torch.load("x.pt")\n')
    assert findings == []


def test_suppression_comment_is_honoured(tmp_path):
    findings = _scan(
        tmp_path, "a.py", 'm = torch.load("x.pt")  # nosec reviewed\n')
    assert findings == []


def test_overlong_lines_are_skipped(tmp_path):
    padding = "x" * (ai.MAX_LINE_LEN + 10)
    findings = _scan(tmp_path, "a.py", f'm = torch.load("x.pt")  # {padding}\n')
    assert findings == []


def test_notebook_source_and_output_are_scanned(tmp_path):
    notebook = {
        "cells": [
            {"cell_type": "code",
             "source": ['m = torch.load("x.pt")\n'],
             "outputs": [
                 {"output_type": "stream",
                  "text": ['KEY = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWx012345"\n']},
             ]},
        ]
    }
    findings = _scan(tmp_path, "nb.ipynb", json.dumps(notebook))
    ids = _ids(findings)
    assert "AI-TORCH-LOAD-UNSAFE" in ids
    # A key printed into a committed cell result leaks just as surely as one
    # written in source, which is why outputs are scanned too.
    assert "AI-SECRET-OPENAI" in ids


def test_malformed_notebook_does_not_raise(tmp_path):
    findings = _scan(tmp_path, "nb.ipynb", "not json at all")
    assert findings == []


# ---------------------------------------------------------------------------
# Model artifacts -- the no-deserialisation guarantee
# ---------------------------------------------------------------------------

def _write_pickleish(path):
    """Pickle protocol-2 opcode followed by bytes that are NOT a valid
    pickle, so anything attempting to unpickle this would raise."""
    path.write_bytes(b"\x80\x04garbage-not-a-valid-pickle")


def test_unsafe_artifact_is_classified_by_magic_bytes(tmp_path):
    target = tmp_path / "legacy.joblib"
    _write_pickleish(target)
    artifact = ai.inspect_artifact(target)
    assert artifact is not None
    assert artifact.safe_format is False
    assert artifact.pickle_detected is True
    assert artifact.extension == ".joblib"


def test_safe_artifact_is_recognised(tmp_path):
    target = tmp_path / "clean.safetensors"
    target.write_bytes(b"\x00" * 16)
    artifact = ai.inspect_artifact(target)
    assert artifact is not None
    assert artifact.safe_format is True
    assert artifact.pickle_detected is False


def test_unknown_extension_is_not_an_artifact(tmp_path):
    target = tmp_path / "notes.txt"
    target.write_text("hello", encoding="utf-8")
    assert ai.inspect_artifact(target) is None


def test_artifact_inspection_never_deserialises(tmp_path, monkeypatch):
    """The point of the whole module: loading an untrusted model IS the
    vulnerability being reported. A call to an unpickler during a scan would
    mean the tool exploits the thing it is meant to warn about, so fail loudly
    if one ever happens.
    """
    import pickle

    def explode(*args, **kwargs):
        raise AssertionError("the scanner must never deserialise an artifact")

    monkeypatch.setattr(pickle, "load", explode)
    monkeypatch.setattr(pickle, "loads", explode)
    monkeypatch.setattr(pickle, "Unpickler", explode)

    _write_pickleish(tmp_path / "model.pkl")
    _write_pickleish(tmp_path / "net.pt")
    result = ai.scan_ai(tmp_path)

    assert len(result.artifacts) == 2
    assert len(result.unsafe_artifacts) == 2


def test_pickle_artifact_becomes_a_finding(tmp_path):
    _write_pickleish(tmp_path / "legacy.joblib")
    result = ai.scan_ai(tmp_path)
    hits = _by_id(result.findings, "AI-PICKLE-ARTIFACT")
    assert len(hits) == 1
    assert hits[0].owasp == "LLM03"
    assert hits[0].atlas == "AML.T0010"
    assert hits[0].line == 0


def test_safe_artifact_produces_no_finding(tmp_path):
    (tmp_path / "clean.safetensors").write_bytes(b"\x00" * 16)
    result = ai.scan_ai(tmp_path)
    assert result.findings == []
    assert result.unsafe_artifacts == []


def test_declared_extension_without_pickle_magic_is_not_a_finding(tmp_path):
    """A .bin of raw weights is not a pickle; say so rather than guessing
    from the extension alone."""
    (tmp_path / "weights.bin").write_bytes(b"\x01\x02\x03\x04" * 8)
    result = ai.scan_ai(tmp_path)
    assert result.unsafe_artifacts and not result.findings


# ---------------------------------------------------------------------------
# Whole-tree scan, exclusion, reporting
# ---------------------------------------------------------------------------

def _tree(tmp_path):
    # Note: "vendor" would be wrong here -- it is in the shared SKIP_DIRS,
    # so it never reaches the exclude logic under test.
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "agent.py").write_text(
        'm = torch.load("x.pt")\nresult = eval(completion)\n', encoding="utf-8")
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "dep.py").write_text(
        'm = torch.load("y.pt")\n', encoding="utf-8")
    return tmp_path


def test_vendored_directories_are_skipped_by_default(tmp_path):
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "dep.py").write_text(
        'm = torch.load("y.pt")\n', encoding="utf-8")
    result = ai.scan_ai(tmp_path)
    assert result.files_scanned == 0
    assert result.findings == []


def test_scan_counts_files_and_sorts_by_severity(tmp_path):
    result = ai.scan_ai(_tree(tmp_path))
    assert result.files_scanned == 2
    assert result.findings[0].severity == "CRITICAL"


def test_exclude_is_respected(tmp_path):
    result = ai.scan_ai(_tree(tmp_path), exclude=["pkg"])
    assert result.files_scanned == 1
    assert all("pkg" not in f.file for f in result.findings)


def test_severity_and_owasp_counts(tmp_path):
    result = ai.scan_ai(_tree(tmp_path))
    counts = ai.severity_counts(result.findings)
    assert counts.get("CRITICAL") == 1
    assert counts.get("HIGH") == 2
    owasp = ai.owasp_counts(result.findings)
    assert owasp["LLM03"] == 2
    assert owasp["LLM05"] == 1


def test_meets_threshold(tmp_path):
    result = ai.scan_ai(_tree(tmp_path))
    assert ai.meets_threshold(result.findings, "critical") is True
    assert ai.meets_threshold([], "low") is False


def test_meets_threshold_rejects_unknown_severity():
    with pytest.raises(ValueError):
        ai.meets_threshold([], "catastrophic")


def test_text_report_states_the_scope_limit(tmp_path):
    report = ai.text_report(ai.scan_ai(_tree(tmp_path)))
    assert "Static analysis only" in report
    assert "no model was loaded, probed or adversarially tested" in report


def test_text_report_can_omit_remediation(tmp_path):
    result = ai.scan_ai(_tree(tmp_path))
    assert "fix:" in ai.text_report(result)
    assert "fix:" not in ai.text_report(result, show_remediation=False)


def test_text_report_says_artifacts_were_not_deserialised(tmp_path):
    _write_pickleish(tmp_path / "legacy.joblib")
    report = ai.text_report(ai.scan_ai(tmp_path))
    assert "never deserialised" in report


def test_json_report_shape(tmp_path):
    _write_pickleish(tmp_path / "m.pkl")
    result = ai.scan_ai(_tree(tmp_path))
    payload = ai.json_report(result)
    assert payload["tool"] == "coldlight aisec"
    for key in ("files_scanned", "notebooks_scanned", "severity_counts",
                "owasp_llm_counts", "model_artifacts", "unsafe_artifact_count",
                "findings", "errors"):
        assert key in payload
    # The report and assurance stages read this back from disk.
    assert json.loads(json.dumps(payload))["findings"]


def test_findings_carry_provenance(tmp_path):
    result = ai.scan_ai(_tree(tmp_path))
    assert result.findings
    for finding in result.findings:
        assert finding.severity_source == "coldlight-rule"


# ---------------------------------------------------------------------------
# Baseline integration
# ---------------------------------------------------------------------------

def test_baseline_fingerprints_ai_findings(tmp_path):
    import coldlight_baseline as bl

    assert bl.SOURCE_AI == "ai"
    result = ai.scan_ai(_tree(tmp_path))
    prints = {bl.fingerprint_for(bl.SOURCE_AI, f, root=tmp_path)
              for f in result.findings}
    assert len(prints) == len(result.findings)
    assert all(p.startswith("ai:") for p in prints)


def test_ai_fingerprint_ignores_line_numbers(tmp_path):
    """Adding a line above a finding must not make it look new."""
    import coldlight_baseline as bl

    one = _scan(tmp_path, "a.py", 'm = torch.load("x.pt")\n')
    two = _scan(tmp_path, "b.py", '\n\nm = torch.load("x.pt")\n')
    assert one[0].line != two[0].line
    first = bl.fingerprint_for(bl.SOURCE_AI, one[0], root=tmp_path)
    second = bl.fingerprint_for(bl.SOURCE_AI, two[0], root=tmp_path)
    # Different files, so the prints differ -- but only by path.
    assert first.replace("a.py", "") == second.replace("b.py", "")
