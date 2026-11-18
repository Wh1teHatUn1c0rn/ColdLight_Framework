"""Tests for coldlight_attest.

Most run offline: digest verification and the HMAC backend are pure stdlib, so
tampering can be proven without any external tool. The GnuPG/OpenSSL tests
skip when those binaries are absent.
"""

import json
import shutil
import subprocess
import sys

import pytest

import coldlight_attest as at


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def assessment(tmp_path, *, with_assurance=True, with_report_json=True):
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    (out / "report.md").write_text("# Report\n\n### RO-001 — a finding\n",
                                   encoding="utf-8")
    (out / "code.json").write_text(
        json.dumps({"findings": [{"rule_id": "R1"}], "files_scanned": 3}),
        encoding="utf-8")
    (out / "run.json").write_text(
        json.dumps({"exit_code": 1, "incomplete": False,
                    "stages_ok": 2, "stages_failed": 0}), encoding="utf-8")
    if with_report_json:
        (out / "report.json").write_text(
            json.dumps({"finding_count": 1, "raw_item_count": 1,
                        "known_exploited": 0,
                        "severity_counts": {"HIGH": 1}}), encoding="utf-8")
    if with_assurance:
        (out / "assurance.json").write_text(
            json.dumps({"classes_examined": 2, "classes_in_tool_scope": 7,
                        "classes_total": 14, "units_checked": 3,
                        "units_total": 3,
                        "unexamined": ["sbom", "detection"],
                        "failed": []}), encoding="utf-8")
    return out


# ---------------------------------------------------------------------------
# Hashing and serialisation
# ---------------------------------------------------------------------------

def test_sha256_file_matches_hashlib(tmp_path):
    import hashlib

    path = tmp_path / "x.bin"
    path.write_bytes(b"some bytes \x00\xff")
    assert at.sha256_file(path) == hashlib.sha256(path.read_bytes()).hexdigest()


def test_serialisation_is_deterministic():
    statement = {"b": 1, "a": {"z": [1, 2], "y": "x"}}
    assert at.serialise(statement) == at.serialise(dict(statement))
    assert at.serialise({"a": 1, "b": 2}) == at.serialise({"b": 2, "a": 1})


def test_serialisation_is_valid_json_and_readable():
    data = at.serialise({"a": 1, "nested": {"k": "v"}})
    assert json.loads(data) == {"a": 1, "nested": {"k": "v"}}
    assert b"\n" in data          # indented, for a human to inspect


# ---------------------------------------------------------------------------
# Building the statement
# ---------------------------------------------------------------------------

def test_statement_uses_the_in_toto_format(tmp_path):
    statement = at.build_statement(assessment(tmp_path))
    assert statement["_type"] == "https://in-toto.io/Statement/v1"
    assert statement["predicateType"].endswith("/assessment/v1")
    assert statement["subject"]
    assert statement["predicate"]["tool"]["name"] == "ColdLight"


def test_reports_are_subjects_and_scans_are_inputs(tmp_path):
    statement = at.build_statement(assessment(tmp_path))
    subjects = {s["name"] for s in statement["subject"]}
    inputs = {i["name"] for i in statement["predicate"]["inputs"]}

    assert "report.md" in subjects
    assert "report.json" in subjects
    assert "code.json" in inputs
    assert "run.json" in inputs
    assert not (subjects & inputs)        # nothing counted twice


def test_every_recorded_file_carries_a_digest(tmp_path):
    statement = at.build_statement(assessment(tmp_path))
    entries = statement["subject"] + statement["predicate"]["inputs"]
    assert entries
    for entry in entries:
        assert len(entry["digest"]["sha256"]) == 64
        assert entry["bytes"] > 0


def test_the_attestation_covers_scope_not_just_content(tmp_path):
    """Signing '17 findings' is near-worthless if nobody can tell whether 17
    came from assessing everything or one directory."""
    statement = at.build_statement(assessment(tmp_path))
    assurance = statement["predicate"]["assurance"]
    assert assurance["present"] is True
    assert assurance["classesExamined"] == 2
    assert assurance["classesInToolScope"] == 7
    assert assurance["unexamined"] == ["sbom", "detection"]


def test_missing_assurance_is_called_out(tmp_path):
    statement = at.build_statement(assessment(tmp_path, with_assurance=False))
    assurance = statement["predicate"]["assurance"]
    assert assurance["present"] is False
    assert "not attested" in assurance["note"]


def test_findings_and_run_summaries_are_recorded(tmp_path):
    predicate = at.build_statement(assessment(tmp_path))["predicate"]
    assert predicate["findings"]["total"] == 1
    assert predicate["run"]["incomplete"] is False


def test_disclaimer_is_always_present(tmp_path):
    predicate = at.build_statement(assessment(tmp_path))["predicate"]
    assert "not exploitation" in predicate["disclaimer"]
    assert "unknown rather than clean" in predicate["disclaimer"]


def test_a_directory_with_no_report_is_refused(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(at.AttestError, match="no report to attest"):
        at.build_statement(empty)


def test_missing_directory_is_refused(tmp_path):
    with pytest.raises(at.AttestError, match="no such directory"):
        at.build_statement(tmp_path / "nope")


def test_the_attestation_does_not_record_itself(tmp_path):
    out = assessment(tmp_path)
    at.write_statement(at.build_statement(out), out)
    second = at.build_statement(out)       # build again, now that it exists
    names = {i["name"] for i in second["predicate"]["inputs"]}
    assert at.ATTESTATION_NAME not in names


# ---------------------------------------------------------------------------
# Tamper detection -- no external tool needed
# ---------------------------------------------------------------------------

def test_untouched_assessment_verifies(tmp_path):
    out = assessment(tmp_path)
    at.write_statement(at.build_statement(out), out)
    result = at.verify(out)
    assert result.digests_ok is True
    assert result.checked >= 4
    assert result.mismatched == []


def test_an_edited_report_is_detected(tmp_path):
    out = assessment(tmp_path)
    at.write_statement(at.build_statement(out), out)

    (out / "report.md").write_text("# Report\n\n(finding deleted)\n",
                                   encoding="utf-8")
    result = at.verify(out)
    assert result.digests_ok is False
    assert "report.md" in result.mismatched
    assert result.ok is False
    assert "do not rely" in at.verify_report(result)


def test_an_edited_input_is_detected(tmp_path):
    """The evidence behind the report matters as much as the report."""
    out = assessment(tmp_path)
    at.write_statement(at.build_statement(out), out)

    (out / "code.json").write_text(json.dumps({"findings": []}),
                                   encoding="utf-8")
    result = at.verify(out)
    assert "code.json" in result.mismatched


def test_a_deleted_file_is_detected(tmp_path):
    out = assessment(tmp_path)
    at.write_statement(at.build_statement(out), out)
    (out / "code.json").unlink()

    result = at.verify(out)
    assert result.digests_ok is False
    assert "code.json" in result.missing


def test_verify_without_an_attestation_is_refused(tmp_path):
    with pytest.raises(at.AttestError, match="no attestation"):
        at.verify(assessment(tmp_path))


def test_malformed_attestation_is_refused(tmp_path):
    out = assessment(tmp_path)
    (out / at.ATTESTATION_NAME).write_text("{not json", encoding="utf-8")
    with pytest.raises(at.AttestError, match="not valid JSON"):
        at.verify(out)


# ---------------------------------------------------------------------------
# Exit-code semantics: an INVALID signature is not the same as NO signature
# ---------------------------------------------------------------------------

def test_invalid_signature_makes_the_result_not_ok():
    """Regression: the CLI once exited 0 on a BAD signature unless
    --require-signature was passed. An invalid signature is evidence of
    tampering and must always fail."""
    result = at.VerifyResult(digests_ok=True, signature_ok=False)
    assert result.ok is False


def test_absent_signature_still_allows_ok():
    """Unsigned is 'cannot tell', not 'proven bad' -- a different thing."""
    result = at.VerifyResult(digests_ok=True, signature_ok=None)
    assert result.ok is True


def test_bad_digests_are_never_ok():
    assert at.VerifyResult(digests_ok=False, signature_ok=True).ok is False


def test_report_distinguishes_unsigned_from_invalid():
    unsigned = at.verify_report(
        at.VerifyResult(digests_ok=True, signature_ok=None, checked=3))
    assert "SIGNATURE UNVERIFIED" in unsigned
    assert "Treat as unsigned" in unsigned

    invalid = at.verify_report(
        at.VerifyResult(digests_ok=True, signature_ok=False, checked=3))
    assert "VERIFICATION FAILED" in invalid


def test_report_states_the_trust_model():
    verified = at.verify_report(
        at.VerifyResult(digests_ok=True, signature_ok=True, checked=3))
    assert "VERIFIED" in verified
    # An unverifiable signature is worse than none, so say what it rests on.
    assert "channel you trust" in verified


# ---------------------------------------------------------------------------
# HMAC backend (stdlib, so fully testable)
# ---------------------------------------------------------------------------

def test_hmac_round_trip(tmp_path, monkeypatch):
    monkeypatch.setenv("COLDLIGHT_TEST_SECRET", "correct horse battery staple")
    out = assessment(tmp_path)
    path = at.write_statement(at.build_statement(out), out)

    result = at.sign(path, at.BACKEND_HMAC, key_env="COLDLIGHT_TEST_SECRET")
    assert result.signature_path.endswith(".hmac")

    verified = at.verify(out, key_env="COLDLIGHT_TEST_SECRET")
    assert verified.signature_ok is True
    assert verified.signature_backend == at.BACKEND_HMAC


def test_hmac_detects_a_modified_attestation(tmp_path, monkeypatch):
    monkeypatch.setenv("COLDLIGHT_TEST_SECRET", "s3cret")
    out = assessment(tmp_path)
    path = at.write_statement(at.build_statement(out), out)
    at.sign(path, at.BACKEND_HMAC, key_env="COLDLIGHT_TEST_SECRET")

    statement = json.loads(path.read_text(encoding="utf-8"))
    statement["predicate"]["findings"]["total"] = 0
    path.write_bytes(at.serialise(statement))

    assert at.verify(out, key_env="COLDLIGHT_TEST_SECRET").signature_ok is False


def test_hmac_with_the_wrong_key_fails(tmp_path, monkeypatch):
    monkeypatch.setenv("COLDLIGHT_TEST_SECRET", "right")
    out = assessment(tmp_path)
    path = at.write_statement(at.build_statement(out), out)
    at.sign(path, at.BACKEND_HMAC, key_env="COLDLIGHT_TEST_SECRET")

    monkeypatch.setenv("COLDLIGHT_TEST_SECRET", "wrong")
    assert at.verify(out, key_env="COLDLIGHT_TEST_SECRET").signature_ok is False


def test_hmac_refuses_an_empty_secret(tmp_path, monkeypatch):
    monkeypatch.delenv("COLDLIGHT_NOPE", raising=False)
    out = assessment(tmp_path)
    path = at.write_statement(at.build_statement(out), out)
    with pytest.raises(at.AttestError, match="unset or empty"):
        at.sign(path, at.BACKEND_HMAC, key_env="COLDLIGHT_NOPE")


def test_hmac_file_warns_it_is_symmetric(tmp_path, monkeypatch):
    monkeypatch.setenv("COLDLIGHT_TEST_SECRET", "x")
    out = assessment(tmp_path)
    path = at.write_statement(at.build_statement(out), out)
    result = at.sign(path, at.BACKEND_HMAC, key_env="COLDLIGHT_TEST_SECRET")

    payload = json.loads(open(result.signature_path, encoding="utf-8").read())
    assert "forge" in payload["warning"]
    assert payload["alg"] == "HMAC-SHA256"


def test_hmac_secret_never_lands_in_the_signature_file(tmp_path, monkeypatch):
    secret = "super-secret-value-12345"
    monkeypatch.setenv("COLDLIGHT_TEST_SECRET", secret)
    out = assessment(tmp_path)
    path = at.write_statement(at.build_statement(out), out)
    result = at.sign(path, at.BACKEND_HMAC, key_env="COLDLIGHT_TEST_SECRET")
    assert secret not in open(result.signature_path, encoding="utf-8").read()


# ---------------------------------------------------------------------------
# Delegated backends: command construction, without executing anything
# ---------------------------------------------------------------------------

def test_unknown_backend_is_refused(tmp_path):
    out = assessment(tmp_path)
    path = at.write_statement(at.build_statement(out), out)
    with pytest.raises(at.AttestError, match="unknown backend"):
        at.sign(path, "magic-marker")


@pytest.mark.skipif(not shutil.which("gpg"), reason="gpg not installed")
def test_gpg_command_never_carries_a_passphrase(tmp_path):
    """Passphrases belong to gpg-agent, never to our argv -- a command line is
    visible to every other process on the box."""
    out = assessment(tmp_path)
    path = at.write_statement(at.build_statement(out), out)
    command = at.gpg_sign_command(path, key="someone@example.com")

    joined = " ".join(command).lower()
    assert "--passphrase" not in joined
    assert "--detach-sign" in joined
    assert "--armor" in joined


@pytest.mark.skipif(not shutil.which("openssl"), reason="openssl not installed")
def test_openssl_passphrase_is_passed_by_env_reference_only(tmp_path):
    out = assessment(tmp_path)
    path = at.write_statement(at.build_statement(out), out)
    command = at.openssl_sign_command(path, key="k.pem",
                                      passphrase_env="MY_PASS")
    assert "env:MY_PASS" in command        # the NAME, never the value
    joined = " ".join(command)
    assert "pass:" not in joined           # never the literal form


@pytest.mark.skipif(not shutil.which("openssl"), reason="openssl not installed")
def test_openssl_needs_a_key(tmp_path):
    out = assessment(tmp_path)
    path = at.write_statement(at.build_statement(out), out)
    with pytest.raises(at.AttestError, match="needs --key"):
        at.openssl_sign_command(path, key="")


def test_dry_run_executes_nothing(tmp_path, monkeypatch):
    out = assessment(tmp_path)
    path = at.write_statement(at.build_statement(out), out)

    def explode(*args, **kwargs):
        raise AssertionError("dry run must not execute a command")

    monkeypatch.setattr(subprocess, "run", explode)
    result = at.sign(path, at.BACKEND_HMAC, key_env="X", dry_run=True)
    assert "would HMAC" in result.detail


# ---------------------------------------------------------------------------
# End-to-end with real GnuPG, when available
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not shutil.which("gpg"), reason="gpg not installed")
def test_gpg_sign_and_verify_round_trip(tmp_path, monkeypatch):
    """Uses a throwaway keyring in tmp_path -- never the user's own."""
    home = tmp_path / "gnupg"
    home.mkdir(mode=0o700)
    monkeypatch.setenv("GNUPGHOME", str(home))

    created = subprocess.run(
        ["gpg", "--batch", "--yes", "--passphrase", "",
         "--quick-generate-key", "ColdLight Suite <suite@invalid>",
         "default", "default", "never"],
        capture_output=True, text=True)
    if created.returncode != 0:
        pytest.skip(f"could not create a test key: "
                    f"{created.stderr.strip()[:120]}")

    out = assessment(tmp_path)
    path = at.write_statement(at.build_statement(out), out)
    at.sign(path, at.BACKEND_GPG, key="suite@invalid")

    result = at.verify(out)
    assert result.digests_ok is True
    assert result.signature_ok is True
    assert result.ok is True

    # Tamper with the signed statement: the signature must now fail.
    statement = json.loads(path.read_text(encoding="utf-8"))
    statement["predicate"]["findings"]["total"] = 999
    path.write_bytes(at.serialise(statement))

    tampered = at.verify(out)
    assert tampered.signature_ok is False
    assert tampered.ok is False
