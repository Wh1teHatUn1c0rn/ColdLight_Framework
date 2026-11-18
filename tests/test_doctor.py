"""Tests for the preflight dependency check.

No test here touches the network. The endpoint and resolver probes are
injected, which is also the point: `coldlight_doctor.run()` has to be callable
without egress, or it could not be tested in CI -- and a preflight that only
works on a healthy machine is not a preflight.

The local checks do shell out (`git --version` and friends) and do look at the
real PATH. That is deliberate: the thing under test is what this machine can
actually do, and a mocked `shutil.which` would test the mock.
"""

from __future__ import annotations

import json
import sys

import pytest

import coldlight_assess as ra
import coldlight_doctor as rd


@pytest.fixture(autouse=True)
def isolate(tmp_path, monkeypatch):
    """Keep the suite out of the operator's real cache and trust store.

    `coldlight_trust` memoises the shared SSL context, so a test that changes the
    CA environment would otherwise be answered from a context built by
    whichever test ran first.
    """
    import coldlight_trust as trust

    monkeypatch.setenv("COLDLIGHT_CACHE", str(tmp_path / "cache"))
    monkeypatch.delenv("COLDLIGHT_CA_BUNDLE", raising=False)
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    trust.reset()
    yield
    trust.reset()


# ---------------------------------------------------------------------------
# Probe doubles
# ---------------------------------------------------------------------------

def reach_ok(url, *, method="GET", payload=None, timeout=8):
    return 200, ""


def reach_refused(url, *, method="GET", payload=None, timeout=8):
    return 403, ""


def reach_server_error(url, *, method="GET", payload=None, timeout=8):
    return 500, ""


def reach_dead(url, *, method="GET", payload=None, timeout=8):
    return None, "Name or service not known"


def reach_tls_broken(url, *, method="GET", payload=None, timeout=8):
    return None, "TLS verification failed: certificate has expired"


def reach_exploding(url, *, method="GET", payload=None, timeout=8):
    raise RuntimeError("the probe itself blew up")


def resolve_ok(resolver):
    return ""


def resolve_dead(resolver):
    return "blocked by policy"


def resolve_only_google(resolver):
    return "" if "google" in resolver else "connection refused"


def endpoint(**kwargs):
    base = {"name": "Test service", "urls": ("https://example.test/a",)}
    base.update(kwargs)
    return rd.Endpoint(**base)


# ---------------------------------------------------------------------------
# Structural guards
#
# The profile filter matches checks by NAME. That coupling is invisible at
# runtime -- a renamed check silently drops out of `--profile` mode and the
# report looks fine. These three tests are the only thing that catches it.
# ---------------------------------------------------------------------------

def test_every_stage_need_names_a_real_check():
    produced = {c.name for c in rd.run(offline=True).checks}
    referenced = set(rd.ALWAYS)
    for needs in rd.STAGE_NEEDS.values():
        referenced.update(needs)
    missing = referenced - produced
    assert not missing, f"STAGE_NEEDS/ALWAYS name checks that do not exist: {missing}"


def test_every_assess_stage_is_in_stage_needs():
    """A stage added to `assess` must declare its dependencies here.

    Without this, a new stage would silently get an empty dependency set and
    `doctor --profile` would report it as needing nothing.
    """
    known = {name for name, _enabled, _fn in ra.STAGES}
    assert known == set(rd.STAGE_NEEDS), (
        f"assess stages and STAGE_NEEDS disagree: "
        f"only in assess={known - set(rd.STAGE_NEEDS)}, "
        f"only in doctor={set(rd.STAGE_NEEDS) - known}")


def test_check_names_are_unique():
    names = [c.name for c in rd.run(offline=True).checks]
    assert len(names) == len(set(names))


def test_every_check_belongs_to_a_known_group():
    for check in rd.run(offline=True).checks:
        assert check.group in rd.GROUP_ORDER


def test_every_check_has_a_known_status():
    for check in rd.run(offline=True).checks:
        assert check.status in rd.STATUS_ORDER


def test_a_blocking_check_without_a_remedy_would_be_a_dead_end():
    """Anything that can report MISSING has to say what to do about it."""
    for check in rd.run(offline=True).checks:
        if check.status == rd.STATUS_MISSING:
            assert check.remedy, f"{check.name} is missing with no remedy"


# ---------------------------------------------------------------------------
# Offline behaviour: skipped is not healthy
# ---------------------------------------------------------------------------

def test_offline_skips_the_network_without_calling_it():
    result = rd.run(offline=True, reach=reach_exploding,
                    resolve=resolve_dead)
    assert result.offline
    assert [c.name for c in result.unchecked]


def test_offline_network_checks_are_skipped_not_ok():
    result = rd.run(offline=True)
    network = result.by_group(rd.GROUP_NETWORK)
    assert network
    assert all(c.status == rd.STATUS_SKIPPED for c in network)
    assert not any(c.status == rd.STATUS_OK for c in network)


def test_skipped_checks_are_never_blocking():
    for check in rd.run(offline=True).by_group(rd.GROUP_NETWORK):
        assert not check.blocking


def test_an_offline_run_says_what_it_did_not_look_at():
    text = rd.text_report(rd.run(offline=True))
    assert "NOT CHECKED" in text
    assert "A clean report above does not cover them" in text


def test_healthy_does_not_mean_complete():
    """`healthy` ignores skipped checks, so it must never be read alone."""
    result = rd.DoctorResult(checks=[
        rd.Check(name="a", status=rd.STATUS_OK),
        rd.Check(name="b", status=rd.STATUS_SKIPPED, detail="offline"),
    ])
    assert result.healthy
    assert result.unchecked
    assert "what was not" in rd.text_report(result)


# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------

def test_all_ok_exits_zero():
    result = rd.DoctorResult(checks=[rd.Check(name="a", status=rd.STATUS_OK)])
    assert result.exit_code == 0


@pytest.mark.parametrize("status", [rd.STATUS_DEGRADED, rd.STATUS_MISSING,
                                    rd.STATUS_FAILED])
def test_a_non_fatal_problem_exits_one(status):
    result = rd.DoctorResult(checks=[
        rd.Check(name="a", status=rd.STATUS_OK),
        rd.Check(name="b", status=status),
    ])
    assert result.exit_code == 1


def test_only_a_fatal_problem_exits_two():
    result = rd.DoctorResult(checks=[
        rd.Check(name="b", status=rd.STATUS_FAILED, fatal=True),
    ])
    assert result.exit_code == 2
    assert result.fatal_checks


def test_a_skipped_only_result_still_exits_zero():
    """Skipping is the operator's choice; the text, not the code, carries it."""
    result = rd.DoctorResult(checks=[
        rd.Check(name="a", status=rd.STATUS_SKIPPED, detail="offline")])
    assert result.exit_code == 0


# ---------------------------------------------------------------------------
# Endpoint probing
# ---------------------------------------------------------------------------

def test_a_two_hundred_is_ok():
    check = rd.check_endpoint(endpoint(), reach=reach_ok)
    assert check.status == rd.STATUS_OK
    assert "HTTP 200" in check.detail


@pytest.mark.parametrize("probe", [reach_refused, reach_server_error])
def test_an_answering_host_is_degraded_not_failed(probe):
    """The host answered, so DNS, TCP and TLS all worked. Calling that a
    connectivity failure would send someone to debug the wrong layer."""
    check = rd.check_endpoint(endpoint(), reach=probe)
    assert check.status == rd.STATUS_DEGRADED
    assert "reachable" in check.detail


def test_rate_limiting_says_so():
    check = rd.check_endpoint(endpoint(), reach=reach_refused)
    assert "rate limiting" in check.remedy


def test_an_unreachable_host_is_failed():
    check = rd.check_endpoint(endpoint(affects=("scan deps",)),
                              reach=reach_dead)
    assert check.status == rd.STATUS_FAILED
    assert check.blocking
    assert "Name or service not known" in check.detail


def test_a_tls_failure_is_reported_as_a_trust_problem():
    check = rd.check_endpoint(endpoint(), reach=reach_tls_broken)
    assert check.status == rd.STATUS_FAILED
    assert "certificate has expired" in check.detail
    assert "trust store" in check.remedy


def test_the_mirror_is_used_when_the_primary_is_blocked():
    calls: list[str] = []

    def reach(url, *, method="GET", payload=None, timeout=8):
        calls.append(url)
        return (None, "blocked") if "primary" in url else (200, "")

    check = rd.check_endpoint(
        endpoint(urls=("https://primary.test/i", "https://mirror.test/i")),
        reach=reach)
    assert calls == ["https://primary.test/i", "https://mirror.test/i"]
    # Working, but not silently: a blocked primary is worth knowing.
    assert check.status == rd.STATUS_DEGRADED
    assert "primary unreachable" in check.detail
    assert not check.blocking


def test_the_mirror_is_not_consulted_when_the_primary_answers():
    calls: list[str] = []

    def reach(url, *, method="GET", payload=None, timeout=8):
        calls.append(url)
        return 200, ""

    rd.check_endpoint(
        endpoint(urls=("https://primary.test/i", "https://mirror.test/i")),
        reach=reach)
    assert calls == ["https://primary.test/i"]


def test_a_failure_explains_what_the_feed_was_for():
    """EPSS and Exploit-DB block no command outright. Without the note, their
    failure would read as unexplained noise."""
    check = rd.check_endpoint(
        endpoint(affects=(), note="exploitation-probability scores"),
        reach=reach_dead)
    assert "exploitation-probability scores" in check.remedy


def test_a_probe_that_raises_becomes_a_finding_not_a_crash():
    checks = rd.network_checks(reach=reach_exploding, resolve=resolve_ok)
    broken = [c for c in checks if c.status == rd.STATUS_FAILED]
    assert broken
    assert all("the check itself failed" in c.detail or c.detail
               for c in broken)


def test_network_check_order_is_stable():
    """Two runs of the same machine should diff cleanly, so the parallel
    probes are re-ordered back into the table's order."""
    first = [c.name for c in rd.network_checks(reach=reach_ok,
                                               resolve=resolve_ok)]
    second = [c.name for c in rd.network_checks(reach=reach_ok,
                                                resolve=resolve_ok)]
    assert first == second
    assert len(first) == len(set(first))


# ---------------------------------------------------------------------------
# What the probes send
# ---------------------------------------------------------------------------

def test_probes_send_a_fixed_payload_and_nothing_about_the_engagement():
    """The preflight runs before an assessment and talks to five external
    services. If a later change made it probe the target instead of a
    constant, this is the test that fails.
    """
    sent: list[tuple[str, str, str]] = []

    def recording(url, *, method="GET", payload=None, timeout=8):
        sent.append((url, method, json.dumps(payload, sort_keys=True)))
        return 200, ""

    rd.network_checks(reach=recording, resolve=resolve_ok)

    assert sent, "no endpoint was probed"
    for url, _method, body in sent:
        # A fixed, public query. Nothing derived from the machine, the
        # project, or the scope.
        assert "example.com" not in url
        assert body in ('null',
                        '{"package": {"ecosystem": "PyPI", "name": "requests"},'
                        ' "version": "2.31.0"}')


def test_the_large_feeds_are_probed_with_head():
    """The KEV feed and the Exploit-DB index are multi-megabyte. A preflight
    that downloaded both would cost more than the command it precedes."""
    methods = {}

    def recording(url, *, method="GET", payload=None, timeout=8):
        methods[url] = method
        return 200, ""

    rd.network_checks(reach=recording, resolve=resolve_ok)
    heavy = [m for url, m in methods.items()
             if "known_exploited" in url or "files_exploits" in url]
    assert heavy
    assert all(m == "HEAD" for m in heavy)


# ---------------------------------------------------------------------------
# DNS-over-HTTPS: one check, because one resolver is enough
# ---------------------------------------------------------------------------

def test_both_resolvers_answering_is_ok():
    check = rd.check_doh(resolve=resolve_ok)
    assert check.status == rd.STATUS_OK
    assert not check.blocking


def test_one_working_resolver_keeps_mail_audit_available():
    """`mail audit` tries resolvers in order and needs one. Reporting each
    separately would condemn the command on a blocked Cloudflare."""
    check = rd.check_doh(resolve=resolve_only_google)
    assert check.status == rd.STATUS_DEGRADED
    assert not check.blocking
    assert "dns.google" in check.detail
    assert "cloudflare-dns.com" in check.detail

    result = rd.DoctorResult(checks=[check])
    assert "mail audit" not in dict(result.unavailable)


def test_no_resolver_answering_takes_mail_audit_out():
    check = rd.check_doh(resolve=resolve_dead)
    assert check.status == rd.STATUS_FAILED
    assert check.blocking

    result = rd.DoctorResult(checks=[check])
    assert "mail audit" in dict(result.unavailable)


def test_the_doh_check_covers_every_configured_resolver():
    import coldlight_mail as mail

    asked: list[str] = []

    def recording(resolver):
        asked.append(resolver)
        return ""

    rd.check_doh(resolve=recording)
    assert asked == list(mail.DOH_RESOLVERS)


# ---------------------------------------------------------------------------
# TLS trust store
# ---------------------------------------------------------------------------

def test_a_ca_bundle_pointing_nowhere_is_reported_not_ignored(monkeypatch,
                                                              tmp_path):
    """The loader drops an unreadable COLDLIGHT_CA_BUNDLE silently. Someone who
    set it to fix a verification error deserves to be told it did nothing."""
    monkeypatch.setenv("COLDLIGHT_CA_BUNDLE", str(tmp_path / "nope.pem"))
    check = rd.check_ca_bundle()
    assert check.status == rd.STATUS_DEGRADED
    assert "does not exist" in check.detail
    assert "being ignored" in check.remedy


def test_a_real_ca_bundle_is_named_by_its_variable(monkeypatch):
    """Uses certifi's own bundle: a genuinely loadable PEM beats a fixture,
    because the check's real work is handing the file to OpenSSL."""
    certifi = pytest.importorskip("certifi")
    import coldlight_trust as trust

    monkeypatch.setenv("COLDLIGHT_CA_BUNDLE", certifi.where())
    trust.reset()

    check = rd.check_ca_bundle()
    assert check.status == rd.STATUS_OK
    assert "COLDLIGHT_CA_BUNDLE" in check.detail
    assert check.path == certifi.where()


def test_a_malformed_ca_bundle_fails_rather_than_passing(monkeypatch,
                                                         tmp_path):
    import coldlight_trust as trust

    bundle = tmp_path / "junk.pem"
    bundle.write_text("this is not a certificate", encoding="utf-8")
    monkeypatch.setenv("COLDLIGHT_CA_BUNDLE", str(bundle))
    trust.reset()

    check = rd.check_ca_bundle()
    assert check.status == rd.STATUS_FAILED
    assert check.blocking
    assert "Never disable certificate checking" in check.remedy


def test_the_trust_store_check_never_suggests_weakening_verification():
    """A TLS failure is the one place a tool is tempted to offer the easy fix.
    The remedy may only ever point at a better trust store.

    The forbidden phrases are assembled at runtime rather than written out:
    spelled literally they are exactly what `scan code` flags as CWE-295, and
    this project scans its own tree in CI.
    """
    forbidden = ("verify" + "=False", "CERT_" + "NONE",
                 "check_hostname", "_create_unverified")
    for check in rd.run(offline=True).by_group(rd.GROUP_TRUST):
        for phrase in forbidden:
            assert phrase not in check.remedy, (check.name, phrase)
        assert "skip" not in check.remedy.lower()


# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------

def test_an_old_python_is_fatal(monkeypatch):
    monkeypatch.setattr(sys, "version_info", (3, 10, 12, "final", 0))
    check = rd.check_python()
    assert check.status == rd.STATUS_FAILED
    assert check.fatal
    assert "3.11" in check.detail or "3.11" in check.remedy


def test_this_python_passes():
    check = rd.check_python()
    assert check.status == rd.STATUS_OK


def test_tomllib_is_present_here():
    assert rd.check_tomllib().status == rd.STATUS_OK


def test_a_python_without_tomllib_is_fatal(monkeypatch):
    """Checked by import rather than inferred from the version: a stripped
    build can satisfy the floor and still lack the module."""
    monkeypatch.setattr(rd.importlib.util, "find_spec",
                        lambda name, *a, **k: None)
    check = rd.check_tomllib()
    assert check.status == rd.STATUS_MISSING
    assert check.fatal
    assert rd.DoctorResult(checks=[check]).exit_code == 2


def test_sqlite_is_proved_by_opening_a_database():
    check = rd.check_sqlite()
    assert check.status == rd.STATUS_OK
    assert "SQLite" in check.detail


def test_a_python_without_ssl_skips_the_network_rather_than_crashing(
        monkeypatch):
    """`skipped_network_checks` is reached on a Python with no ssl module, and
    the modules owning the endpoint URLs cannot be imported there."""
    def exploding_endpoints():
        raise ImportError("No module named 'ssl'")

    monkeypatch.setattr(rd, "_endpoints", exploding_endpoints)
    checks = rd.skipped_network_checks("no ssl")

    assert checks
    assert all(c.status == rd.STATUS_SKIPPED for c in checks)
    assert "mail audit" in checks[0].affects


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

def test_a_missing_tool_names_the_commands_it_costs(monkeypatch):
    monkeypatch.setattr(rd.shutil, "which", lambda _name: None)
    check = rd.check_git()
    assert check.status == rd.STATUS_MISSING
    assert check.affects == ("scan history",)
    assert not check.fatal          # one command, not the whole tool


def test_a_missing_binary_is_not_fatal(monkeypatch):
    """Binaries are found on PATH..."""
    monkeypatch.setattr(rd.shutil, "which", lambda _name: None)
    for check in (rd.check_git(), rd.check_gpg(), rd.check_openssl_tool()):
        assert check.status == rd.STATUS_MISSING
        assert not check.fatal
        assert check.affects
    assert rd.DoctorResult(checks=[rd.check_git()]).exit_code == 1


def test_a_missing_optional_package_is_not_fatal(monkeypatch):
    """...while the optional extras are found as importable modules. Patching
    the wrong one of the two leaves these reporting ok, which is how this test
    came to exist."""
    monkeypatch.setattr(rd.importlib.util, "find_spec",
                        lambda name, *a, **k: None)
    for check in (rd.check_pyinstaller(), rd.check_qrcode()):
        assert check.status == rd.STATUS_MISSING
        assert not check.fatal
        assert check.affects
    assert rd.DoctorResult(checks=[rd.check_qrcode()]).exit_code == 1


def test_signtool_is_not_applicable_off_windows(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    check = rd.check_signtool()
    assert check.status == rd.STATUS_SKIPPED
    assert not check.blocking
    assert "Windows-only" in check.detail


def test_openssl_is_asked_for_its_version_the_way_it_accepts(monkeypatch):
    """`openssl --version` is a usage error on OpenSSL 1.x and LibreSSL, and
    the error text got reported as if it were a version."""
    recorded: dict = {}

    def fake(path, args, *, timeout=10):
        recorded["args"] = args
        return "OpenSSL 1.1.1k  25 Mar 2021"

    monkeypatch.setattr(rd.shutil, "which", lambda _n: "/usr/bin/openssl")
    monkeypatch.setattr(rd, "_tool_version", fake)
    check = rd.check_openssl_tool()
    assert recorded["args"] == ("version",)
    assert check.detail.startswith("OpenSSL")


def test_tool_version_reads_a_real_command():
    assert "Python" in rd._tool_version(sys.executable, ("--version",))


def test_tool_version_survives_a_tool_that_is_not_there():
    assert rd._tool_version("definitely-not-a-real-binary-xyz",
                            ("--version",)) == ""


def test_a_tool_with_no_version_flag_still_reports_found(monkeypatch):
    monkeypatch.setattr(rd.shutil, "which", lambda _n: "C:/sdk/signtool.exe")
    monkeypatch.setattr(sys, "platform", "win32")
    check = rd.check_signtool()
    assert check.status == rd.STATUS_OK
    assert check.detail == "found"


# ---------------------------------------------------------------------------
# Local storage
# ---------------------------------------------------------------------------

def test_an_unwritable_cache_is_slow_not_broken(monkeypatch, tmp_path):
    import coldlight_vulnintel as vi

    directory = tmp_path / "ro"
    directory.mkdir()
    monkeypatch.setattr(vi, "cache_dir", lambda: directory)

    def deny(*_args, **_kwargs):
        raise OSError(13, "Permission denied")

    monkeypatch.setattr(rd.Path, "write_text", deny)
    check = rd.check_cache_dir()
    assert check.status == rd.STATUS_DEGRADED
    assert not check.blocking          # scans still work, just slower
    assert "re-download" in check.remedy


def test_an_empty_cache_is_ok_and_says_feeds_come_later():
    check = rd.check_cache_dir()
    assert check.status == rd.STATUS_OK
    assert "empty" in check.detail or "cached feed" in check.detail


# ---------------------------------------------------------------------------
# Profile narrowing
# ---------------------------------------------------------------------------

def profile_file(tmp_path, body: str):
    path = tmp_path / "profile.toml"
    path.write_text(body, encoding="utf-8")
    return path


def test_a_profile_narrows_the_run_to_what_it_needs(tmp_path):
    path = profile_file(tmp_path, """
[metadata]
engagement_id = "ENG-1"
authorization_reference = "SOW-1"

[stages.history]
paths = ["."]
""")
    stages, name = rd.stages_for_profile(path)
    assert stages == ["git history"]

    result = rd.run(offline=True, stages=stages, profile=name)
    names = {c.name for c in result.checks}
    assert "git" in names
    # Nothing in this profile builds, signs or renders a QR poster.
    assert "PyInstaller" not in names
    assert "GnuPG" not in names
    assert "DNS-over-HTTPS" not in names
    # The universals are always checked.
    assert set(rd.ALWAYS) <= names


def test_a_mail_profile_checks_dns_and_not_git(tmp_path):
    path = profile_file(tmp_path, """
[metadata]
engagement_id = "ENG-1"
authorization_reference = "SOW-1"

[stages.mail]
domains = ["example.com"]
""")
    stages, _ = rd.stages_for_profile(path)
    assert stages == ["email posture"]
    names = {c.name for c in rd.run(offline=True, stages=stages).checks}
    assert "DNS-over-HTTPS" in names
    assert "git" not in names


def test_an_unreadable_profile_is_a_clear_error(tmp_path):
    with pytest.raises(rd.DoctorError):
        rd.stages_for_profile(tmp_path / "missing.toml")


def test_a_malformed_profile_is_a_clear_error(tmp_path):
    path = profile_file(tmp_path, "this is not = = valid toml")
    with pytest.raises(rd.DoctorError):
        rd.stages_for_profile(path)


def test_stages_with_no_external_dependency_are_named_not_omitted():
    assert rd.local_stages(["source code", "git history"]) == ["source code"]
    text = rd.text_report(rd.run(offline=True, stages=["source code"],
                                 profile="p.toml"))
    assert "no external dependency" in text


def test_failing_stages_maps_a_broken_dependency_back_to_its_stage():
    result = rd.DoctorResult(checks=[
        rd.Check(name="git", status=rd.STATUS_MISSING,
                 detail="git is not on PATH", affects=("scan history",)),
    ])
    assert rd.failing_stages(result, ["git history", "source code"]) == [
        ("git history", "git: git is not on PATH")]


def test_a_healthy_dependency_dooms_no_stage():
    result = rd.DoctorResult(checks=[
        rd.Check(name="git", status=rd.STATUS_OK, detail="git version 2.4")])
    assert rd.failing_stages(result, ["git history"]) == []


def test_a_degraded_dependency_dooms_no_stage():
    """Degraded means it works. Only MISSING and FAILED take a stage out."""
    result = rd.DoctorResult(checks=[
        rd.Check(name="DNS-over-HTTPS", status=rd.STATUS_DEGRADED,
                 detail="one resolver blocked", affects=("mail audit",))])
    assert rd.failing_stages(result, ["email posture"]) == []


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def test_the_report_lists_commands_rather_than_only_dependencies():
    """The payoff: an operator wants to know what will not work, not which
    binary is absent."""
    result = rd.DoctorResult(checks=[
        rd.Check(name="git", status=rd.STATUS_MISSING,
                 detail="git is not on PATH", affects=("scan history",)),
        rd.Check(name="PyInstaller", status=rd.STATUS_MISSING,
                 detail="PyInstaller is not installed", affects=("build",)),
    ])
    text = rd.text_report(result)
    assert "Commands that will not work on this machine" in text
    assert "scan history" in text
    assert "build" in text
    assert "the 2 commands listed above" in text


def test_one_broken_command_reads_as_singular():
    result = rd.DoctorResult(checks=[
        rd.Check(name="git", status=rd.STATUS_MISSING, detail="absent",
                 affects=("scan history",))])
    assert "the 1 command listed above" in rd.text_report(result)


def test_a_command_broken_twice_is_named_once_by_the_worse_cause():
    result = rd.DoctorResult(checks=[
        rd.Check(name="b", status=rd.STATUS_MISSING, detail="missing cause",
                 affects=("scan deps",)),
        rd.Check(name="a", status=rd.STATUS_FAILED, detail="failed cause",
                 affects=("scan deps",)),
    ])
    assert result.unavailable == [("scan deps", "failed cause")]


def test_a_fatal_result_says_nothing_will_work():
    result = rd.DoctorResult(checks=[
        rd.Check(name="Python", status=rd.STATUS_FAILED, fatal=True,
                 detail="3.9.1 -- ColdLight needs 3.11 or newer",
                 affects=("every command",))])
    text = rd.text_report(result)
    assert "ColdLight cannot run on this machine." in text
    assert "3.9.1" in text


def test_a_fully_healthy_result_says_so_without_hedging():
    result = rd.DoctorResult(checks=[rd.Check(name="a", status=rd.STATUS_OK)])
    assert "Every dependency checked out." in rd.text_report(result)


def test_the_report_names_the_profile_it_narrowed_to(tmp_path):
    text = rd.text_report(rd.run(offline=True, stages=["git history"],
                                 profile="scope/prof.toml"))
    assert "scope/prof.toml" in text
    assert "Checking only what this profile needs." in text


def test_json_report_round_trips():
    payload = rd.json_report(rd.run(offline=True))
    again = json.loads(json.dumps(payload))
    assert again["tool"] == "coldlight-doctor"
    assert again["checks"]
    assert isinstance(again["checks"][0]["affects"], list)
    assert again["exit_code"] in (0, 1, 2)


def test_json_report_records_what_was_not_checked():
    payload = rd.json_report(rd.run(offline=True))
    assert payload["offline"] is True
    assert payload["not_checked"]


def test_json_report_carries_provenance():
    payload = rd.json_report(rd.run(offline=True))
    assert payload["coldlight_version"]
    assert payload["python"]["version"]
    assert payload["platform"]


# ---------------------------------------------------------------------------
# The short form `assess` prints
# ---------------------------------------------------------------------------

def test_preflight_is_one_line_when_everything_is_fine():
    result = rd.DoctorResult(checks=[
        rd.Check(name="a", status=rd.STATUS_OK),
        rd.Check(name="b", status=rd.STATUS_OK),
    ])
    lines = rd.preflight_lines(result)
    assert lines == ["preflight: 2 dependencies checked, all healthy"]


def test_preflight_names_the_stage_that_will_fail():
    result = rd.DoctorResult(
        checks=[rd.Check(name="git", status=rd.STATUS_MISSING,
                         detail="git is not on PATH",
                         affects=("scan history",))],
        profile_stages=["git history", "source code"])
    lines = rd.preflight_lines(result)
    assert any("git history" in line for line in lines)
    assert any("running anyway" in line for line in lines)


def test_preflight_mentions_a_degradation_without_condemning_a_stage():
    result = rd.DoctorResult(
        checks=[rd.Check(name="DNS-over-HTTPS", status=rd.STATUS_DEGRADED,
                         detail="cloudflare blocked, google answered",
                         affects=("mail audit",))],
        profile_stages=["email posture"])
    lines = rd.preflight_lines(result)
    assert any("DEGRADED" in line for line in lines)
    assert not any("will fail" in line for line in lines)


def test_preflight_lines_are_prefixed_for_a_shared_log():
    result = rd.DoctorResult(checks=[rd.Check(name="a", status=rd.STATUS_OK)])
    assert all(line.startswith("preflight: ")
               for line in rd.preflight_lines(result))


# ---------------------------------------------------------------------------
# A trust-store failure must not be blamed on the network
#
# Once DNS started sharing the one trust store, a bad CA bundle began taking
# the resolvers down with everything else -- and the remedy still said the
# network was blocking them.
# ---------------------------------------------------------------------------

def test_a_certificate_failure_in_dns_points_at_the_trust_store():
    def tls_broken(resolver):
        return "[X509: NO_CERTIFICATE_OR_CRL_FOUND] no certificate or crl found"

    check = rd.check_doh(resolve=tls_broken)
    assert check.status == rd.STATUS_FAILED
    assert "trust store" in check.remedy
    assert "blocked on this network" not in check.remedy


def test_a_genuine_network_block_in_dns_still_says_so():
    def refused(resolver):
        return "connection refused"

    check = rd.check_doh(resolve=refused)
    assert check.status == rd.STATUS_FAILED
    assert "blocked on this network" in check.remedy


@pytest.mark.parametrize("text,expected", [
    ("[X509: NO_CERTIFICATE_OR_CRL_FOUND] no certificate", True),
    ("SSLError: bad handshake", True),
    ("certificate has expired", True),
    ("connection refused", False),
    ("Name or service not known", False),
    ("timed out", False),
    ("", False),
])
def test_tls_errors_are_told_apart_from_unreachable_ones(text, expected):
    assert rd._looks_like_tls(text) is expected
