"""Tests for the shared TLS trust store.

The last test in this file is the one that matters most. The bug this module
exists to fix was not a wrong line of code -- it was a module that never
imported the trust store and so quietly used a different one. No unit test
would have caught that, because every individual call site looked fine. So the
guard is structural: walk the source of every module and fail if any TLS call
is made without the shared context.
"""

from __future__ import annotations

import ast
import ssl
from pathlib import Path

import pytest

import coldlight_trust as trust

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def fresh_context(monkeypatch):
    """The context is memoised, so a test that changes the CA environment
    would otherwise be answered by one an earlier test already built."""
    monkeypatch.delenv("COLDLIGHT_CA_BUNDLE", raising=False)
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    trust.reset()
    yield
    trust.reset()


# ---------------------------------------------------------------------------
# Verification is never weakened
# ---------------------------------------------------------------------------

def test_the_context_always_verifies():
    context = trust.ssl_context()
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED


def test_the_context_is_memoised():
    assert trust.ssl_context() is trust.ssl_context()


def test_reset_drops_the_memoised_context():
    first = trust.ssl_context()
    trust.reset()
    assert trust.ssl_context() is not first


def test_there_is_no_way_to_turn_verification_off():
    """No argument, environment variable or module flag may weaken the check.

    A stale bundle is a configuration problem with a configuration fix. If a
    future change adds an escape hatch, this is where it should be argued for
    rather than slipped in.
    """
    source = (ROOT / "coldlight_trust.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    signature = next(node for node in ast.walk(tree)
                     if isinstance(node, ast.FunctionDef)
                     and node.name == "ssl_context")
    assert not signature.args.args
    assert not signature.args.kwonlyargs

    for forbidden in ("CERT_" + "NONE", "CERT_" + "OPTIONAL",
                      "_create_unverified"):
        assert forbidden not in source, forbidden


# ---------------------------------------------------------------------------
# Bundle precedence
# ---------------------------------------------------------------------------

def test_an_explicit_bundle_wins(tmp_path, monkeypatch):
    bundle = tmp_path / "cacert.pem"
    bundle.write_text("# a path check, not a real bundle", encoding="utf-8")
    monkeypatch.setenv("COLDLIGHT_CA_BUNDLE", str(bundle))
    assert trust.ca_bundle() == str(bundle)
    assert trust.ca_bundle_source() == "COLDLIGHT_CA_BUNDLE"


def test_coldlight_variable_outranks_the_generic_one(tmp_path, monkeypatch):
    mine = tmp_path / "mine.pem"
    generic = tmp_path / "generic.pem"
    for path in (mine, generic):
        path.write_text("#", encoding="utf-8")
    monkeypatch.setenv("COLDLIGHT_CA_BUNDLE", str(mine))
    monkeypatch.setenv("SSL_CERT_FILE", str(generic))
    assert trust.ca_bundle() == str(mine)


def test_the_generic_variable_is_used_when_ours_is_unset(tmp_path,
                                                         monkeypatch):
    generic = tmp_path / "generic.pem"
    generic.write_text("#", encoding="utf-8")
    monkeypatch.setenv("SSL_CERT_FILE", str(generic))
    assert trust.ca_bundle() == str(generic)
    assert trust.ca_bundle_source() == "SSL_CERT_FILE"


def test_a_path_that_is_not_there_is_skipped_not_passed_on(tmp_path,
                                                           monkeypatch):
    """Falling through beats handing OpenSSL a path that does not exist --
    a typo should degrade, not break every connection."""
    monkeypatch.setenv("COLDLIGHT_CA_BUNDLE", str(tmp_path / "nope.pem"))
    assert trust.ca_bundle() != str(tmp_path / "nope.pem")


def test_a_skipped_variable_is_reported_rather_than_swallowed(tmp_path,
                                                              monkeypatch):
    """Falling through silently is the trap. Someone who set the variable to
    fix a verification error has to be able to find out it did nothing."""
    monkeypatch.setenv("COLDLIGHT_CA_BUNDLE", str(tmp_path / "nope.pem"))
    assert trust.ignored_ca_bundle_vars() == ["COLDLIGHT_CA_BUNDLE"]


def test_a_directory_does_not_count_as_a_bundle(tmp_path, monkeypatch):
    monkeypatch.setenv("COLDLIGHT_CA_BUNDLE", str(tmp_path))
    assert trust.ca_bundle() != str(tmp_path)


def test_nothing_is_reported_as_ignored_when_nothing_is_set():
    assert trust.ignored_ca_bundle_vars() == []


def test_the_source_is_named_even_with_no_variables_set():
    # certifi in a dev checkout, the system store without it. Either is a
    # real answer; "" would not be.
    assert trust.ca_bundle_source() in ("certifi", "system")


# ---------------------------------------------------------------------------
# The public surface vuln-intel used to own
# ---------------------------------------------------------------------------

def test_vulnintel_still_exposes_the_trust_helpers():
    """`ssl_context` and `ca_bundle` were part of its published surface, and
    other code (and other people's scripts) import them from there."""
    import coldlight_vulnintel as vi

    assert vi.ssl_context is trust.ssl_context
    assert vi.ca_bundle is trust.ca_bundle


def test_vulnintel_keeps_no_second_copy_of_the_cache():
    """A leftover `_ssl_ctx` there would mean anything resetting it had no
    effect while appearing to -- the same trap in a new place."""
    import coldlight_vulnintel as vi

    assert not hasattr(vi, "_ssl_ctx")


# ---------------------------------------------------------------------------
# The structural guard
# ---------------------------------------------------------------------------

# `coldlight_awareness.py` is the awareness payload. It is frozen into a tiny exe
# carrying only itself and `coldlight_config`, and it runs on a FOUND USB on
# someone else's machine -- where the assessor's COLDLIGHT_CA_BUNDLE is neither
# present nor relevant. The stdlib default context it gets verifies normally.
# Importing the trust store there would both bloat the payload and tie it to
# the assessor's environment.
EXEMPT = {
    "coldlight_awareness.py": "the payload runs on the subject's machine, not "
                           "the assessor's, and is frozen with only "
                           "coldlight_config beside it",
}


def _urlopen_calls(tree: ast.AST) -> list[ast.Call]:
    return [node for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and ((isinstance(node.func, ast.Attribute)
                  and node.func.attr == "urlopen")
                 or (isinstance(node.func, ast.Name)
                     and node.func.id == "urlopen"))]


def test_every_tls_call_uses_the_shared_trust_store():
    """The bug this module exists to fix, caught structurally.

    `coldlight_mail` called `urlopen` without a context, so `mail audit` used the
    system trust store while every other network call used the configured one
    -- and COLDLIGHT_CA_BUNDLE silently applied to some of ColdLight and not the
    rest. Every call site looked correct in isolation; only the set of them
    was wrong. Hence a test over the whole tree.
    """
    offenders: list[str] = []
    for path in sorted(ROOT.glob("coldlight*.py")):
        if path.name in EXEMPT:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for call in _urlopen_calls(tree):
            keywords = {kw.arg for kw in call.keywords}
            if "context" not in keywords:
                offenders.append(f"{path.name}:{call.lineno}")

    assert not offenders, (
        "urlopen without context=ssl_context() -- these calls use the system "
        f"trust store instead of the configured one: {offenders}. Import it "
        "from coldlight_trust, or add a justified entry to EXEMPT.")


def test_the_exemptions_are_real_files_with_stated_reasons():
    """An exemption that outlives the file it covers would silently widen."""
    for name, reason in EXEMPT.items():
        assert (ROOT / name).is_file(), f"EXEMPT names a missing file: {name}"
        assert len(reason) > 40, f"{name} needs a real reason, not a shrug"


def test_the_exempt_payload_really_does_make_a_tls_call():
    """If the payload stops calling urlopen, the exemption is dead weight and
    should go rather than sit there covering nothing."""
    tree = ast.parse((ROOT / "coldlight_awareness.py").read_text(
        encoding="utf-8"))
    assert _urlopen_calls(tree), (
        "coldlight_awareness.py no longer calls urlopen; drop it from EXEMPT")


def test_the_guard_would_actually_catch_an_unguarded_call():
    """A structural test that cannot fail is decoration. Prove it fires."""
    tree = ast.parse("import urllib.request\n"
                     "urllib.request.urlopen(req, timeout=5)\n")
    calls = _urlopen_calls(tree)
    assert len(calls) == 1
    assert "context" not in {kw.arg for kw in calls[0].keywords}


def test_the_guard_accepts_a_guarded_call():
    tree = ast.parse("import urllib.request\n"
                     "urllib.request.urlopen(req, timeout=5, context=ctx)\n")
    calls = _urlopen_calls(tree)
    assert len(calls) == 1
    assert "context" in {kw.arg for kw in calls[0].keywords}


def test_mail_imports_the_shared_trust_store():
    """The specific regression: it is the import that was missing, not a
    keyword argument."""
    source = (ROOT / "coldlight_mail.py").read_text(encoding="utf-8")
    assert "from coldlight_trust import ssl_context" in source


def test_the_trust_module_pulls_in_nothing_heavy():
    """Every network-using module imports this, so it has to stay cheap --
    otherwise someone will be tempted to avoid it again."""
    tree = ast.parse((ROOT / "coldlight_trust.py").read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert not any(name.startswith("coldlight") for name in imported), imported
    assert imported <= {"os", "ssl", "pathlib", "certifi", "__future__"}, (
        imported)
