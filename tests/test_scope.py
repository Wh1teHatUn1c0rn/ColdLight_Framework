"""Tests for coldlight_scope (the authorization guard).

This module is a gate, so the tests are mostly about what it REFUSES. A guard
that fails open is worse than no guard, because it looks like one.
"""

import datetime

import pytest

import coldlight_scope as sc


UTC = datetime.timezone.utc


def at(year, month, day):
    return datetime.datetime(year, month, day, 12, 0, tzinfo=UTC)


def scope_file(tmp_path, body, name="scope.toml"):
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return path


GOOD = '''
[scope]
authorization_reference = "TICKET-4417"
authorized_by = "Jane Smith, CISO"
valid_from = "2026-11-01"
valid_until = "2026-12-01"
targets = ["https://staging.example.com/api", "*.dev.example.com"]
excluded = ["https://staging.example.com/api/admin"]
'''


# ---------------------------------------------------------------------------
# Parsing: what a scope entry may say
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw,host,port,path", [
    ("example.com", "example.com", None, ""),
    ("example.com/api", "example.com", None, "/api"),
    ("example.com:8443", "example.com", 8443, ""),
    ("http://localhost:8000", "localhost", 8000, ""),
    ("https://a.b.example.com/x/y", "a.b.example.com", None, "/x/y"),
    ("*.dev.example.com", "*.dev.example.com", None, ""),
    ("10.0.0.5", "10.0.0.5", None, ""),
    ("EXAMPLE.COM", "example.com", None, ""),
    ("example.com.", "example.com", None, ""),
])
def test_accepted_entries(raw, host, port, path):
    rule = sc.parse_rule(raw)
    assert rule.host == host
    assert rule.port == port
    assert rule.path == path


@pytest.mark.parametrize("raw,fragment", [
    ("", "empty"),
    ("*", "leading"),
    ("*.com", "too broad"),
    ("*.local", "too broad"),
    ("*.co.uk", "public suffix"),
    ("*.amazonaws.com", "public suffix"),
    ("foo.*.example.com", "leading"),
    ("*.*.example.com", "leading"),
    ("ftp://example.com", "not probeable"),
    ("file:///etc/passwd", "not probeable"),
    ("10.0.0.0/24", "CIDR"),
    ("192.168.0.0/16", "CIDR"),
    ("https://example.com/api?token=x", "query"),
    ("https://example.com/api#frag", "query"),
])
def test_refused_entries(raw, fragment):
    with pytest.raises(sc.ScopeError) as excinfo:
        sc.parse_rule(raw)
    assert fragment.lower() in str(excinfo.value).lower()


def test_wildcard_in_an_ip_is_refused():
    with pytest.raises(sc.ScopeError):
        sc.parse_rule("*.0.0.1")


# ---------------------------------------------------------------------------
# Deny by default
# ---------------------------------------------------------------------------

def test_empty_scope_authorises_nothing():
    """"Nothing configured" must never mean "everything permitted"."""
    scope = sc.Scope(authorization_reference="T")
    decision = scope.check("https://anything.example.com")
    assert decision.allowed is False
    assert "deny by default" in decision.reason


def test_unlisted_target_is_refused():
    scope = sc.Scope(authorization_reference="T",
                     targets=[sc.parse_rule("example.com")])
    assert scope.check("https://other.example.net").allowed is False


def test_listed_target_is_allowed_and_cites_the_authorization():
    scope = sc.Scope(authorization_reference="TICKET-9",
                     targets=[sc.parse_rule("example.com")])
    decision = scope.check("https://example.com/x")
    assert decision.allowed is True
    assert "TICKET-9" in decision.reason
    assert decision.authorization_reference == "TICKET-9"


def test_unprobeable_scheme_is_refused_at_check_time():
    scope = sc.Scope(authorization_reference="T",
                     targets=[sc.parse_rule("example.com")])
    assert scope.check("ftp://example.com").allowed is False


# ---------------------------------------------------------------------------
# Exclusions always win
# ---------------------------------------------------------------------------

def test_exclusion_beats_a_wildcard_target():
    scope = sc.Scope(authorization_reference="T",
                     targets=[sc.parse_rule("*.dev.example.com")],
                     excluded=[sc.parse_rule("prod.dev.example.com")])
    decision = scope.check("https://prod.dev.example.com/x")
    assert decision.allowed is False
    assert "excluded" in decision.reason


def test_exclusion_wins_regardless_of_ordering():
    """Precedence must come from the rule kind, not the file order."""
    target = sc.parse_rule("*.dev.example.com")
    carve_out = sc.parse_rule("prod.dev.example.com")

    first = sc.Scope(authorization_reference="T", targets=[target],
                     excluded=[carve_out])
    second = sc.Scope(authorization_reference="T", excluded=[carve_out],
                      targets=[target])
    for scope in (first, second):
        assert scope.check("https://prod.dev.example.com/").allowed is False


def test_excluded_path_covers_its_subtree():
    scope = sc.Scope(authorization_reference="T",
                     targets=[sc.parse_rule("example.com")],
                     excluded=[sc.parse_rule("example.com/admin")])
    assert scope.check("https://example.com/admin").allowed is False
    assert scope.check("https://example.com/admin/users").allowed is False
    assert scope.check("https://example.com/public").allowed is True


# ---------------------------------------------------------------------------
# Matching precision
# ---------------------------------------------------------------------------

def test_path_rule_matches_only_at_a_separator_boundary():
    """/api must not authorise /apikeys."""
    scope = sc.Scope(authorization_reference="T",
                     targets=[sc.parse_rule("example.com/api")])
    assert scope.check("https://example.com/api").allowed is True
    assert scope.check("https://example.com/api/chat").allowed is True
    assert scope.check("https://example.com/apikeys").allowed is False


def test_wildcard_covers_subdomains_but_not_the_apex():
    """Inferring the apex from "*.x" would quietly widen the scope."""
    scope = sc.Scope(authorization_reference="T",
                     targets=[sc.parse_rule("*.dev.example.com")])
    assert scope.check("https://a.dev.example.com/").allowed is True
    assert scope.check("https://a.b.dev.example.com/").allowed is True
    assert scope.check("https://dev.example.com/").allowed is False


def test_explicit_port_is_required_to_match():
    scope = sc.Scope(authorization_reference="T",
                     targets=[sc.parse_rule("http://localhost:8000")])
    assert scope.check("http://localhost:8000/chat").allowed is True
    assert scope.check("http://localhost:9000/chat").allowed is False


def test_rule_without_a_port_matches_any_port():
    scope = sc.Scope(authorization_reference="T",
                     targets=[sc.parse_rule("example.com")])
    assert scope.check("https://example.com:8443/x").allowed is True


def test_scheme_specific_rule_does_not_match_the_other_scheme():
    scope = sc.Scope(authorization_reference="T",
                     targets=[sc.parse_rule("https://example.com")])
    assert scope.check("https://example.com/x").allowed is True
    assert scope.check("http://example.com/x").allowed is False


def test_host_matching_is_case_insensitive():
    scope = sc.Scope(authorization_reference="T",
                     targets=[sc.parse_rule("example.com")])
    assert scope.check("https://EXAMPLE.COM/x").allowed is True


# ---------------------------------------------------------------------------
# The authorization window
# ---------------------------------------------------------------------------

def test_target_is_refused_before_the_window_opens():
    scope = sc.Scope(authorization_reference="T",
                     valid_from=datetime.date(2026, 12, 1),
                     targets=[sc.parse_rule("example.com")])
    decision = scope.check("https://example.com", now=at(2026, 11, 18))
    assert decision.allowed is False
    assert "does not start until" in decision.reason
    assert "2026-12-01" in decision.reason


def test_target_is_refused_after_the_window_closes():
    scope = sc.Scope(authorization_reference="T",
                     valid_until=datetime.date(2026, 11, 1),
                     targets=[sc.parse_rule("example.com")])
    decision = scope.check("https://example.com", now=at(2026, 11, 18))
    assert decision.allowed is False
    assert "expired" in decision.reason
    assert "2026-11-01" in decision.reason


def test_target_is_allowed_inside_the_window():
    scope = sc.Scope(authorization_reference="T",
                     valid_from=datetime.date(2026, 11, 1),
                     valid_until=datetime.date(2026, 12, 1),
                     targets=[sc.parse_rule("example.com")])
    assert scope.check("https://example.com", now=at(2026, 11, 18)).allowed


def test_window_boundaries_are_inclusive():
    scope = sc.Scope(authorization_reference="T",
                     valid_from=datetime.date(2026, 11, 18),
                     valid_until=datetime.date(2026, 11, 18),
                     targets=[sc.parse_rule("example.com")])
    assert scope.check("https://example.com", now=at(2026, 11, 18)).allowed


def test_no_window_means_unbounded():
    scope = sc.Scope(authorization_reference="T",
                     targets=[sc.parse_rule("example.com")])
    assert scope.window_error() == ""


# ---------------------------------------------------------------------------
# require()
# ---------------------------------------------------------------------------

def test_require_raises_with_the_decision_attached():
    scope = sc.Scope(authorization_reference="T",
                     targets=[sc.parse_rule("example.com")])
    with pytest.raises(sc.ScopeDenied) as excinfo:
        scope.require("https://other.example.net")
    assert excinfo.value.decision.allowed is False
    assert excinfo.value.decision.target == "https://other.example.net"


def test_require_returns_the_decision_when_allowed():
    scope = sc.Scope(authorization_reference="T",
                     targets=[sc.parse_rule("example.com")])
    assert scope.require("https://example.com/x").allowed is True


# ---------------------------------------------------------------------------
# The audit trail
# ---------------------------------------------------------------------------

def test_every_decision_is_recorded_including_refusals():
    """The refusals are the interesting half if anyone asks what you touched."""
    scope = sc.Scope(authorization_reference="T",
                     targets=[sc.parse_rule("example.com")])
    scope.check("https://example.com/a")
    scope.check("https://nope.example.net/b")
    scope.check("https://example.com/c")

    assert len(scope.decisions) == 3
    assert [d.allowed for d in scope.decisions] == [True, False, True]
    assert all(d.at for d in scope.decisions)


def test_decisions_survive_serialisation():
    scope = sc.Scope(authorization_reference="T",
                     targets=[sc.parse_rule("example.com")])
    scope.check("https://example.com/a")
    payload = scope.to_dict()
    assert payload["authorization_reference"] == "T"
    assert payload["targets"] == ["example.com"]
    assert len(payload["decisions"]) == 1
    assert payload["decisions"][0]["allowed"] is True


def test_decision_renders_readably():
    scope = sc.Scope(authorization_reference="T",
                     targets=[sc.parse_rule("example.com")])
    assert "ALLOWED" in str(scope.check("https://example.com"))
    assert "REFUSED" in str(scope.check("https://no.example.net"))


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def test_load_valid_scope(tmp_path):
    scope = sc.load_scope(scope_file(tmp_path, GOOD))
    assert scope.authorization_reference == "TICKET-4417"
    assert scope.authorized_by == "Jane Smith, CISO"
    assert scope.valid_from == datetime.date(2026, 11, 1)
    assert len(scope.targets) == 2
    assert len(scope.excluded) == 1


def test_missing_file_says_how_to_create_one(tmp_path):
    with pytest.raises(sc.ScopeError) as excinfo:
        sc.load_scope(tmp_path / "nope.toml")
    message = str(excinfo.value)
    assert "scope" in message.lower()
    assert "--init" in message


def test_placeholder_authorization_is_refused_not_warned(tmp_path):
    """Active probing has to be traceable to a real authorization."""
    body = GOOD.replace('"TICKET-4417"', '"CHANGE-ME"')
    with pytest.raises(sc.ScopeError) as excinfo:
        sc.load_scope(scope_file(tmp_path, body))
    assert "placeholder" in str(excinfo.value)


def test_missing_authorization_is_refused(tmp_path):
    body = '[scope]\ntargets = ["example.com"]\n'
    with pytest.raises(sc.ScopeError):
        sc.load_scope(scope_file(tmp_path, body))


def test_invalid_toml_is_reported_as_such(tmp_path):
    with pytest.raises(sc.ScopeError) as excinfo:
        sc.load_scope(scope_file(tmp_path, "[scope\nbroken"))
    assert "not valid TOML" in str(excinfo.value)


def test_backwards_window_is_refused(tmp_path):
    body = GOOD.replace('valid_until = "2026-12-01"',
                        'valid_until = "2026-10-01"')
    with pytest.raises(sc.ScopeError) as excinfo:
        sc.load_scope(scope_file(tmp_path, body))
    assert "before" in str(excinfo.value)


def test_bad_date_is_reported(tmp_path):
    body = GOOD.replace('valid_from = "2026-11-01"',
                        'valid_from = "the first of November"')
    with pytest.raises(sc.ScopeError) as excinfo:
        sc.load_scope(scope_file(tmp_path, body))
    assert "ISO date" in str(excinfo.value)


def test_an_overbroad_target_fails_the_load_not_the_run(tmp_path):
    """The time to refuse "*.com" is before anyone runs anything."""
    body = GOOD.replace('"*.dev.example.com"', '"*.com"')
    with pytest.raises(sc.ScopeError) as excinfo:
        sc.load_scope(scope_file(tmp_path, body))
    assert "too broad" in str(excinfo.value)


def test_scope_with_no_targets_loads_but_authorises_nothing(tmp_path):
    """A scope file may legitimately exist with nothing in scope yet."""
    body = '[scope]\nauthorization_reference = "T-1"\ntargets = []\n'
    scope = sc.load_scope(scope_file(tmp_path, body))
    assert scope.is_empty
    assert scope.check("https://example.com").allowed is False


def test_probe_section_is_carried_through(tmp_path):
    body = GOOD + '''
[probe]
url = "https://staging.example.com/api/chat"
response_path = "reply"

[probe.headers]
"Content-Type" = "application/json"
'''
    scope = sc.load_scope(scope_file(tmp_path, body))
    assert scope.probe["url"] == "https://staging.example.com/api/chat"
    assert scope.probe["headers"]["Content-Type"] == "application/json"


def test_targets_must_be_a_list(tmp_path):
    body = '[scope]\nauthorization_reference = "T"\ntargets = 7\n'
    with pytest.raises(sc.ScopeError) as excinfo:
        sc.load_scope(scope_file(tmp_path, body))
    assert "list" in str(excinfo.value)


# ---------------------------------------------------------------------------
# Template
# ---------------------------------------------------------------------------

def test_template_round_trips_through_the_loader(tmp_path):
    """The template must parse -- except for its deliberate placeholder."""
    path = tmp_path / "scope.toml"
    sc.write_template(path)
    with pytest.raises(sc.ScopeError) as excinfo:
        sc.load_scope(path)
    assert "placeholder" in str(excinfo.value)

    body = path.read_text(encoding="utf-8").replace(
        '"CHANGE-ME-TICKET"', '"TICKET-1"')
    path.write_text(body, encoding="utf-8")
    scope = sc.load_scope(path)
    assert scope.targets and scope.excluded


def test_template_will_not_overwrite_an_existing_scope_file(tmp_path):
    path = tmp_path / "scope.toml"
    path.write_text("# mine\n", encoding="utf-8")
    with pytest.raises(sc.ScopeError):
        sc.write_template(path)
    assert path.read_text(encoding="utf-8") == "# mine\n"


def test_summary_states_the_default(tmp_path):
    scope = sc.load_scope(scope_file(tmp_path, GOOD))
    summary = scope.summary()
    assert "Anything not listed above is refused." in summary
    assert "always win" in summary
    assert "TICKET-4417" in summary
