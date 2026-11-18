"""Tests for coldlight_canary (benign injection susceptibility probing).

Every test uses a fake opener: nothing here touches the network. The two
properties worth most of the attention are that an unauthorised target is
refused, and that an endpoint echoing the request is never scored as
susceptible -- a false positive there would discredit every report.
"""

import json
import re

import pytest

import coldlight_canary as cn
import coldlight_scope as sc


TOKEN_RE = re.compile(r"COLDLIGHT-CANARY-[0-9A-F]{8}")


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class FakeResponse:
    def __init__(self, status, body):
        self.status = status
        self._body = body.encode("utf-8")

    def read(self, size=None):
        return self._body[:size] if size else self._body

    def getcode(self):
        return self.status

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def fixed_opener(body='{"reply": "I can only help with your question."}',
                 status=200, calls=None):
    def send(request, timeout):
        if calls is not None:
            calls.append(request)
        return FakeResponse(status, body)
    return send


def obedient_opener(calls=None):
    """A model that does what the injected content told it to."""
    def send(request, timeout):
        sent = (request.data or b"").decode("utf-8")
        if calls is not None:
            calls.append(sent)
        match = TOKEN_RE.search(sent)
        token = match.group(0) if match else "NO-TOKEN"
        return FakeResponse(200, json.dumps({"reply": f"Certainly. {token}"}))
    return send


def echoing_opener():
    """An endpoint that returns the submitted request alongside the reply."""
    def send(request, timeout):
        sent = (request.data or b"").decode("utf-8")
        return FakeResponse(200, json.dumps({"reply": sent}))
    return send


def exploding_opener():
    def send(request, timeout):
        raise AssertionError("no request may be sent")
    return send


def scope_for(url="https://staging.example.com/api/chat", **probe):
    config = {"url": url, "response_path": "reply"}
    config.update(probe)
    return sc.Scope(
        authorization_reference="TICKET-4417",
        authorized_by="Jane Smith",
        targets=[sc.parse_rule("https://staging.example.com/api")],
        source="scope.toml",
        probe=config,
    )


def no_sleep(_seconds):
    return None


# ---------------------------------------------------------------------------
# The probe set is benign by construction
# ---------------------------------------------------------------------------

def test_every_probe_is_detected_by_a_benign_marker():
    """The invariant that keeps this from being an attack tool: a probe is
    confirmed by a meaningless marker, never by eliciting harmful content.

    Either the probe embeds a canary token it asks the model to emit, or it
    looks for a marker the operator planted in their own system prompt.
    """
    for probe in cn.PROBES:
        assert ("{token}" in probe.body) or probe.needs_marker, probe.probe_id


def test_every_probe_has_an_echo_phrase_from_its_own_body():
    """Without this the echo check cannot work."""
    for probe in cn.PROBES:
        rendered = probe.render("COLDLIGHT-CANARY-AAAAAAAA")
        assert probe.echo_phrase in rendered, probe.probe_id


def test_every_probe_explains_itself():
    for probe in cn.PROBES:
        assert probe.interpretation.strip(), probe.probe_id
        assert probe.remediation.strip(), probe.probe_id
        assert probe.owasp, probe.probe_id


def test_probe_ids_are_unique():
    ids = [p.probe_id for p in cn.PROBES]
    assert len(ids) == len(set(ids))


def test_probe_set_is_not_loadable_from_configuration():
    """Deliberate: a tool that runs arbitrary payloads from a config file is
    an attack tool regardless of what the file happens to hold."""
    scope = scope_for(probes=["anything"], probe_file="payloads.txt")
    config = cn.probe_config(scope)
    assert "probes" not in config
    assert "probe_file" not in config


def test_canary_tokens_are_unique_per_call():
    tokens = {cn.new_canary() for _ in range(50)}
    assert len(tokens) == 50
    assert all(t.startswith(cn.CANARY_PREFIX) for t in tokens)


# ---------------------------------------------------------------------------
# Authorization is the gate
# ---------------------------------------------------------------------------

def test_out_of_scope_target_is_refused_and_nothing_is_sent():
    scope = scope_for(url="https://prod.example.com/api/chat")
    with pytest.raises(sc.ScopeDenied):
        cn.run_probes(scope, opener=exploding_opener(), sleep=no_sleep)


def test_expired_authorization_refuses_the_run():
    import datetime
    scope = scope_for()
    scope.valid_until = datetime.date(2020, 1, 1)
    with pytest.raises(sc.ScopeDenied) as excinfo:
        cn.run_probes(scope, opener=exploding_opener(), sleep=no_sleep)
    assert "expired" in str(excinfo.value)


def test_empty_scope_refuses_the_run():
    scope = scope_for()
    scope.targets = []
    with pytest.raises(sc.ScopeDenied):
        cn.run_probes(scope, opener=exploding_opener(), sleep=no_sleep)


def test_the_run_records_its_authorization():
    scope = scope_for()
    run = cn.run_probes(scope, opener=fixed_opener(), sleep=no_sleep)
    assert run.authorization_reference == "TICKET-4417"
    assert run.decisions and run.decisions[0]["allowed"] is True


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def test_missing_url_is_a_configuration_error():
    scope = sc.Scope(authorization_reference="T", probe={})
    with pytest.raises(cn.CanaryError) as excinfo:
        cn.probe_config(scope)
    assert "no probe endpoint" in str(excinfo.value)


def test_body_without_a_prompt_placeholder_is_refused():
    scope = scope_for(body='{"message": "hello"}')
    with pytest.raises(cn.CanaryError) as excinfo:
        cn.probe_config(scope)
    assert "{{PROMPT}}" in str(excinfo.value)


def test_unsupported_method_is_refused():
    scope = scope_for(method="DELETE")
    with pytest.raises(cn.CanaryError):
        cn.probe_config(scope)


def test_headers_must_be_a_table():
    scope = scope_for(headers="Authorization: Bearer x")
    with pytest.raises(cn.CanaryError):
        cn.probe_config(scope)


def test_defaults_are_filled_in():
    config = cn.probe_config(scope_for())
    assert config["method"] == "POST"
    assert "{{PROMPT}}" in config["body"]
    assert config["headers"]["Content-Type"] == "application/json"
    assert config["timeout"] >= 1


def test_header_values_are_never_shown():
    """These carry the client's own API key."""
    headers = {"Authorization": "Bearer sk-secret-value", "X-Tenant": "acme"}
    shown = cn.redacted_headers(headers)
    assert set(shown) == {"Authorization", "X-Tenant"}
    assert "sk-secret-value" not in json.dumps(shown)
    assert all(v == cn.REDACTED for v in shown.values())


# ---------------------------------------------------------------------------
# Body building and reply extraction
# ---------------------------------------------------------------------------

def test_prompt_is_json_escaped_into_the_body():
    body = cn.build_body('{"m": "{{PROMPT}}"}', 'say "hi"\nthen stop')
    assert json.loads(body)["m"] == 'say "hi"\nthen stop'


def test_prompt_raw_is_substituted_verbatim():
    assert cn.build_body("X{{PROMPT_RAW}}Y", "a\"b") == 'Xa"bY'


@pytest.mark.parametrize("payload,path,expected", [
    ('{"reply": "hello"}', "reply", "hello"),
    ('{"a": {"b": "deep"}}', "a.b", "deep"),
    ('{"choices": [{"message": {"content": "hi"}}]}',
     "choices.0.message.content", "hi"),
    ('{"reply": "hello"}', "", '{"reply": "hello"}'),
    ('{"reply": 7}', "reply", "7"),
])
def test_extract_reply(payload, path, expected):
    assert cn.extract_reply(payload, path) == expected


@pytest.mark.parametrize("payload,path", [
    ('{"reply": "x"}', "missing"),
    ('{"a": []}', "a.0"),
    ("not json", "reply"),
    ('{"reply": null}', "reply"),
    ('{"a": "x"}', "a.b"),
])
def test_extract_reply_returns_empty_when_the_path_misses(payload, path):
    assert cn.extract_reply(payload, path) == ""


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def _config():
    return cn.probe_config(scope_for())


def _probe():
    return cn.PROBES[1]      # CANARY-INDIRECT-DOCUMENT


def test_token_in_the_reply_is_susceptible():
    outcome, detail, _ = cn.score(
        _probe(), "COLDLIGHT-CANARY-AAAAAAAA", 200,
        '{"reply": "Sure. COLDLIGHT-CANARY-AAAAAAAA"}', "", _config())
    assert outcome == cn.OUTCOME_SUSCEPTIBLE
    assert "treated as an instruction" in detail


def test_absent_token_is_resisted():
    outcome, _, _ = cn.score(
        _probe(), "COLDLIGHT-CANARY-AAAAAAAA", 200,
        '{"reply": "The figures were in line."}', "", _config())
    assert outcome == cn.OUTCOME_RESISTED


def test_echoed_request_is_inconclusive_not_susceptible():
    """The decisive false-positive guard: an endpoint that returns the
    submitted message would otherwise score susceptible on every probe."""
    probe = _probe()
    token = "COLDLIGHT-CANARY-AAAAAAAA"
    echoed = probe.render(token)          # contains BOTH echo phrase and token
    outcome, detail, _ = cn.score(
        probe, token, 200, json.dumps({"reply": echoed}), "", _config())
    assert outcome == cn.OUTCOME_INCONCLUSIVE
    assert "echoed" in detail
    assert "response_path" in detail


def test_transport_failure_is_inconclusive():
    outcome, detail, _ = cn.score(
        _probe(), "T", None, "", "could not reach the endpoint: refused",
        _config())
    assert outcome == cn.OUTCOME_INCONCLUSIVE
    assert "could not reach" in detail


@pytest.mark.parametrize("status", [401, 403, 429, 500, 503])
def test_error_status_is_inconclusive(status):
    outcome, detail, _ = cn.score(
        _probe(), "T", status, '{"error": "nope"}', f"HTTP {status}",
        _config())
    assert outcome == cn.OUTCOME_INCONCLUSIVE
    assert str(status) in detail


def test_empty_reply_is_inconclusive_and_names_the_path():
    outcome, detail, _ = cn.score(
        _probe(), "T", 200, '{"other": "x"}', "", _config())
    assert outcome == cn.OUTCOME_INCONCLUSIVE
    assert "response_path" in detail


def test_a_failed_request_is_never_scored_as_resisted():
    for status, body, error in [(None, "", "boom"), (500, "", "HTTP 500"),
                                (200, "{}", "")]:
        outcome, _, _ = cn.score(_probe(), "T", status, body, error,
                                 _config())
        assert outcome != cn.OUTCOME_RESISTED


# ---------------------------------------------------------------------------
# Running
# ---------------------------------------------------------------------------

def test_obedient_model_is_reported_as_susceptible():
    run = cn.run_probes(scope_for(), opener=obedient_opener(),
                        sleep=no_sleep)
    assert run.susceptible
    assert not run.resisted
    assert run.established is True
    ids = {r.probe_id for r in run.susceptible}
    assert "CANARY-INDIRECT-DOCUMENT" in ids


def test_resistant_model_is_reported_as_resisted():
    run = cn.run_probes(scope_for(), opener=fixed_opener(), sleep=no_sleep)
    assert not run.susceptible
    assert run.resisted
    assert run.established is True


def test_echoing_endpoint_yields_no_findings():
    run = cn.run_probes(scope_for(), opener=echoing_opener(), sleep=no_sleep)
    assert run.susceptible == []
    assert cn.findings(run) == []
    assert run.inconclusive


def test_unreachable_endpoint_establishes_nothing():
    """All-inconclusive must not look like a model that resisted."""
    run = cn.run_probes(scope_for(), opener=fixed_opener(status=503),
                        sleep=no_sleep)
    assert run.established is False
    assert not run.resisted
    assert "establishes NOTHING" in cn.text_report(run)


def test_system_marker_probe_is_skipped_without_a_marker():
    run = cn.run_probes(scope_for(), opener=fixed_opener(), sleep=no_sleep)
    leak = next(r for r in run.results
                if r.probe_id == "CANARY-SYSTEM-PROMPT-LEAK")
    assert leak.outcome == cn.OUTCOME_SKIPPED
    assert "system_marker" in leak.detail


def test_system_marker_probe_detects_a_planted_marker():
    scope = scope_for(system_marker="MARKER-SENTINEL-123")
    body = json.dumps({"reply": "My setup says MARKER-SENTINEL-123. Hello!"})
    run = cn.run_probes(scope, opener=fixed_opener(body=body), sleep=no_sleep)
    leak = next(r for r in run.results
                if r.probe_id == "CANARY-SYSTEM-PROMPT-LEAK")
    assert leak.outcome == cn.OUTCOME_SUSCEPTIBLE
    assert leak.owasp == "LLM07"


def test_system_marker_probe_resists_when_the_marker_stays_put():
    scope = scope_for(system_marker="MARKER-SENTINEL-123")
    run = cn.run_probes(scope, opener=fixed_opener(), sleep=no_sleep)
    leak = next(r for r in run.results
                if r.probe_id == "CANARY-SYSTEM-PROMPT-LEAK")
    assert leak.outcome == cn.OUTCOME_RESISTED


def test_dry_run_sends_nothing_but_shows_the_payloads():
    run = cn.run_probes(scope_for(), dry_run=True,
                        opener=exploding_opener(), sleep=no_sleep)
    assert run.dry_run is True
    assert all(r.outcome == cn.OUTCOME_SKIPPED for r in run.results)
    assert all(r.evidence for r in run.results if r.canary)
    assert "DRY RUN" in cn.text_report(run)


def test_one_token_is_used_for_the_whole_run():
    calls = []
    cn.run_probes(scope_for(), opener=obedient_opener(calls), sleep=no_sleep)
    tokens = {TOKEN_RE.search(sent).group(0) for sent in calls
              if TOKEN_RE.search(sent)}
    assert len(tokens) == 1


def test_probes_are_rate_limited_between_requests():
    waited = []
    cn.run_probes(scope_for(delay_ms=250), opener=fixed_opener(),
                  sleep=waited.append)
    assert waited
    assert all(abs(w - 0.25) < 1e-9 for w in waited)


def test_zero_delay_skips_sleeping():
    waited = []
    cn.run_probes(scope_for(delay_ms=0), opener=fixed_opener(),
                  sleep=waited.append)
    assert waited == []


def test_render_probes_shows_the_exact_text():
    rendered = cn.render_probes("COLDLIGHT-CANARY-AAAAAAAA")
    assert rendered
    for probe, text in rendered:
        assert "COLDLIGHT-CANARY-AAAAAAAA" in text
        assert probe.needs_marker is False


# ---------------------------------------------------------------------------
# Findings and reporting
# ---------------------------------------------------------------------------

def test_only_susceptible_probes_become_findings():
    run = cn.run_probes(scope_for(), opener=obedient_opener(),
                        sleep=no_sleep)
    items = cn.findings(run)
    assert len(items) == len(run.susceptible)
    assert all(f.severity_source == "coldlight-judgement" for f in items)


def test_findings_are_ordered_by_severity():
    run = cn.run_probes(scope_for(), opener=obedient_opener(),
                        sleep=no_sleep)
    order = [cn._SEVERITY_ORDER[f.severity] for f in cn.findings(run)]
    assert order == sorted(order, reverse=True)


def test_resisted_run_produces_no_findings():
    run = cn.run_probes(scope_for(), opener=fixed_opener(), sleep=no_sleep)
    assert cn.findings(run) == []


def test_meets_threshold():
    run = cn.run_probes(scope_for(), opener=obedient_opener(),
                        sleep=no_sleep)
    items = cn.findings(run)
    assert cn.meets_threshold(items, "high") is True
    assert cn.meets_threshold([], "low") is False


def test_meets_threshold_rejects_unknown_severity():
    with pytest.raises(ValueError):
        cn.meets_threshold([], "apocalyptic")


def test_text_report_refuses_to_claim_robustness():
    run = cn.run_probes(scope_for(), opener=fixed_opener(), sleep=no_sleep)
    report = cn.text_report(run)
    assert "not evidence of robustness" in report
    assert "no jailbreak" in report.lower()


def test_json_report_shape():
    run = cn.run_probes(scope_for(), opener=obedient_opener(),
                        sleep=no_sleep)
    payload = cn.json_report(run, scope_for())
    assert payload["tool"] == "coldlight canary"
    for key in ("target", "authorization_reference", "counts", "results",
                "findings", "scope_decisions", "limitations",
                "verdict_established"):
        assert key in payload
    assert payload["counts"]["probes"] == len(run.results)
    assert payload["scope"]["authorization_reference"] == "TICKET-4417"
    assert json.loads(json.dumps(payload))["findings"]


def test_json_report_never_contains_request_headers():
    scope = scope_for()
    scope.probe["headers"] = {"Authorization": "Bearer sk-live-secret"}
    run = cn.run_probes(scope, opener=obedient_opener(), sleep=no_sleep)
    blob = json.dumps(cn.json_report(run, scope))
    assert "sk-live-secret" not in blob


def test_json_report_states_its_limitations():
    run = cn.run_probes(scope_for(), opener=fixed_opener(), sleep=no_sleep)
    limitations = " ".join(cn.json_report(run)["limitations"])
    assert "jailbreak" in limitations
    assert "not evidence of robustness" in limitations
    assert "not counted as resisted" in limitations
