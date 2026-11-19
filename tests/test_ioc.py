"""Tests for coldlight_ioc (indicator-pack scanning). No network, no execution.

Three groups matter more than the rest, and they are the reason this module
exists rather than a grep loop:

* "Expiry" -- an indicator past its date must never be reported as a finding.
* "Corroboration" -- a marker the pack grades as common must not alert alone,
  and an expired indicator must not be allowed to serve as the second signal.
* "Structural guards" -- the loader must refuse a pack it cannot fully
  evaluate, because the alternative is a clean report for a surface nothing
  ever looked at.

The clock is injected everywhere. A module whose whole point is that time
changes the answer cannot be tested at whatever today happens to be.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

import coldlight_ioc as ioc

TODAY = date(2026, 6, 15)

ROOT = Path(__file__).resolve().parent.parent


def _example_pack() -> Path:
    """The shipped format example, or skip.

    Resolved against the repo root rather than the working directory, and
    skipped when it is absent. The example pack is documentation, not a module,
    so it is deliberately not embedded in the single-file build -- and the
    suite is run against the sources extracted back out of that build, where
    `examples/` does not exist. Same convention as the repo-metadata tests in
    test_cli.py and test_bundle.py.
    """
    path = ROOT / "examples" / "ioc" / "example-pack.toml"
    if not path.is_file():
        pytest.skip("no examples/: not running from a checkout")
    return path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_PACK_HEADER = """
[pack]
name = "testpack"
version = "1.0"
source = "https://example.invalid/pack"
license = "CC0-1.0"
retrieved = "2026-06-01"
"""

_INDICATOR = """
[[indicator]]
id = "{id}"
kind = "{kind}"
value = "{value}"
uniqueness = "{uniqueness}"
verification = "{verification}"
tier = "{tier}"
title = "{title}"
"""


def _indicator(id="IND-1", kind="file_content", value="MARKER-ONE",
               uniqueness="A", verification="V2", tier="T1",
               title="a marker", **extra) -> str:
    # Every validated field is a named parameter, not an **extra. Passing one
    # through **extra would append a second copy of a key the template already
    # sets, and TOML rejects the duplicate -- so the test would pass on a
    # parse error instead of on the validation it meant to exercise.
    block = _INDICATOR.format(id=id, kind=kind, value=value,
                              uniqueness=uniqueness, verification=verification,
                              tier=tier, title=title)
    for key, val in extra.items():
        if isinstance(val, bool):
            block += f"{key} = {str(val).lower()}\n"
        else:
            block += f'{key} = "{val}"\n'
    return block


def _write_pack(tmp_path, body: str, *, header: str = _PACK_HEADER,
                name: str = "pack.toml"):
    path = tmp_path / name
    path.write_text(header + body, encoding="utf-8")
    return path


def _tree(tmp_path, files: dict):
    root = tmp_path / "target"
    root.mkdir(exist_ok=True)
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


def _scan(tmp_path, pack_body, files, *, today=TODAY, **kwargs):
    pack = _write_pack(tmp_path, pack_body)
    root = _tree(tmp_path, files)
    return ioc.scan_packs(root, ioc.load_packs([pack]), today=today, **kwargs)


def _ids(findings):
    return [f.indicator_id for f in findings]


# ---------------------------------------------------------------------------
# The shipped example pack
# ---------------------------------------------------------------------------

def test_the_example_pack_loads():
    """It is documentation, and documentation that does not parse is worse
    than none -- someone will copy it."""
    pack = ioc.load_pack(_example_pack())
    assert pack.name == "exampletool"
    assert pack.indicators


def test_the_example_pack_demonstrates_every_grade_that_changes_behaviour():
    """A format example that only shows the happy path teaches the happy path.
    It has to contain a class that stands alone, one that cannot, and one that
    has expired, or the three code paths have no worked illustration."""
    pack = ioc.load_pack(_example_pack())
    assert any(i.stands_alone for i in pack.indicators)
    assert any(not i.stands_alone for i in pack.indicators)
    assert any(i.valid_until and i.expired_on(date(2026, 11, 19))
               for i in pack.indicators)


def test_the_example_pack_demonstrates_every_surface():
    """A format example showing one kind teaches one kind.

    The report names four surfaces and says which ones a pack left uncovered,
    so someone copying this file as a starting point has to be able to see all
    four written out. Equality, not a subset: a kind added without an example
    is a kind with no worked illustration anywhere.
    """
    pack = ioc.load_pack(_example_pack())
    assert {i.kind for i in pack.indicators} == set(ioc.KINDS)


# ---------------------------------------------------------------------------
# Loading: what is refused, and why
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("missing", ["name", "version", "source", "license",
                                     "retrieved"])
def test_a_pack_missing_required_provenance_does_not_load(tmp_path, missing):
    """Attribution is not optional. A finding someone cannot trace back to a
    source is a finding they cannot argue with or dismiss."""
    header = "\n".join(line for line in _PACK_HEADER.strip().splitlines()
                       if not line.startswith(missing + " "))
    with pytest.raises(ioc.PackError) as exc:
        _write_pack(tmp_path, _indicator(), header=header + "\n")
        ioc.load_pack(tmp_path / "pack.toml")
    assert missing in str(exc.value)


def test_the_refusal_explains_why_rather_than_just_failing(tmp_path):
    header = "\n".join(line for line in _PACK_HEADER.strip().splitlines()
                       if not line.startswith("source "))
    path = _write_pack(tmp_path, _indicator(), header=header + "\n")
    with pytest.raises(ioc.PackError) as exc:
        ioc.load_pack(path)
    assert "attributed" in str(exc.value)


def test_a_pack_with_no_indicator_table_does_not_load(tmp_path):
    path = _write_pack(tmp_path, "")
    with pytest.raises(ioc.PackError, match="no .*indicator"):
        ioc.load_pack(path)


def test_a_file_with_no_pack_table_does_not_load(tmp_path):
    path = tmp_path / "pack.toml"
    path.write_text(_indicator(), encoding="utf-8")
    with pytest.raises(ioc.PackError, match=r"\[pack\]"):
        ioc.load_pack(path)


def test_invalid_toml_does_not_load(tmp_path):
    path = tmp_path / "pack.toml"
    path.write_text("this is not = = toml", encoding="utf-8")
    with pytest.raises(ioc.PackError, match="not valid TOML"):
        ioc.load_pack(path)


def test_a_missing_pack_file_is_an_error_not_an_empty_pack(tmp_path):
    with pytest.raises(ioc.PackError, match="cannot read pack"):
        ioc.load_pack(tmp_path / "absent.toml")


def test_an_unknown_indicator_kind_refuses_the_whole_pack(tmp_path):
    """The important refusal.

    Skipping an indicator class this version cannot evaluate would produce a
    scan that reports clean for a surface nothing looked at. Refusing the pack
    means the operator finds out at load time that they need a newer
    ColdLight, instead of trusting a result that never covered what they
    thought.
    """
    path = _write_pack(tmp_path, _indicator(kind="dns_query"))
    with pytest.raises(ioc.PackError) as exc:
        ioc.load_pack(path)
    message = str(exc.value)
    assert "dns_query" in message
    # It has to say what IS supported, or the operator cannot act on it.
    assert ioc.KIND_FILE_CONTENT in message
    assert "clean scan" in message


def test_a_duplicate_indicator_id_does_not_load(tmp_path):
    path = _write_pack(tmp_path,
                       _indicator(id="SAME", value="A-ONE")
                       + _indicator(id="SAME", value="A-TWO"))
    with pytest.raises(ioc.PackError, match="duplicate indicator id"):
        ioc.load_pack(path)


@pytest.mark.parametrize("field,value", [
    ("uniqueness", "Z"),
    ("verification", "V9"),
    ("tier", "T9"),
])
def test_an_out_of_range_grade_does_not_load(tmp_path, field, value):
    path = _write_pack(tmp_path, _indicator(**{field: value}))
    with pytest.raises(ioc.PackError, match=field):
        ioc.load_pack(path)


def test_a_regex_that_does_not_compile_fails_at_load(tmp_path):
    """Not at the first line of the first file, halfway through a scan."""
    path = _write_pack(tmp_path, _indicator(value="(", regex=True))
    with pytest.raises(ioc.PackError, match="does not compile"):
        ioc.load_pack(path)


@pytest.mark.parametrize("field", ["valid_until", "retrieved"])
def test_an_unparseable_date_does_not_load(tmp_path, field):
    if field == "valid_until":
        path = _write_pack(tmp_path, _indicator(valid_until="soon"))
    else:
        header = _PACK_HEADER.replace('retrieved = "2026-06-01"',
                                      'retrieved = "soon"')
        path = _write_pack(tmp_path, _indicator(), header=header)
    with pytest.raises(ioc.PackError, match="ISO date"):
        ioc.load_pack(path)


def test_one_bad_pack_refuses_the_whole_set(tmp_path):
    """Loading two of three packs and scanning with those would hand the
    operator a report that does not obviously say which intel was used."""
    good = _write_pack(tmp_path, _indicator(), name="good.toml")
    bad = _write_pack(tmp_path, _indicator(kind="nope"), name="bad.toml")
    with pytest.raises(ioc.PackError):
        ioc.load_packs([good, bad])
    # And the good one on its own still loads, so the refusal was about the bad
    # one and not a broken helper.
    assert ioc.load_packs([good])


def test_two_packs_with_the_same_name_are_refused(tmp_path):
    a = _write_pack(tmp_path, _indicator(id="A1"), name="a.toml")
    b = _write_pack(tmp_path, _indicator(id="B1"), name="b.toml")
    with pytest.raises(ioc.PackError, match="share the name"):
        ioc.load_packs([a, b])


# ---------------------------------------------------------------------------
# Expiry
# ---------------------------------------------------------------------------

def test_an_expired_indicator_is_not_a_finding(tmp_path):
    result = _scan(
        tmp_path,
        _indicator(value="MARKER-ONE", valid_until="2026-01-01"),
        {"a.py": "x = 'MARKER-ONE'\n"},
    )
    assert result.findings == []
    assert _ids(result.expired) == ["IND-1"]
    assert result.expired[0].status == ioc.STATUS_EXPIRED


def test_an_expired_match_is_still_reported_so_the_decay_is_visible(tmp_path):
    """Dropping the match entirely would be the other way to get this wrong:
    the operator would never learn their pack has gone off."""
    result = _scan(
        tmp_path,
        _indicator(valid_until="2026-01-01"),
        {"a.py": "x = 'MARKER-ONE'\n"},
    )
    assert len(result.expired) == 1
    assert "EXPIRED" in ioc.text_report(result)


def test_an_indicator_valid_until_today_is_still_valid(tmp_path):
    """Inclusive boundary. An indicator the author stands behind "until the
    15th" is good on the 15th."""
    result = _scan(
        tmp_path,
        _indicator(valid_until=TODAY.isoformat()),
        {"a.py": "x = 'MARKER-ONE'\n"},
    )
    assert _ids(result.findings) == ["IND-1"]
    assert result.expired == []


def test_an_indicator_that_lapsed_yesterday_has_expired(tmp_path):
    result = _scan(
        tmp_path,
        _indicator(valid_until="2026-06-14"),
        {"a.py": "x = 'MARKER-ONE'\n"},
    )
    assert result.findings == []
    assert len(result.expired) == 1


def test_an_indicator_with_no_expiry_never_expires_here(tmp_path):
    """The pack author declined to set a lifetime; inventing one for them
    would be this tool making up intel policy. It is counted as undated in the
    coverage note instead."""
    result = _scan(tmp_path, _indicator(), {"a.py": "x = 'MARKER-ONE'\n"})
    assert _ids(result.findings) == ["IND-1"]
    assert result.indicators_undated == 1
    assert "no expiry" in result.coverage_note()


def test_expired_indicators_shrink_the_coverage_denominator(tmp_path):
    pack = _write_pack(
        tmp_path,
        _indicator(id="LIVE", value="M-LIVE", valid_until="2027-01-01")
        + _indicator(id="DEAD", value="M-DEAD", valid_until="2026-01-01"))
    result = ioc.scan_packs(_tree(tmp_path, {"a.py": "pass\n"}),
                            ioc.load_packs([pack]), today=TODAY)
    assert result.indicators_total == 2
    assert result.indicators_active == 1
    assert result.indicators_expired == 1
    assert result.fully_current is False


def test_fail_on_ignores_expired_matches(tmp_path):
    """An expired indicator must not be able to break someone's build. It is
    not evidence of anything."""
    result = _scan(
        tmp_path,
        _indicator(tier="T1", valid_until="2026-01-01"),
        {"a.py": "x = 'MARKER-ONE'\n"},
    )
    assert ioc.meets_threshold(result.findings, "LOW") is False


# ---------------------------------------------------------------------------
# Corroboration
# ---------------------------------------------------------------------------

def test_a_distinctive_indicator_stands_alone(tmp_path):
    result = _scan(tmp_path, _indicator(uniqueness="A"),
                   {"a.py": "x = 'MARKER-ONE'\n"})
    assert _ids(result.findings) == ["IND-1"]
    assert result.corroboration == []


@pytest.mark.parametrize("weak", ["C", "D", "E", "F"])
def test_a_common_indicator_does_not_alert_alone(tmp_path, weak):
    result = _scan(tmp_path, _indicator(uniqueness=weak),
                   {"a.py": "x = 'MARKER-ONE'\n"})
    assert result.findings == []
    assert result.corroboration[0].status == ioc.STATUS_CORROBORATION


def test_a_second_signal_promotes_a_common_indicator(tmp_path):
    pack = _write_pack(
        tmp_path,
        _indicator(id="WEAK", value="M-WEAK", uniqueness="C", tier="T3")
        + _indicator(id="STRONG", value="M-STRONG", uniqueness="A"))
    result = ioc.scan_packs(
        _tree(tmp_path, {"a.py": "x = 'M-WEAK'\n", "b.py": "y = 'M-STRONG'\n"}),
        ioc.load_packs([pack]), today=TODAY)
    assert set(_ids(result.findings)) == {"WEAK", "STRONG"}
    assert result.corroboration == []
    promoted = next(f for f in result.findings if f.indicator_id == "WEAK")
    # It records what promoted it: the reading of the rule is ColdLight's, so
    # the reader gets to check the working.
    assert promoted.corroborated_by == ("STRONG",)


def test_two_common_indicators_corroborate_each_other(tmp_path):
    """Intended. The rule is that a single weak signal must not alert; two
    different weak signals in the same tree are two signals."""
    pack = _write_pack(
        tmp_path,
        _indicator(id="W1", value="M-ONE", uniqueness="C", tier="T3")
        + _indicator(id="W2", value="M-TWO", uniqueness="D", tier="T4"))
    result = ioc.scan_packs(
        _tree(tmp_path, {"a.py": "x = 'M-ONE'\ny = 'M-TWO'\n"}),
        ioc.load_packs([pack]), today=TODAY)
    assert set(_ids(result.findings)) == {"W1", "W2"}


def test_the_same_indicator_twice_is_not_a_second_signal(tmp_path):
    """The case that would quietly defeat the whole rule. One common marker
    appearing in forty files is still one marker, and counting repetitions as
    corroboration would promote every noisy indicator in the pack.
    """
    result = _scan(
        tmp_path,
        _indicator(uniqueness="C", tier="T3"),
        {"a.py": "x = 'MARKER-ONE'\n",
         "b.py": "y = 'MARKER-ONE'\n",
         "c/d.py": "z = 'MARKER-ONE'\n"},
    )
    assert result.findings == []
    assert len(result.corroboration) == 3
    assert {f.status for f in result.corroboration} == {
        ioc.STATUS_CORROBORATION}


def test_an_expired_indicator_cannot_serve_as_the_second_signal(tmp_path):
    """Otherwise expiry leaks back in through the side door: a dead string
    would quietly license a live weak one to alert."""
    pack = _write_pack(
        tmp_path,
        _indicator(id="WEAK", value="M-WEAK", uniqueness="C", tier="T3")
        + _indicator(id="DEAD", value="M-DEAD", uniqueness="A",
                     valid_until="2026-01-01"))
    result = ioc.scan_packs(
        _tree(tmp_path, {"a.py": "x = 'M-WEAK'\ny = 'M-DEAD'\n"}),
        ioc.load_packs([pack]), today=TODAY)
    assert result.findings == []
    assert _ids(result.corroboration) == ["WEAK"]
    assert _ids(result.expired) == ["DEAD"]


def test_fail_on_ignores_matches_awaiting_corroboration(tmp_path):
    result = _scan(tmp_path, _indicator(uniqueness="C", tier="T1"),
                   {"a.py": "x = 'MARKER-ONE'\n"})
    assert ioc.meets_threshold(result.findings, "LOW") is False


def test_fail_on_fires_on_a_real_finding(tmp_path):
    """The threshold has to work, or the two tests above prove nothing."""
    result = _scan(tmp_path, _indicator(uniqueness="A", tier="T1"),
                   {"a.py": "x = 'MARKER-ONE'\n"})
    assert ioc.meets_threshold(result.findings, "CRITICAL") is True


def test_an_unknown_threshold_is_an_error(tmp_path):
    with pytest.raises(ValueError, match="unknown severity threshold"):
        ioc.meets_threshold([], "spicy")


# ---------------------------------------------------------------------------
# Pack staleness -- a coverage claim, not a finding
# ---------------------------------------------------------------------------

def test_a_stale_pack_still_produces_its_findings(tmp_path):
    """Staleness is about what we can claim to have covered, not about whether
    a match happened. Suppressing the match would be the wrong correction."""
    header = _PACK_HEADER.replace('retrieved = "2026-06-01"',
                                  'retrieved = "2025-01-01"')
    pack = _write_pack(tmp_path, _indicator(), header=header)
    result = ioc.scan_packs(_tree(tmp_path, {"a.py": "x = 'MARKER-ONE'\n"}),
                            ioc.load_packs([pack]), today=TODAY)
    assert _ids(result.findings) == ["IND-1"]
    assert [p.name for p in result.stale_packs] == ["testpack"]
    assert result.fully_current is False
    assert "not refreshed" in result.coverage_note()


def test_a_fresh_pack_is_not_stale(tmp_path):
    result = _scan(tmp_path, _indicator(valid_until="2027-01-01"),
                   {"a.py": "x = 'MARKER-ONE'\n"})
    assert result.stale_packs == []
    assert result.fully_current is True
    assert result.coverage_note() == ""


def test_a_tightened_staleness_window_actually_reaches_the_report(tmp_path):
    """Regression. `stale_after_days` was taken by the scan and then not
    carried onto the result, so the report and the ledger went on using the
    default -- a parameter that looked like it worked and did not.
    """
    result = _scan(tmp_path, _indicator(valid_until="2027-01-01"),
                   {"a.py": "pass\n"}, stale_after_days=5)
    assert [p.name for p in result.stale_packs] == ["testpack"]
    assert "over 5 days" in result.coverage_note()


# ---------------------------------------------------------------------------
# Severity provenance
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("tier,severity", [
    ("T1", "CRITICAL"), ("T2", "HIGH"), ("T3", "MEDIUM"), ("T4", "LOW"),
])
def test_severity_comes_from_the_packs_tier(tmp_path, tier, severity):
    result = _scan(tmp_path, _indicator(tier=tier),
                   {"a.py": "x = 'MARKER-ONE'\n"})
    assert result.findings[0].severity == severity


def test_the_severity_source_is_a_declared_one():
    """Same arrangement as coldlight_codescan: the literal lives here, and
    this test is what stops it drifting from the canonical set."""
    import coldlight_vulnintel as vi

    assert ioc.SEVERITY_SOURCE in vi.SEVERITY_SOURCES
    assert ioc.SEVERITY_SOURCE == vi.SEV_SRC_PACK


def test_a_pack_tier_is_not_counted_as_a_measurement():
    """A third party's opinion must not be reported with the authority of a
    CVSS score."""
    import coldlight_vulnintel as vi

    assert not vi.is_measured(ioc.SEVERITY_SOURCE)


def test_every_finding_carries_the_pack_and_its_source(tmp_path):
    result = _scan(tmp_path, _indicator(), {"a.py": "x = 'MARKER-ONE'\n"})
    finding = result.findings[0]
    assert finding.pack == "testpack"
    assert finding.source == "https://example.invalid/pack"
    assert finding.severity_source == ioc.SEVERITY_SOURCE


# ---------------------------------------------------------------------------
# Suppression is deliberately not honoured
# ---------------------------------------------------------------------------

def test_an_in_file_suppression_comment_does_not_hide_an_indicator(tmp_path):
    """The security decision in this module.

    `coldlight_codescan` honours `# nosec` because a developer may reasonably
    silence a rule about code they wrote. A file being searched for an
    intrusion marker is, by hypothesis, a file someone else may have written.
    Letting its contents switch off its own detection would hand the suppression
    mechanism to whoever planted the marker.
    """
    result = _scan(
        tmp_path, _indicator(),
        {"a.py": "x = 'MARKER-ONE'  # nosec\n",
         "b.py": "y = 'MARKER-ONE'  # coldlight:ignore\n"},
    )
    assert len(result.findings) == 2


def test_a_marker_inside_a_comment_is_still_found(tmp_path):
    """The code scanner skips comment-only lines to cut false positives. Here
    a comment is just as good a place to hide a marker as anywhere else."""
    result = _scan(tmp_path, _indicator(),
                   {"a.py": "# MARKER-ONE was here\n"})
    assert len(result.findings) == 1


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------

def test_a_secret_on_the_matched_line_is_masked_by_default(tmp_path):
    result = _scan(tmp_path, _indicator(value="MARKER-ONE"),
                   {"a.py": "MARKER_ONE_KEY = 'MARKER-ONE-aaaaaaaaaaaaaaaa'\n"})
    assert "***REDACTED***" in result.findings[0].snippet
    assert "aaaaaaaaaaaaaaaa" not in result.findings[0].snippet


def test_redaction_can_be_turned_off_per_indicator(tmp_path):
    """For a marker that cannot contain a credential, masking it would hide
    the evidence and leave the reader a line number and nothing else."""
    result = _scan(tmp_path, _indicator(value="BANNER-XYZ", redact=False),
                   {"a.py": "x = 'BANNER-XYZ'\n"})
    assert "BANNER-XYZ" in result.findings[0].snippet
    assert "***REDACTED***" not in result.findings[0].snippet


# ---------------------------------------------------------------------------
# Matching mechanics
# ---------------------------------------------------------------------------

def test_a_value_is_literal_unless_regex_is_requested(tmp_path):
    """A pack author writing `v1.2.3` should not have to know that `.` means
    anything, and a value that is accidentally a pattern is a false positive
    nobody can explain."""
    result = _scan(tmp_path, _indicator(value="a.c"),
                   {"hit.py": "x = 'a.c'\n", "miss.py": "y = 'abc'\n"})
    assert len(result.findings) == 1
    assert result.findings[0].file.endswith("hit.py")


def test_a_regex_is_used_when_asked_for(tmp_path):
    result = _scan(tmp_path, _indicator(value="EX[0-9]+", regex=True),
                   {"a.py": "x = 'EX4242'\n"})
    assert len(result.findings) == 1


def test_matching_is_case_sensitive_unless_asked_otherwise(tmp_path):
    result = _scan(tmp_path, _indicator(value="MarkerCase"),
                   {"a.py": "x = 'markercase'\n"})
    assert result.findings == []

    insensitive = _scan(tmp_path, _indicator(value="MarkerCase",
                                             ignore_case=True),
                        {"a.py": "x = 'markercase'\n"})
    assert len(insensitive.findings) == 1


def test_the_line_number_is_recorded(tmp_path):
    result = _scan(tmp_path, _indicator(),
                   {"a.py": "one\ntwo\nx = 'MARKER-ONE'\n"})
    assert result.findings[0].line == 3


def test_exclude_globs_are_honoured(tmp_path):
    pack = _write_pack(tmp_path, _indicator())
    root = _tree(tmp_path, {"keep.py": "x = 'MARKER-ONE'\n",
                            "skip/a.py": "y = 'MARKER-ONE'\n"})
    result = ioc.scan_packs(root, ioc.load_packs([pack]), today=TODAY,
                            exclude=["skip"])
    assert len(result.findings) == 1
    assert result.findings[0].file.endswith("keep.py")


def test_a_pack_inside_the_scanned_tree_does_not_match_itself(tmp_path):
    """A pack kept in version control sits in the tree being scanned, where
    every indicator in it would otherwise match its own declaration and report
    the pack as a compromise of itself.
    """
    root = _tree(tmp_path, {"a.py": "pass\n"})
    pack = _write_pack(root, _indicator(), name="pack.toml")
    result = ioc.scan_packs(root, ioc.load_packs([pack]), today=TODAY)
    assert result.findings == []


def test_files_are_counted_once_when_two_packs_share_a_kind(tmp_path):
    """Regression. The tree was walked once per pack, so scanning with two
    packs reported twice as many files scanned as exist -- inflating the one
    number a reader uses to sanity-check the scan's reach.
    """
    header_b = _PACK_HEADER.replace('name = "testpack"', 'name = "second"')
    a = _write_pack(tmp_path, _indicator(id="A1", value="M-A"), name="a.toml")
    b = _write_pack(tmp_path, _indicator(id="B1", value="M-B"),
                    header=header_b, name="b.toml")
    root = _tree(tmp_path, {"one.py": "pass\n", "two.py": "pass\n"})

    one_pack = ioc.scan_packs(root, ioc.load_packs([a]), today=TODAY)
    two_packs = ioc.scan_packs(root, ioc.load_packs([a, b]), today=TODAY)
    assert one_pack.files_scanned == two_packs.files_scanned == 2


# ---------------------------------------------------------------------------
# Structural guards
# ---------------------------------------------------------------------------

def test_every_declared_kind_has_a_handler():
    """The guard that matters for the next slice.

    KINDS is what `load_pack` accepts; HANDLERS is what `scan_packs` can
    actually evaluate. If a kind is added to the first without the second, a
    pack using it loads happily, matches nothing, and reports clean -- a
    capability that silently passes for a surface nothing looked at. The two
    cannot be allowed to drift.
    """
    assert set(ioc.KINDS) == set(ioc.HANDLERS), (
        "KINDS and HANDLERS disagree. A kind in KINDS with no handler loads "
        "and then evaluates nothing; a handler with no kind is dead code.")
    assert set(ioc.KINDS) == set(ioc.KIND_SURFACE), (
        "KINDS and KIND_SURFACE disagree. A kind with no surface description "
        "is scanned and then left out of the report's accounting, which is "
        "the same silence reached by another route.")
    assert set(ioc.KIND_VALIDATORS) <= set(ioc.KINDS), (
        "a per-kind validator names a kind that does not exist, so the checks "
        "it holds never run")
    for kind, (unit, description) in ioc.KIND_SURFACE.items():
        assert unit and description, (
            f"{kind} has no readable accounting, so its row in the report "
            "cannot say what was examined")


def test_a_kind_with_no_handler_is_reported_not_silently_skipped():
    """Proves the fallback in `scan_packs` fires.

    `load_pack` refuses unknown kinds, so this path is only reachable by
    building a Pack in code -- which is exactly what a future caller might do.
    It must not come back clean.
    """
    orphan = ioc.Indicator(
        id="ORPHAN", kind="not_a_real_kind", value="x", uniqueness="A",
        verification="V2", tier="T1", title="unevaluable")
    pack = ioc.Pack(name="orphan", version="1", source="https://example.invalid",
                    license="CC0-1.0", retrieved="2026-06-01",
                    indicators=(orphan,))
    result = ioc.scan_packs(".", [pack], today=TODAY)
    assert result.findings == []
    assert result.errors, "an unevaluable indicator produced a silent clean scan"
    assert "NOT evaluated" in result.errors[0]


def test_a_non_numeric_port_on_a_hand_built_indicator_is_reported(tmp_path):
    """Loading validates the value, so this is only reachable by building an
    Indicator in code -- which is exactly what a future caller might do. It
    has to come back as an error rather than a traceback, and above all not as
    a clean scan."""
    broken = ioc.Indicator(
        id="BAD-PORT", kind=ioc.KIND_LISTENING_PORT, value="not-a-number",
        uniqueness="C", verification="V3", tier="T3", title="unevaluable")
    pack = ioc.Pack(name="handmade", version="1",
                    source="https://example.invalid", license="CC0-1.0",
                    retrieved="2026-06-01", indicators=(broken,))
    root = _tree(tmp_path, {"app.yml": "port: 18788\n"})
    result = ioc.scan_packs(root, [pack], today=TODAY)
    assert result.findings == [] and result.corroboration == []
    assert any("NOT evaluated" in e for e in result.errors), result.errors


def test_the_corroboration_classes_are_a_subset_of_the_declared_classes():
    assert ioc.CORROBORATION_CLASSES <= set(ioc.UNIQUENESS_CLASSES)


def test_every_tier_maps_to_a_known_severity():
    assert set(ioc.TIER_SEVERITY) == set(ioc.TIERS)
    assert set(ioc.TIER_SEVERITY.values()) <= set(ioc.SEVERITY_ORDER)


def test_a_missing_scan_root_is_refused_rather_than_reported_clean(tmp_path):
    """An absent path walks to nothing, and nothing is indistinguishable from
    a clean result: zero files, zero findings, no error. SECURITY.md calls a
    clean result that is not clean a vulnerability in this tool.
    """
    pack = _write_pack(tmp_path, _indicator())
    with pytest.raises(ioc.IocError, match="no such path"):
        ioc.scan_packs(tmp_path / "nowhere", ioc.load_packs([pack]),
                       today=TODAY)


def test_pack_errors_are_scan_errors_so_one_except_clause_catches_both():
    assert issubclass(ioc.PackError, ioc.IocError)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def test_a_scan_with_no_packs_reports_not_assessed():
    """Not "0 findings". Nothing was looked for."""
    result = ioc.IocScanResult(scanned_on=TODAY.isoformat())
    report = ioc.text_report(result)
    assert "NOT ASSESSED" in report
    assert "nothing" in report


def test_the_report_separates_findings_from_the_other_two_buckets(tmp_path):
    pack = _write_pack(
        tmp_path,
        _indicator(id="STRONG", value="M-STRONG", uniqueness="A")
        + _indicator(id="WEAK", value="M-WEAK", uniqueness="C", tier="T3")
        + _indicator(id="DEAD", value="M-DEAD", uniqueness="A",
                     valid_until="2026-01-01"))
    # M-STRONG is absent from the tree, so the only live match is the weak one
    # and it stays uncorroborated. The dead one must not stand in for it.
    weak_only = ioc.scan_packs(_tree(tmp_path, {"a.py": "x='M-WEAK'\ny='M-DEAD'\n"}),
                               ioc.load_packs([pack]), today=TODAY)
    report = ioc.text_report(weak_only)
    assert ioc.STATUS_CORROBORATION in report
    assert ioc.STATUS_EXPIRED in report
    assert "not evidence of anything" in report


def test_the_report_states_what_it_does_not_cover(tmp_path):
    """The closing note is the honest part of this module's output."""
    result = _scan(tmp_path, _indicator(), {"a.py": "pass\n"})
    report = ioc.text_report(result)
    assert "Network, identity and cloud telemetry" in report
    assert "not that the host is clean" in report


def test_the_report_shows_each_packs_provenance(tmp_path):
    result = _scan(tmp_path, _indicator(), {"a.py": "pass\n"})
    report = ioc.text_report(result)
    assert "https://example.invalid/pack" in report
    assert "CC0-1.0" in report


def test_a_stale_pack_is_flagged_in_the_report(tmp_path):
    result = _scan(tmp_path, _indicator(valid_until="2027-01-01"),
                   {"a.py": "pass\n"}, stale_after_days=5)
    assert "STALE" in ioc.text_report(result)


def test_notes_can_be_suppressed(tmp_path):
    result = _scan(tmp_path, _indicator(note="a useful remark"),
                   {"a.py": "x = 'MARKER-ONE'\n"})
    assert "a useful remark" in ioc.text_report(result, show_notes=True)
    assert "a useful remark" not in ioc.text_report(result, show_notes=False)


def test_the_json_report_keeps_the_three_buckets_apart(tmp_path):
    pack = _write_pack(
        tmp_path,
        _indicator(id="WEAK", value="M-WEAK", uniqueness="C", tier="T3")
        + _indicator(id="DEAD", value="M-DEAD", uniqueness="A",
                     valid_until="2026-01-01"))
    result = ioc.scan_packs(_tree(tmp_path, {"a.py": "x='M-WEAK'\ny='M-DEAD'\n"}),
                            ioc.load_packs([pack]), today=TODAY)
    data = ioc.json_report(result)
    assert data["findings"] == []
    assert [f["indicator_id"] for f in data["corroboration_required"]] == ["WEAK"]
    assert [f["indicator_id"] for f in data["expired"]] == ["DEAD"]
    assert data["fully_current"] is False
    assert data["indicators_expired"] == 1


def test_the_json_report_carries_attribution_per_pack(tmp_path):
    """A consumer of the JSON has to be able to say where a finding came from
    without going back to the pack file."""
    result = _scan(tmp_path, _indicator(), {"a.py": "pass\n"})
    pack = ioc.json_report(result)["packs"][0]
    assert pack["source"] == "https://example.invalid/pack"
    assert pack["license"] == "CC0-1.0"
    assert pack["retrieved"] == "2026-06-01"


def test_the_json_report_is_serialisable(tmp_path):
    import json

    result = _scan(tmp_path, _indicator(), {"a.py": "x = 'MARKER-ONE'\n"})
    assert json.loads(json.dumps(ioc.json_report(result)))["tool"] == \
        "coldlight ioc"


def test_severity_counts_only_count_findings(tmp_path):
    result = _scan(tmp_path, _indicator(uniqueness="C", tier="T1"),
                   {"a.py": "x = 'MARKER-ONE'\n"})
    assert ioc.severity_counts(result.findings) == {}
    assert ioc.severity_counts(result.corroboration) == {"CRITICAL": 1}
# ---------------------------------------------------------------------------
# The file-name surface
# ---------------------------------------------------------------------------

def test_a_filename_indicator_finds_a_file_the_content_walk_never_opens(tmp_path):
    """Why this surface does not reuse the source-file walker.

    `iter_source_files` filters on extension, so an extensionless dropped
    binary is invisible to it. A filename indicator that could only see .py
    and .yml files would report no dropped artifact after looking in none of
    the places one lands -- a clean result for a surface nothing examined.
    """
    result = _scan(
        tmp_path,
        _indicator(id="DROP", kind="file_name", value=".exampletool-agent"),
        {".exampletool-agent": "binary-ish\n", "app.py": "pass\n"})
    assert _ids(result.findings) == ["DROP"]
    assert result.findings[0].file.endswith(".exampletool-agent")


def test_an_absolute_path_indicator_matches_a_tree_scanned_from_its_root(tmp_path):
    """Published packs write dropped-file markers as absolute POSIX paths.

    Against a relative walk, "/var/tmp/.x" could never hit: the indicator
    would load, be counted among the ones this scan evaluated, and be
    structurally incapable of firing. The handler offers every path with a
    leading "/" for exactly this case.
    """
    result = _scan(
        tmp_path,
        _indicator(id="ABS", kind="file_name",
                   value="/var/tmp/.exampletool-stage"),
        {"var/tmp/.exampletool-stage": "x\n"})
    assert _ids(result.findings) == ["ABS"]


def test_a_filename_indicator_ignores_what_is_inside_the_file(tmp_path):
    """The surfaces are not interchangeable. This one is about what exists,
    and a document describing a dropper is not a dropper."""
    result = _scan(
        tmp_path,
        _indicator(id="NAME", kind="file_name", value="agent.bin"),
        {"notes.md": "the dropper writes agent.bin into /opt\n"})
    assert result.findings == []


def test_a_filename_finding_claims_no_line_number(tmp_path):
    """The file's existence is the evidence; there is no line. Printing
    "path:0" would invent a precision this surface does not have."""
    result = _scan(tmp_path,
                   _indicator(id="NAME", kind="file_name", value="agent.bin"),
                   {"agent.bin": "x\n"})
    finding = result.findings[0]
    assert finding.line == 0
    assert f"{finding.file}:0" not in ioc.text_report(result)


def test_the_filename_walk_reaches_further_than_the_content_walk(tmp_path):
    """Two surfaces, two walks, counted separately.

    One `files_scanned` could not be true of both, and a reader checking the
    scan's reach against a single number would be checking the wrong one.
    """
    body = (_indicator(id="C1", kind="file_content", value="nothing-here")
            + _indicator(id="N1", kind="file_name", value="nothing-here"))
    result = _scan(tmp_path, body,
                   {"app.py": "pass\n", "blob.bin": "x\n", "data.dat": "y\n"})
    content = result.surfaces[ioc.KIND_FILE_CONTENT]
    names = result.surfaces[ioc.KIND_FILE_NAME]
    assert content.examined == 1
    assert names.examined == 3
    assert result.files_scanned == content.examined


# ---------------------------------------------------------------------------
# The listening-port surface
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("line", [
    "port: 18788",
    "PORT=18788",
    "containerPort: 18788",
    "listen 18788 ssl;",
    '      - "18788:8080"',
    'bind_address = "0.0.0.0:18788"',
    "upstream = http://10.1.2.3:18788/health",
])
def test_a_port_indicator_matches_a_declared_port(tmp_path, line):
    """The spellings a port actually appears in. One Class C marker alone is
    not a finding, so it lands in the corroboration list -- which is the point
    of the grade, not a failure to match."""
    result = _scan(tmp_path,
                   _indicator(id="PORT", kind="listening_port", value="18788",
                              uniqueness="C", tier="T3"),
                   {"app.yml": line + "\n"})
    assert _ids(result.corroboration) == ["PORT"], line


@pytest.mark.parametrize("line", [
    "support: 18788",
    "transport = 18788",
    "reporting: 18788",
    "version: 118788",
    "timeout: 187880",
    "build = 2026-18788",
])
def test_a_port_indicator_does_not_match_a_number_declaring_nothing(tmp_path, line):
    """A port inside a longer number, or beside a key that merely contains
    the word, is not a declaration. Reporting it as one is how a scanner
    teaches its operator to ignore it -- and an ignored scanner misses the
    finding that mattered."""
    result = _scan(tmp_path,
                   _indicator(id="PORT", kind="listening_port", value="18788",
                              uniqueness="C", tier="T3"),
                   {"app.yml": line + "\n"})
    assert result.findings == [] and result.corroboration == [], line


@pytest.mark.parametrize("key,expected", [
    ("port", True), ("PORT", True), ("ports", True), ("containerPort", True),
    ("target_port", True), ("listen_address", True), ("nodePort", True),
    ("bind", True),
    ("support", False), ("transport", False), ("reporting", False),
    ("portal", False), ("important", False), ("version", False),
])
def test_only_a_key_that_names_a_port_is_read_as_declaring_one(key, expected):
    """Substring matching would make "support" and "transport" port keys. The
    key is split on separators and camelCase and the words compared whole."""
    assert ioc._is_port_key(key) is expected


def test_a_loopback_address_does_not_declare_its_own_octets_as_ports(tmp_path):
    """Why only the all-digit components of an authority are considered.

    "127.0.0.1:8080" offers 127, 0, 0, 1 and 8080 to a naive split, and 127 is
    a valid port number -- so an indicator for port 127 would fire on every
    line that mentions a loopback address.
    """
    result = _scan(tmp_path,
                   _indicator(id="P127", kind="listening_port", value="127",
                              uniqueness="C", tier="T3"),
                   {"app.conf": 'upstream = "127.0.0.1:8080"\n'})
    assert result.findings == [] and result.corroboration == []


@pytest.mark.parametrize("uniqueness", ["A", "B"])
def test_a_port_indicator_cannot_be_graded_to_stand_alone(tmp_path, uniqueness):
    """Every port is some unrelated software's default, so a pack grading one
    A or B is asking for a standalone CRITICAL on a two-byte integer. The pack
    is refused rather than quietly downgraded: rewriting an author's grade
    would make the report disagree with the pack it cites."""
    path = _write_pack(tmp_path, _indicator(
        id="P", kind="listening_port", value="8080", uniqueness=uniqueness,
        tier="T3"))
    with pytest.raises(ioc.PackError, match="cannot be graded"):
        ioc.load_pack(path)


@pytest.mark.parametrize("flag", ["regex", "ignore_case"])
def test_a_port_indicator_refuses_options_that_would_do_nothing(tmp_path, flag):
    """An option that silently has no effect is worse than one refused: the
    author believes they asked for something and the report will not say they
    did not get it."""
    path = _write_pack(tmp_path, _indicator(
        id="P", kind="listening_port", value="8080", uniqueness="C",
        tier="T3", **{flag: True}))
    with pytest.raises(ioc.PackError, match="no meaning"):
        ioc.load_pack(path)


@pytest.mark.parametrize("value", ["not-a-port", "70000", "0", "8080x"])
def test_a_port_value_that_is_not_a_port_does_not_load(tmp_path, value):
    """It could never match, so it would be a dead indicator padding the
    count of indicators this scan claims to have evaluated."""
    path = _write_pack(tmp_path, _indicator(
        id="P", kind="listening_port", value=value, uniqueness="C",
        tier="T3"))
    with pytest.raises(ioc.PackError, match="port"):
        ioc.load_pack(path)


def test_the_port_surface_only_opens_configuration_files(tmp_path):
    """A stated limit, not an oversight.

    A port assigned in application source is a declaration too, and this
    surface will not see it. The limit is disclosed in the report's surface
    table rather than left for the reader to discover, which is what that
    table is for.
    """
    result = _scan(tmp_path,
                   _indicator(id="P", kind="listening_port", value="18788",
                              uniqueness="C", tier="T3"),
                   {"app.py": "app.run(port=18788)\n"})
    assert result.findings == [] and result.corroboration == []
    assert result.surfaces[ioc.KIND_LISTENING_PORT].examined == 0


def test_the_marker_survives_redaction_on_a_port_match(tmp_path):
    """Regression-shaped, from the same bug as the quoted path in slice one.

    `redact()` masks quoted values, and a compose port mapping is a quoted
    value. Masking the whole line leaves a line number and a row of asterisks
    where the evidence should be, so what matched is extracted first and shown
    verbatim while the rest of the line is still masked.
    """
    result = _scan(tmp_path,
                   _indicator(id="P", kind="listening_port", value="18788",
                              uniqueness="C", tier="T3"),
                   {"compose.yml": '      - "18788:18788"\n'})
    snippet = result.corroboration[0].snippet
    assert "port 18788" in snippet
    assert "REDACTED" in snippet, "the context around the match is not masked"


# ---------------------------------------------------------------------------
# The container-image surface
# ---------------------------------------------------------------------------

def test_an_image_indicator_matches_what_a_manifest_deploys(tmp_path):
    result = _scan(
        tmp_path,
        _indicator(id="IMG", kind="container_image",
                   value="registry.example.invalid/tool/agent"),
        {"k8s/deploy.yaml":
            "    - image: registry.example.invalid/tool/agent:v3\n"})
    assert _ids(result.findings) == ["IMG"]
    assert "registry.example.invalid/tool/agent:v3" \
        in result.findings[0].snippet


@pytest.mark.parametrize("line", [
    "FROM registry.example.invalid/tool/agent:v3",
    "FROM registry.example.invalid/tool/agent:v3 AS builder",
    "FROM --platform=linux/amd64 registry.example.invalid/tool/agent:v3",
])
def test_an_image_indicator_matches_a_dockerfile_from_line(tmp_path, line):
    result = _scan(
        tmp_path,
        _indicator(id="IMG", kind="container_image",
                   value="registry.example.invalid/tool/agent"),
        {"Dockerfile": line + "\n"})
    assert _ids(result.findings) == ["IMG"], line


def test_an_image_named_in_prose_is_not_a_deployment(tmp_path):
    """The whole value of this surface over a content search.

    A registry named in a comment, a changelog or a README is documentation.
    Reporting it as a deployed image is noise, and noise is what gets a real
    finding ignored.
    """
    result = _scan(
        tmp_path,
        _indicator(id="IMG", kind="container_image",
                   value="registry.example.invalid/tool/agent"),
        {"deploy.yaml":
            "# the image registry.example.invalid/tool/agent was removed\n"
            "    - image: nginx:1.27\n"})
    assert result.findings == []


def test_an_image_repository_matches_any_tag_of_it(tmp_path):
    """A pack naming a repository means every tag of it; one naming a tag
    means that tag. Which it is stays the author's choice, so the tag is left
    on the reference rather than stripped before matching."""
    body = (_indicator(id="REPO", kind="container_image",
                       value="registry.example.invalid/tool/agent")
            + _indicator(id="TAG", kind="container_image",
                         value="registry.example.invalid/tool/agent:v9"))
    result = _scan(
        tmp_path, body,
        {"compose.yml":
            "    image: registry.example.invalid/tool/agent:v3\n"})
    assert _ids(result.findings) == ["REPO"]


def test_an_image_value_with_whitespace_does_not_load(tmp_path):
    """It would load, count towards the indicators this scan claims to have
    evaluated, and never match. A dead indicator is worse than a missing one:
    it inflates the denominator the assurance ledger reports."""
    path = _write_pack(tmp_path, _indicator(
        id="IMG", kind="container_image", value="registry.invalid/a b"))
    with pytest.raises(ioc.PackError, match="whitespace"):
        ioc.load_pack(path)


# ---------------------------------------------------------------------------
# Across the surfaces
# ---------------------------------------------------------------------------

def test_two_weak_markers_on_different_surfaces_corroborate_each_other(tmp_path):
    """What the extra surfaces are for.

    A port in a config and a filename on disk are each too common to alert on
    alone, and a tool that leaves one trace in each is the ordinary case.
    Insisting both signals sit in the same file would throw that away.
    """
    body = (_indicator(id="PORT", kind="listening_port", value="18788",
                       uniqueness="C", tier="T3")
            + _indicator(id="NAME", kind="file_name", value="agent.bin",
                         uniqueness="D", tier="T4"))
    result = _scan(tmp_path, body,
                   {"app.yml": "port: 18788\n", "opt/agent.bin": "x\n"})
    assert result.corroboration == []
    assert {f.indicator_id: f.corroborated_by for f in result.findings} == {
        "PORT": ("NAME",), "NAME": ("PORT",)}


@pytest.mark.parametrize("kind,value,uniqueness,files", [
    ("file_name", "agent.bin", "A", {"agent.bin": "x\n"}),
    ("listening_port", "18788", "C", {"a.yml": "port: 18788\n"}),
    ("container_image", "reg.invalid/t/a", "A",
     {"a.yml": "    image: reg.invalid/t/a\n"}),
])
def test_expiry_holds_on_every_surface(tmp_path, kind, value, uniqueness, files):
    """Expiry is the first rule of this module, and a rule that only holds on
    the surface it was written for is not a rule."""
    result = _scan(tmp_path,
                   _indicator(id="OLD", kind=kind, value=value,
                              uniqueness=uniqueness, tier="T3",
                              valid_until="2026-01-01"),
                   files)
    assert result.findings == []
    assert _ids(result.expired) == ["OLD"]


def test_a_surface_no_indicator_covers_is_reported_as_uncovered(tmp_path):
    """"Looked and found nothing" against "nobody looked", at the level of the
    surface rather than the whole scan. A surface left out of the table reads
    as one that came back clean."""
    result = _scan(tmp_path, _indicator(), {"app.py": "pass\n"})
    assert [row.kind for row in result.uncovered_surfaces] == [
        ioc.KIND_FILE_NAME, ioc.KIND_LISTENING_PORT, ioc.KIND_CONTAINER_IMAGE]
    report = ioc.text_report(result)
    assert "NOT COVERED" in report
    for row in result.uncovered_surfaces:
        assert row.kind.replace("_", " ") in report


def test_every_surface_has_a_row_after_a_scan(tmp_path):
    """`result.surfaces` is read directly by whatever consumes a scan, so a
    surface no indicator covered has to be present and marked uncovered rather
    than missing from the mapping. A consumer indexing it would otherwise get
    a KeyError for the one case it most needs to report."""
    result = _scan(tmp_path, _indicator(), {"app.py": "pass\n"})
    assert set(result.surfaces) == set(ioc.KINDS)
    assert result.surfaces[ioc.KIND_CONTAINER_IMAGE].covered is False


def test_a_covered_surface_with_nothing_to_examine_is_not_an_uncovered_one(tmp_path):
    """Two zeroes that mean opposite things. `examined == 0` because the tree
    holds no manifests is a surface that looked; `covered is False` is a pack
    that never asked."""
    result = _scan(tmp_path,
                   _indicator(id="IMG", kind="container_image",
                              value="reg.invalid/t/a"),
                   {"app.py": "pass\n"})
    row = result.surfaces[ioc.KIND_CONTAINER_IMAGE]
    assert row.covered and row.examined == 0
    assert row not in result.uncovered_surfaces


def test_the_pack_is_not_evidence_of_itself_on_the_filename_surface(tmp_path):
    """A pack kept in version control sits in the tree being scanned. On the
    content surface every indicator matches its own declaration; on the
    filename surface a pack named after the thing it hunts matches its own
    path."""
    root = _tree(tmp_path, {"app.py": "pass\n"})
    pack = _write_pack(root, _indicator(id="NAME", kind="file_name",
                                        value="agent.toml"),
                       name="agent.toml")
    result = ioc.scan_packs(root, ioc.load_packs([pack]), today=TODAY)
    assert result.findings == []


def test_the_json_report_accounts_for_every_surface(tmp_path):
    """Including the ones these packs do not cover, and in a fixed order, so
    a reader comparing two reports is comparing the same rows."""
    result = _scan(tmp_path, _indicator(), {"app.py": "pass\n"})
    data = ioc.json_report(result)
    assert [row["kind"] for row in data["surfaces"]] == list(ioc.KINDS)
    assert data["surfaces_uncovered"] == [
        k for k in ioc.KINDS if k != ioc.KIND_FILE_CONTENT]
    covered = {row["kind"]: row for row in data["surfaces"]}
    assert covered[ioc.KIND_FILE_CONTENT]["covered"] is True
    assert covered[ioc.KIND_FILE_NAME]["covered"] is False
