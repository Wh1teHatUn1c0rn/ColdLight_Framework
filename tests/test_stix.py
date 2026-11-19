"""Tests for coldlight_stix (STIX 2.1 -> indicator pack).

What matters here is not how much of a bundle gets imported. It is that
nothing is imported *wrong*: a pattern this tool cannot represent must be
refused with a reason rather than narrowed to the part it understands, and the
pack that comes out must be one `coldlight_ioc.load_pack` accepts -- a
generated pack the scanner rejects is a file the operator keeps believing is
intel.

The clock is injected, because an imported indicator's validity window and the
pack's `retrieved` date both depend on it.
"""

from __future__ import annotations

import json
import re
from datetime import date
from pathlib import Path

import pytest

import coldlight_ioc as ioc
import coldlight_stix as sx

TODAY = date(2026, 11, 19)

ROOT = Path(__file__).resolve().parent.parent

BS = chr(92)


def _example_bundle() -> Path:
    """The shipped example bundle, or skip.

    Same convention as the example pack: `examples/` is documentation rather
    than a module, so it is not embedded in the single-file build and these
    tests cannot run against the sources extracted from it.
    """
    path = ROOT / "examples" / "ioc" / "example-bundle.json"
    if not path.is_file():
        pytest.skip("no examples/: not running from a checkout")
    return path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def indicator(**over) -> dict:
    obj = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--0000-1",
        "created": "2026-11-10T00:00:00.000Z",
        "modified": "2026-11-10T00:00:00.000Z",
        "name": "Test marker",
        "pattern": "[file:name = 'marker.bin']",
        "pattern_type": "stix",
        "confidence": 90,
        "labels": ["class-A", "V1"],
        "external_references": [
            {"source_name": "Example", "url": "https://example.invalid/a"},
        ],
    }
    obj.update(over)
    return obj


def bundle(*objects, license_statement=True) -> dict:
    extra = []
    if license_statement:
        extra.append({
            "type": "marking-definition",
            "id": "marking-definition--0000-9",
            "definition_type": "statement",
            "definition": {"statement": "Detection Rule License 1.1"},
        })
    return {"type": "bundle", "id": "bundle--0000-0",
            "objects": list(objects) + extra}


def write(tmp_path, payload, name="bundle.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def do_import(tmp_path, payload, **kwargs) -> sx.Imported:
    kwargs.setdefault("today", TODAY)
    return sx.import_bundle(write(tmp_path, payload), **kwargs)


# ---------------------------------------------------------------------------
# Patterns ColdLight can carry
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("pattern,expected", [
    ("[file:name = 'artx_agent']", (ioc.KIND_FILE_NAME, "artx_agent", False)),
    ("[file:name = '/var/tmp/.agent']",
     (ioc.KIND_FILE_NAME, "/var/tmp/.agent", False)),
    ("[file:hashes.'SHA-256' = '" + "a" * 64 + "']",
     (ioc.KIND_FILE_DIGEST, "a" * 64, False)),
    ('[file:hashes."SHA-256" = "' + "b" * 64 + '"]',
     (ioc.KIND_FILE_DIGEST, "b" * 64, False)),
    ("[file:hashes.SHA-256 = '" + "c" * 64 + "']",
     (ioc.KIND_FILE_DIGEST, "c" * 64, False)),
    ("[network-traffic:dst_port = 8787]",
     (ioc.KIND_LISTENING_PORT, "8787", False)),
    ("[FILE:NAME = 'upper.bin']", (ioc.KIND_FILE_NAME, "upper.bin", False)),
])
def test_a_pattern_this_tool_can_evaluate_is_carried(pattern, expected):
    assert sx.parse_pattern(pattern) == expected


def test_matches_becomes_a_regex_indicator():
    kind, value, is_regex = sx.parse_pattern(
        "[file:name MATCHES '^zzartx[0-9]+" + BS + BS + ".php$']")
    assert (kind, is_regex) == (ioc.KIND_FILE_NAME, True)
    assert value == "^zzartx[0-9]+" + BS + ".php$"


@pytest.mark.parametrize("slashes", [1, 2])
def test_a_regex_escape_survives_the_import(slashes):
    """The one place where unquoting is not cosmetic. Resolving the escaped
    dot to a bare dot would turn it into "any character" and hand the operator
    a broader pattern than the author published, under the author's name.

    Both widths matter, and only one of them separates a correct
    implementation from the obvious wrong one. Two backslashes are the defined
    STIX escape for one backslash, and resolving every pair happens to give
    the same answer. A SINGLE backslash before a metacharacter is not a
    defined STIX escape at all -- it is passed through, and it is how a rule
    author actually writes a regex -- so that is the width where eating the
    escape shows up."""
    pattern = ("[file:name MATCHES '^probekit-[0-9]+" + BS * slashes
               + ".sh$']")
    _kind, value, _regex = sx.parse_pattern(pattern)

    assert value == "^probekit-[0-9]+" + BS + ".sh$"
    compiled = re.compile(value)
    assert compiled.search("probekit-42.sh")
    assert not compiled.search("probekit-42Xsh")


@pytest.mark.parametrize("literal,expected", [
    ("'it" + BS + "'s.bin'", "it's.bin"),
    ("'C:" + BS + BS + "temp" + BS + BS + "x.bin'", "C:" + BS + "temp" + BS + "x.bin"),
])
def test_the_two_stix_escapes_are_resolved(literal, expected):
    kind, value, _ = sx.parse_pattern(f"[file:name = {literal}]")
    assert (kind, value) == (ioc.KIND_FILE_NAME, expected)


# ---------------------------------------------------------------------------
# Patterns that are refused, and the reason given
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("pattern,reason", [
    ("[ipv4-addr:value = '198.51.100.7']", "network address"),
    ("[ipv6-addr:value = '2001:db8::1']", "network address"),
    ("[domain-name:value = 'c2.example.invalid']", "DNS"),
    ("[url:value = 'https://example.invalid/x']", "network traffic"),
    ("[email-addr:value = 'a@example.invalid']", "mail"),
    ("[user-account:account_login = 'svc']", "no account surface"),
    ("[windows-registry-key:key = 'HKLM" + BS + BS + "x']", "registry"),
    ("[process:command_line = 'sh -c x']", "process"),
    ("[directory:path = '/var/tmp']", "match files"),
    ("[artifact:payload_bin = 'eA==']", "never reconstructs"),
    ("[software:name = 'probekit']", "inventory"),
    ("[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']", "MD5"),
    ("[file:hashes.'SHA-1' = 'da39a3ee5e6b4b0d3255bfef95601890afd80709']",
     "SHA-1"),
    ("[file:size = 4096]", "not a marker on its own"),
    ("[network-traffic:src_port = 44321]", "ephemeral"),
    ("[file:name = 'a' AND file:size = 10]", "compound"),
    ("[file:name = 'a'] OR [file:name = 'b']", "compound"),
    ("[file:name = 'a'] FOLLOWEDBY [file:name = 'b']", "compound"),
    ("[file:name IN ('a', 'b')]", "compound"),
    ("[file:name LIKE 'artx%']", "LIKE"),
    ("[file:name != 'artx']", "!= operator"),
    ("[file:size > 10]", "not a marker on its own"),
    ("", "no pattern"),
    ("file:name = 'x'", "not a single STIX comparison"),
    ("[file:unknown_property = 'x']", "no surface in this tool"),
])
def test_a_pattern_this_tool_cannot_carry_is_refused(pattern, reason):
    with pytest.raises(sx.StixError, match=re.escape(reason)):
        sx.parse_pattern(pattern)


def test_a_filename_containing_and_is_not_a_compound_pattern():
    """String literals are blanked before looking for operators, so a file
    called "FOO AND BAR.txt" is imported rather than refused with a reason
    that would make no sense to the reader."""
    kind, value, _ = sx.parse_pattern("[file:name = 'FOO AND BAR.txt']")
    assert (kind, value) == (ioc.KIND_FILE_NAME, "FOO AND BAR.txt")


def test_matches_on_a_digest_is_refused():
    """A digest is compared whole. A regex against one would load and mean
    something the digest surface cannot do."""
    with pytest.raises(sx.StixError, match="compared whole"):
        sx.parse_pattern("[file:hashes.'SHA-256' MATCHES '^a+$']")


def test_a_rule_in_another_language_is_refused(tmp_path):
    payload = bundle(indicator(pattern="title: x\\ndetection: y",
                               pattern_type="sigma"),
                     indicator(id="indicator--0000-2"))
    imported = do_import(tmp_path, payload)
    assert len(imported.entries) == 1
    assert any("sigma rule" in r.reason for r in imported.refusals)


# ---------------------------------------------------------------------------
# The three ColdLight axes
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("confidence,tier", [
    (100, "T1"), (95, "T1"), (85, "T1"),
    (84, "T2"), (70, "T2"), (65, "T2"),
    (64, "T3"), (50, "T3"), (40, "T3"),
    (39, "T4"), (1, "T4"), (0, "T4"),
])
def test_tier_is_derived_from_confidence(confidence, tier):
    obj = indicator(confidence=confidence, labels=[])
    assert sx.tier_of(obj) == (tier, True)


def test_an_explicit_tier_label_beats_the_confidence():
    """The author said it. A derived value must never override a stated one."""
    obj = indicator(confidence=10, labels=["tier-T1"])
    assert sx.tier_of(obj) == ("T1", False)


def test_an_indicator_with_no_tier_and_no_confidence_is_refused(tmp_path):
    """Tier maps to the severity a report prints and attributes to the pack
    author. Inventing it would put our guess in their mouth."""
    obj = indicator(labels=[])
    obj.pop("confidence")
    with pytest.raises(sx.StixError, match="no basis in the bundle"):
        sx.tier_of(obj)

    imported = do_import(tmp_path, bundle(indicator(id="indicator--0000-2"),
                                          obj))
    assert len(imported.entries) == 1
    assert any("no basis" in r.reason for r in imported.refusals)


@pytest.mark.parametrize("confidence", [-1, 101, 500])
def test_a_confidence_outside_the_stix_range_is_refused(confidence):
    with pytest.raises(sx.StixError, match="outside 0-100"):
        sx.tier_of(indicator(confidence=confidence, labels=[]))


def test_a_boolean_confidence_is_not_read_as_a_number():
    """`True` is an int in Python. Reading it as confidence 1 would quietly
    grade an indicator T4 off a field that carries no number at all."""
    with pytest.raises(sx.StixError, match="no basis in the bundle"):
        sx.tier_of(indicator(confidence=True, labels=[]))


@pytest.mark.parametrize("label,expected", [
    ("class-A", "A"), ("class-C", "C"), ("uniqueness-B", "B"),
    ("CLASS-F", "F"),
])
def test_an_explicit_uniqueness_class_is_carried(label, expected):
    assert sx.uniqueness_of(indicator(labels=[label])) == (expected, False)


def test_an_unstated_uniqueness_defaults_to_one_that_cannot_alert_alone():
    """The documented default, and the direction matters: class A would print
    standalone findings the author never graded as distinctive, while
    refusing would discard most real bundles, since STIX has no field for
    this axis."""
    assert sx.uniqueness_of(indicator(labels=[])) == ("C", True)
    assert sx.DEFAULT_UNIQUENESS in ioc.CORROBORATION_CLASSES


def test_an_unstated_verification_defaults_to_unverified():
    assert sx.verification_of(indicator(labels=[])) == ("V4", True)
    assert sx.verification_of(indicator(labels=["V2"])) == ("V2", False)


def test_every_default_applied_is_recorded_on_the_entry(tmp_path):
    obj = indicator(labels=[], confidence=50)
    imported = do_import(tmp_path, bundle(obj))
    entry = imported.entries[0]

    assert entry.uniqueness == "C"
    assert entry.verification == "V4"
    assert entry.tier == "T3"
    assert len(entry.defaults) == 3
    assert "cannot alert on its own" in entry.note
    assert "derived from STIX confidence 50" in entry.note
    assert imported.defaulted == [entry]


# ---------------------------------------------------------------------------
# Reading the bundle
# ---------------------------------------------------------------------------

def test_a_missing_bundle_is_refused(tmp_path):
    with pytest.raises(sx.StixError, match="no such bundle"):
        sx.import_bundle(tmp_path / "nope.json")


def test_a_file_that_is_not_json_is_refused(tmp_path):
    path = tmp_path / "b.json"
    path.write_text("not json at all", encoding="utf-8")
    with pytest.raises(sx.StixError, match="not valid JSON"):
        sx.import_bundle(path)


def test_a_json_file_that_is_not_a_bundle_is_refused(tmp_path):
    """Guessing at the structure of a security artifact is how an importer
    ends up half-reading two different formats."""
    with pytest.raises(sx.StixError, match="not 'bundle'"):
        do_import(tmp_path, {"type": "indicator", "objects": []})


def test_a_bundle_with_no_objects_array_is_refused(tmp_path):
    with pytest.raises(sx.StixError, match="no objects array"):
        do_import(tmp_path, {"type": "bundle"})


def test_a_bundle_with_nothing_importable_is_refused_not_emptied(tmp_path):
    """A pack with no indicators does not load, so writing one would move the
    failure to whoever tried to use the file -- by which time the reasons are
    gone."""
    payload = bundle(indicator(pattern="[ipv4-addr:value = '198.51.100.7']"))
    with pytest.raises(sx.StixError, match="no indicator this tool can"):
        do_import(tmp_path, payload)


def test_the_refusal_reasons_are_in_the_nothing_importable_error(tmp_path):
    payload = bundle(indicator(pattern="[domain-name:value = 'x.invalid']"))
    with pytest.raises(sx.StixError, match="DNS"):
        do_import(tmp_path, payload)


# ---------------------------------------------------------------------------
# Pack metadata
# ---------------------------------------------------------------------------

def test_the_licence_comes_from_a_statement_marking(tmp_path):
    imported = do_import(tmp_path, bundle(indicator()))
    assert imported.license == "Detection Rule License 1.1"


def test_a_tlp_marking_is_not_read_as_a_licence(tmp_path):
    """TLP says who may see the data. It says nothing about the terms of
    reuse, and a pack whose licence field said "TLP:CLEAR" would be
    misattributing the author's own terms."""
    tlp = {"type": "marking-definition", "id": "marking-definition--0000-8",
           "definition_type": "tlp", "definition": {"tlp": "white"}}
    with pytest.raises(sx.StixError, match="--license"):
        do_import(tmp_path, bundle(indicator(), tlp, license_statement=False))


def test_a_bundle_with_no_source_is_refused_with_the_flag_to_pass(tmp_path):
    obj = indicator()
    obj.pop("external_references")
    with pytest.raises(sx.StixError, match="--source"):
        do_import(tmp_path, bundle(obj))


def test_the_operator_can_state_the_source_and_licence(tmp_path):
    obj = indicator()
    obj.pop("external_references")
    imported = do_import(tmp_path, bundle(obj, license_statement=False),
                         source="https://example.invalid/fetched",
                         license="CC0-1.0")
    assert imported.source == "https://example.invalid/fetched"
    assert imported.license == "CC0-1.0"


def test_the_pack_name_comes_from_the_tool_object(tmp_path):
    tool = {"type": "tool", "id": "tool--0000-7", "name": "ProbeKit"}
    imported = do_import(tmp_path, bundle(indicator(), tool))
    assert imported.name == "probekit"


def test_a_bundle_with_no_tool_object_still_gets_a_name(tmp_path):
    assert do_import(tmp_path, bundle(indicator())).name == "imported-bundle"


def test_the_name_and_version_can_be_overridden(tmp_path):
    imported = do_import(tmp_path, bundle(indicator()), name="mine",
                         version="7")
    assert (imported.name, imported.version) == ("mine", "7")


def test_retrieved_is_the_bundles_own_date_when_the_bundle_is_older(tmp_path):
    """A pack fetched today from a year-old bundle is a year-old pack.
    `retrieved` is what the coverage ledger reads to decide whether the intel
    is still current, so understating freshness is the safe direction."""
    imported = do_import(tmp_path, bundle(indicator()))
    assert imported.retrieved == "2026-11-10"


def test_retrieved_never_runs_ahead_of_the_clock(tmp_path):
    """A bundle stamped in the future would otherwise produce a pack that
    reports as fresh for as long as the skew lasts."""
    future = indicator(modified="2027-01-01T00:00:00.000Z")
    imported = do_import(tmp_path, bundle(future))
    assert imported.retrieved == TODAY.isoformat()


def test_two_indicators_with_the_same_name_get_distinct_ids(tmp_path):
    """Ids are how a finding is traced back to the pack, and `load_pack`
    refuses a duplicate."""
    payload = bundle(indicator(id="indicator--0000-1"),
                     indicator(id="indicator--0000-2",
                               pattern="[file:name = 'other.bin']"))
    imported = do_import(tmp_path, payload)
    ids = [e.id for e in imported.entries]
    assert len(set(ids)) == 2, ids
    ioc.load_pack(_written(tmp_path, imported))


def test_an_unnamed_indicator_still_gets_an_id(tmp_path):
    obj = indicator()
    obj.pop("name")
    imported = do_import(tmp_path, bundle(obj))
    assert imported.entries[0].id.startswith("STIX-")


def test_the_stix_id_is_carried_so_a_finding_traces_back(tmp_path):
    imported = do_import(tmp_path, bundle(indicator()))
    assert "imported from indicator--0000-1" in imported.entries[0].note


# ---------------------------------------------------------------------------
# Writing a pack the scanner accepts
# ---------------------------------------------------------------------------

def _written(tmp_path, imported, name="out.toml") -> Path:
    return sx.write_pack(imported, tmp_path / name)


def test_the_generated_pack_loads(tmp_path):
    """The guard this module lives or dies by. An importer that writes a pack
    `load_pack` refuses hands the operator a file that looks like intel."""
    imported = do_import(tmp_path, bundle(indicator()))
    pack = ioc.load_pack(_written(tmp_path, imported))
    assert pack.name == imported.name
    assert len(pack.indicators) == 1


def _stix_literal(value: str) -> str:
    """`value` as a STIX string literal.

    STIX patterning defines two escapes inside a literal, the quote and the
    backslash, and no others: a real tab or newline is written as itself.
    Writing them C-style would produce a pattern whose value is the two
    characters backslash-n, which is what the importer correctly reads it as
    -- and what an earlier version of this test mistook for a bug.
    """
    return "'" + value.replace(BS, BS + BS).replace("'", BS + "'") + "'"


@pytest.mark.parametrize("nasty", [
    "it's-quoted.bin",
    'double"quoted.bin',
    "back" + BS + "slash.bin",
    "double" + BS + BS + "slash.bin",
    "tab\tinside.bin",
    "newline\ninside.bin",
    "both'and" + BS + '"quotes.bin',
])
def test_a_value_needing_escapes_survives_the_toml(tmp_path, nasty):
    """TOML has two string forms and the emitter picks between them: a literal
    string for anything without a quote or a control character, a basic string
    with every escape written out for the rest. A value that came out wrong
    would be an indicator that silently matches something else.

    Checked by parsing the generated file, which is the emitter's own claim.
    What the loader then does with the value is the next test."""
    import tomllib

    imported = do_import(tmp_path, bundle(indicator(
        pattern=f"[file:name = {_stix_literal(nasty)}]")))
    data = tomllib.loads(sx.render_pack(imported))
    assert data["indicator"][0]["value"] == nasty


@pytest.mark.parametrize("nasty", [
    "it's-quoted.bin",
    'double"quoted.bin',
    "back" + BS + "slash.bin",
    "tab\tinside.bin",
    "newline\ninside.bin",
])
def test_the_generated_pack_loads_whatever_the_value_contains(tmp_path, nasty):
    """The loader has to accept it, and for a path it also normalises the
    separators -- `_check_file_name` turns a backslash into a forward slash so
    a pack written with Windows paths matches a tree walked with POSIX ones.
    So this asserts the pack loads and the value arrives normalised, not that
    it arrives byte for byte."""
    imported = do_import(tmp_path, bundle(indicator(
        pattern=f"[file:name = {_stix_literal(nasty)}]")))
    pack = ioc.load_pack(_written(tmp_path, imported))
    assert pack.indicators[0].value == nasty.replace(BS, "/")


def test_a_description_with_quotes_round_trips(tmp_path):
    imported = do_import(tmp_path, bundle(indicator(
        description="the operator's own \"notes\" " + BS + " here")))
    pack = ioc.load_pack(_written(tmp_path, imported))
    assert "operator's own" in pack.indicators[0].note


def test_regex_is_declared_only_for_a_matches_pattern(tmp_path):
    payload = bundle(
        indicator(id="indicator--0000-1",
                  pattern="[file:name MATCHES '^a[0-9]+$']"),
        indicator(id="indicator--0000-2", pattern="[file:name = 'b.bin']"))
    text = sx.render_pack(do_import(tmp_path, payload))
    assert text.count("regex = true") == 1


def test_the_generated_pack_says_it_was_generated(tmp_path):
    payload = bundle(indicator(),
                     indicator(id="indicator--0000-2",
                               pattern="[ipv4-addr:value = '198.51.100.7']"))
    text = sx.render_pack(do_import(tmp_path, payload))
    assert "GENERATED, do not hand-edit" in text
    assert "Refused: 1 STIX indicator(s)" in text


def test_an_empty_optional_field_is_left_out_rather_than_written_blank(
        tmp_path):
    obj = indicator()
    obj.pop("valid_until", None)
    text = sx.render_pack(do_import(tmp_path, bundle(obj)))
    assert "valid_until" not in text


# ---------------------------------------------------------------------------
# The shipped example bundle, end to end
# ---------------------------------------------------------------------------

def test_the_example_bundle_imports(tmp_path):
    imported = sx.import_bundle(_example_bundle(), today=TODAY)
    kinds = sorted(e.kind for e in imported.entries)
    assert kinds == [ioc.KIND_FILE_DIGEST, ioc.KIND_FILE_NAME,
                     ioc.KIND_FILE_NAME, ioc.KIND_FILE_NAME,
                     ioc.KIND_LISTENING_PORT]
    assert len(imported.refusals) == 7
    assert len(imported.expired_on(TODAY)) == 1


def test_the_example_bundle_demonstrates_every_refusal_class(tmp_path):
    """It is documentation. A bundle that only showed what imports would
    teach nobody what the importer will not do."""
    reasons = " ".join(r.reason for r in
                       sx.import_bundle(_example_bundle(),
                                        today=TODAY).refusals)
    for expected in ("network address", "DNS", "compound", "sigma",
                     "MD5", "account", "no basis"):
        assert expected in reasons, expected


def test_a_scan_with_the_imported_example_pack_finds_planted_markers(
        tmp_path):
    """The whole chain: bundle -> pack -> loader -> scan -> findings."""
    imported = sx.import_bundle(_example_bundle(), today=TODAY)
    pack = ioc.load_pack(_written(tmp_path, imported))

    root = tmp_path / "tree"
    (root / "var" / "tmp").mkdir(parents=True)
    (root / "var" / "tmp" / ".probekit-implant").write_bytes(b"x\n")
    (root / "probekit-42.sh").write_bytes(b"#!/bin/sh\n")
    (root / "probekit-notes.sh").write_bytes(b"not anchored\n")
    (root / "renamed.dat").write_bytes(b"exampletool placeholder artifact\n")
    (root / "app.yml").write_bytes(b"port: 19099\n")

    result = ioc.scan_packs(root, [pack], today=TODAY)
    found = {f.indicator_id for f in result.findings}

    assert "PROBEKIT-IMPLANT-ON-DISK" in found
    assert "PROBEKIT-DROPPER-BY-CONTENT-HASH" in found
    assert "PROBEKIT-STAGED-SCRIPT-NAME" in found
    # Anchored, so the second script must not match.
    evidence = " ".join(f.snippet for f in result.findings)
    assert "probekit-notes.sh" not in evidence
    # Graded C by the import default, and promoted here because three other
    # markers turned up in the same scan.
    port = next(f for f in result.findings
                if f.indicator_id == "PROBEKIT-CONSOLE-PORT")
    assert port.corroborated_by


def test_the_expired_entry_is_imported_but_cannot_produce_a_finding(tmp_path):
    imported = sx.import_bundle(_example_bundle(), today=TODAY)
    pack = ioc.load_pack(_written(tmp_path, imported))

    root = tmp_path / "tree"
    (root / "opt" / "probekit").mkdir(parents=True)
    (root / "opt" / "probekit" / "stage0.bin").write_bytes(b"old\n")

    result = ioc.scan_packs(root, [pack], today=TODAY)
    assert result.findings == []
    assert [f.indicator_id for f in result.expired] == [
        "PROBEKIT-2025-STAGER-PATH"]


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def test_the_text_report_groups_refusals_by_reason(tmp_path):
    payload = bundle(
        indicator(),
        indicator(id="indicator--0000-2",
                  pattern="[ipv4-addr:value = '198.51.100.7']"),
        indicator(id="indicator--0000-3",
                  pattern="[ipv4-addr:value = '198.51.100.8']"))
    report = sx.text_report(do_import(tmp_path, payload), today=TODAY)

    assert "NOT imported -- this is the coverage statement" in report
    assert "2  ipv4-addr is a network address" in report
    assert "network, identity and cloud" in report


def test_the_json_report_carries_the_refusals(tmp_path):
    payload = bundle(indicator(),
                     indicator(id="indicator--0000-2",
                               pattern="[domain-name:value = 'x.invalid']"))
    payload_json = sx.json_report(do_import(tmp_path, payload), today=TODAY)

    assert payload_json["indicators_seen"] == 2
    assert payload_json["imported"] == 1
    assert payload_json["refused"] == 1
    assert payload_json["refusals"][0]["name"] == "Test marker"
    assert sum(payload_json["refusals_by_reason"].values()) == 1


def test_an_already_expired_import_is_counted(tmp_path):
    payload = bundle(indicator(valid_until="2026-01-01T00:00:00.000Z"))
    imported = do_import(tmp_path, payload)
    assert len(imported.expired_on(TODAY)) == 1
    assert "already expired" in sx.text_report(imported, today=TODAY)


def test_an_undated_import_is_not_counted_as_expired(tmp_path):
    obj = indicator()
    obj.pop("valid_until", None)
    assert do_import(tmp_path, bundle(obj)).expired_on(TODAY) == []
