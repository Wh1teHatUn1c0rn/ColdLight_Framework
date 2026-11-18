"""Tests for coldlight_detect (ATT&CK mapping, Sigma rules, validation worksheet)."""

import json

import pytest

import coldlight_detect as rd
from coldlight_config import CampaignConfig


# ---------------------------------------------------------------------------
# Technique catalog
# ---------------------------------------------------------------------------

def test_every_technique_has_tactics_and_a_url():
    assert rd.TECHNIQUES
    for tid, tech in rd.TECHNIQUES.items():
        assert tech.technique_id == tid
        assert tech.tactics, f"{tid} has no tactics"
        assert tech.name
        assert tech.exercised, f"{tid} must say what ColdLight actually does"
        assert tech.url.startswith("https://attack.mitre.org/techniques/")


def test_subtechnique_url_uses_a_slash():
    assert rd.TECHNIQUES["T1204.002"].url.endswith("/T1204/002/")
    assert rd.TECHNIQUES["T1091"].url.endswith("/T1091/")


def test_technique_sigma_tag_form():
    assert rd.TECHNIQUES["T1204.002"].tag == "attack.t1204.002"
    assert rd.TECHNIQUES["T1091"].tag == "attack.t1091"


def test_expected_techniques_are_covered():
    # The ones a USB-drop / phishing awareness test genuinely exercises.
    assert {"T1091", "T1204.002", "T1566.002", "T1071.001"} <= set(rd.TECHNIQUES)


# ---------------------------------------------------------------------------
# Vector coverage
# ---------------------------------------------------------------------------

def test_vectors_match_the_db_vector_values():
    # These keys must line up with the `vector` column written by the collector.
    assert set(rd.VECTORS) == {"usb", "link", "qr"}
    for key, vector in rd.VECTORS.items():
        assert vector.vector == key


def test_every_vector_resolves_its_techniques():
    for vector in rd.VECTORS.values():
        techs = vector.techniques
        assert techs, f"{vector.vector} maps to no techniques"
        for tech in techs:
            assert isinstance(tech, rd.Technique)


def test_every_vector_has_telemetry():
    for vector in rd.VECTORS.values():
        assert vector.telemetry, f"{vector.vector} lists no telemetry"
        for source in vector.telemetry:
            assert source.platform in {"windows", "network", "mobile"}
            assert source.source and source.detail


def test_qr_vector_is_honest_about_the_blind_spot():
    gaps = " ".join(rd.VECTORS["qr"].gaps).lower()
    assert "personal" in gaps or "cellular" in gaps


def test_usb_vector_flags_logging_that_is_off_by_default():
    off = [s for s in rd.VECTORS["usb"].telemetry if not s.default_on]
    assert off, "should warn that some USB telemetry is disabled by default"


# ---------------------------------------------------------------------------
# YAML emitter
# ---------------------------------------------------------------------------

def test_quoting_leaves_plain_strings_bare():
    assert rd._q("process_creation") == "process_creation"
    assert rd._q("windows") == "windows"


def test_quoting_protects_special_characters():
    assert rd._q("a: b").startswith("'")
    assert rd._q("C:\\Windows").startswith("'")
    assert rd._q("") == "''"


def test_quoting_protects_ambiguous_scalars():
    # These would otherwise parse as bool/number, not string.
    for value in ("true", "false", "null", "1.0", "42"):
        assert rd._q(value).startswith("'"), value


def test_booleans_and_ints_are_native():
    assert rd._q(True) == "true"
    assert rd._q(False) == "false"
    assert rd._q(6416) == "6416"


def test_single_quotes_are_escaped_by_doubling():
    assert rd._q("it's") == "'it''s'"


def test_emit_renders_nested_structures():
    lines = rd._emit({
        "logsource": {"category": "proxy"},
        "tags": ["attack.t1091", "attack.execution"],
        "level": "high",
    })
    text = "\n".join(lines)
    assert "logsource:" in text
    assert "    category: proxy" in text
    assert "    - attack.t1091" in text
    assert "level: high" in text


# ---------------------------------------------------------------------------
# Sigma rules
# ---------------------------------------------------------------------------

def test_generic_rules_exist_and_have_unique_ids():
    rules = rd.generic_rules()
    assert len(rules) >= 4
    ids = [r.rule_id for r in rules]
    assert len(ids) == len(set(ids)), "Sigma rule ids must be unique"
    filenames = [r.filename for r in rules]
    assert len(filenames) == len(set(filenames))


def test_rule_ids_look_like_uuids():
    for rule in rd.generate_rules():
        parts = rule.rule_id.split("-")
        assert len(parts) == 5, rule.rule_id
        assert [len(p) for p in parts] == [8, 4, 4, 4, 12], rule.rule_id


def test_rule_levels_are_valid_sigma_levels():
    valid = {"informational", "low", "medium", "high", "critical"}
    for rule in rd.generate_rules():
        assert rule.level in valid, f"{rule.filename}: {rule.level}"


def test_rule_yaml_has_the_required_sigma_fields():
    rule = rd.generic_rules()[0]
    text = rule.to_yaml()
    for field in ("title:", "id:", "status:", "description:", "references:",
                  "author:", "date:", "tags:", "logsource:", "detection:",
                  "falsepositives:", "level:"):
        assert field in text, f"missing {field}"


def test_every_rule_has_a_detection_condition():
    for rule in rd.generate_rules():
        assert "condition" in rule.detection, rule.filename
        assert rule.falsepositives, f"{rule.filename} must state false positives"


def test_condition_only_references_defined_selections():
    keywords = {"and", "or", "not", "all", "of", "them", "1", "any"}
    for rule in rd.generate_rules():
        defined = {k for k in rule.detection if k != "condition"}
        condition = rule.detection["condition"]
        for token in condition.replace("(", " ").replace(")", " ").split():
            if token in keywords:
                continue
            assert token in defined, (
                f"{rule.filename}: condition references undefined "
                f"selection {token!r}"
            )


def test_tags_include_both_tactic_and_technique():
    rule = next(r for r in rd.generic_rules()
                if r.filename == "proc_exec_from_removable_media.yml")
    assert "attack.t1091" in rule.tags
    assert "attack.t1204.002" in rule.tags
    assert "attack.initial_access" in rule.tags
    assert "attack.execution" in rule.tags


def test_references_point_at_attack():
    for rule in rd.generate_rules():
        assert any("attack.mitre.org" in ref for ref in rule.references)


def test_removable_media_rule_excludes_the_system_drive():
    rule = next(r for r in rd.generic_rules()
                if r.filename == "proc_exec_from_removable_media.yml")
    text = rule.to_yaml()
    assert "[D-Z]" in text          # only non-system drive letters
    assert "explorer.exe" in text   # user-initiated from the shell


def test_generated_rules_parse_as_real_yaml():
    """The YAML emitter is hand-rolled, so verify it against a real parser.

    A subtly invalid rule would otherwise fail silently here and only surface
    later in someone's SIEM.
    """
    yaml = pytest.importorskip("yaml", reason="pyyaml not installed")

    cfg = CampaignConfig(
        engagement_id="ENG-1",
        lure_filename="Q3_Salary_Review.exe",
        collector_url="https://collector.example.com:8000/awareness/hit",
    )
    required = ("title", "id", "status", "description", "references", "author",
                "date", "tags", "logsource", "detection", "falsepositives",
                "level")

    rules = rd.generate_rules(cfg)
    assert len(rules) >= 6

    for rule in rules:
        doc = yaml.safe_load(rule.to_yaml())
        assert isinstance(doc, dict), rule.filename
        for key in required:
            assert key in doc, f"{rule.filename} missing {key}"
        assert doc["id"] == rule.rule_id
        assert doc["level"] == rule.level
        assert isinstance(doc["tags"], list) and doc["tags"]
        assert isinstance(doc["falsepositives"], list)
        assert "condition" in doc["detection"]


def test_yaml_roundtrip_preserves_regex_and_paths():
    """Backslashes must survive quoting -- a mangled regex silently matches
    nothing, which looks like 'no detections' rather than a broken rule."""
    import re

    yaml = pytest.importorskip("yaml", reason="pyyaml not installed")

    rule = next(r for r in rd.generic_rules()
                if r.filename == "proc_exec_from_removable_media.yml")
    doc = yaml.safe_load(rule.to_yaml())
    detection = doc["detection"]

    pattern = detection["selection_image"]["Image|re"]
    assert pattern == r"^[D-Z]:\\"          # exactly one literal backslash
    assert re.compile(pattern)              # and it is a valid regex
    assert re.match(pattern, r"E:\tool.exe")
    assert not re.match(pattern, r"C:\Windows\system32\cmd.exe")

    assert detection["selection_shell_parent"]["ParentImage|endswith"] == [
        r"\explorer.exe"
    ]
    assert detection["filter_system_drive"]["Image|startswith"] == "C:\\"


def test_yaml_event_ids_stay_integers():
    yaml = pytest.importorskip("yaml", reason="pyyaml not installed")

    rule = next(r for r in rd.generic_rules()
                if r.filename == "usb_device_arrival_driverframeworks.yml")
    doc = yaml.safe_load(rule.to_yaml())
    assert doc["detection"]["selection"]["EventID"] == [2003, 2100, 2102]

    rule = next(r for r in rd.generic_rules()
                if r.filename == "usb_mass_storage_device_arrival.yml")
    doc = yaml.safe_load(rule.to_yaml())
    assert doc["detection"]["selection"]["EventID"] == 6416


def test_yaml_booleans_stay_native():
    yaml = pytest.importorskip("yaml", reason="pyyaml not installed")
    rule = next(r for r in rd.generic_rules()
                if r.filename == "net_conn_from_removable_media.yml")
    doc = yaml.safe_load(rule.to_yaml())
    assert doc["detection"]["selection"]["Initiated"] is True


def test_backslashes_survive_yaml_quoting():
    rule = next(r for r in rd.generic_rules()
                if r.filename == "proc_exec_from_removable_media.yml")
    text = rule.to_yaml()
    # Single-quoted YAML keeps backslashes literal: the regex must not be mangled.
    assert "'^[D-Z]:\\\\'" in text
    assert "'\\explorer.exe'" in text or "- '\\explorer.exe'" in text


# ---------------------------------------------------------------------------
# Campaign-pinned rules
# ---------------------------------------------------------------------------

def test_no_campaign_rules_without_a_config():
    assert rd.generate_rules(None) == rd.generic_rules()


def test_campaign_rules_pin_the_lure_and_collector():
    cfg = CampaignConfig(
        engagement_id="ENG-2026-11",
        authorization_reference="RoE-77",
        lure_filename="Q3_Salary_Review.exe",
        collector_url="https://collector.example.com:8000/awareness/hit",
    )
    rules = rd.generate_rules(cfg)
    names = {r.filename for r in rules}
    assert "campaign_lure_execution.yml" in names
    assert "campaign_landing_page_access.yml" in names

    lure_rule = next(r for r in rules if r.filename == "campaign_lure_execution.yml")
    assert "Q3_Salary_Review.exe" in lure_rule.to_yaml()
    assert "ENG-2026-11" in lure_rule.to_yaml()

    page_rule = next(r for r in rules
                     if r.filename == "campaign_landing_page_access.yml")
    yaml_text = page_rule.to_yaml()
    assert "collector.example.com" in yaml_text
    assert ":8000" not in yaml_text   # host only, no port


def test_campaign_rules_skipped_when_values_are_absent():
    cfg = CampaignConfig(lure_filename="", collector_url="")
    assert rd.campaign_rules(cfg) == []


@pytest.mark.parametrize("url,expected", [
    ("https://host.example.com/awareness/hit", "host.example.com"),
    ("http://10.0.0.5:8000/land", "10.0.0.5"),
    ("host.example.com:8000", "host.example.com"),
    ("", ""),
])
def test_collector_host_extraction(url, expected):
    assert rd._collector_host(url) == expected


# ---------------------------------------------------------------------------
# ATT&CK Navigator layer
# ---------------------------------------------------------------------------

def test_navigator_layer_shape():
    layer = rd.navigator_layer()
    assert layer["domain"] == "enterprise-attack"
    assert layer["versions"]["layer"] == "4.5"
    ids = {t["techniqueID"] for t in layer["techniques"]}
    assert ids == set(rd.TECHNIQUES)
    for entry in layer["techniques"]:
        assert entry["enabled"] is True
        assert entry["score"] == 100
        assert entry["comment"]


def test_navigator_json_is_valid_json():
    parsed = json.loads(rd.navigator_json())
    assert parsed["techniques"]
    assert parsed["name"]


def test_navigator_layer_accepts_a_custom_name():
    assert rd.navigator_layer("My Campaign")["name"] == "My Campaign"
    assert json.loads(rd.navigator_json("Other"))["name"] == "Other"


# ---------------------------------------------------------------------------
# Mapping report / checklist
# ---------------------------------------------------------------------------

def test_mapping_report_covers_every_vector_and_technique():
    text = rd.mapping_report()
    for vector in rd.VECTORS.values():
        assert vector.label in text
    for tid in rd.TECHNIQUES:
        assert tid in text


def test_mapping_report_states_the_scope_limit():
    text = rd.mapping_report().lower()
    assert "benign" in text
    assert "delivery" in text or "user-execution" in text


def test_checklist_warns_to_verify_logging_first():
    text = rd.checklist_markdown()
    assert "Before the test" in text
    assert "Sysmon" in text
    # The key insight: missing logs look like a detection failure.
    assert "logging" in text.lower()


def test_checklist_includes_campaign_details_when_given():
    cfg = CampaignConfig(engagement_id="ENG-9", authorization_reference="RoE-5")
    text = rd.checklist_markdown(cfg)
    assert "ENG-9" in text
    assert "RoE-5" in text


def test_checklist_distinguishes_logged_from_alerted():
    text = rd.checklist_markdown()
    assert "Logged, not alerted" in text
    assert "No telemetry" in text


# ---------------------------------------------------------------------------
# Validation worksheet
# ---------------------------------------------------------------------------

def _hit(**over):
    base = {
        "engagement_id": "ENG-1",
        "run_id": "r1",
        "timestamp_utc": "2026-11-17T14:30:00Z",
        "received_utc": "2026-11-17T14:30:05Z",
        "hostname": "WS-0042",
        "username": "jdoe",
        "os": "Windows 10",
        "ran_from": "E:\\",
        "excluded": 0,
        "vector": "usb",
    }
    base.update(over)
    return base


def test_worksheet_handles_no_hits():
    text = rd.validation_worksheet([])
    assert "No hits recorded yet" in text


def test_worksheet_lists_each_hit_with_host_user_and_time():
    text = rd.validation_worksheet([_hit(), _hit(hostname="WS-9", username="asmith")])
    assert "Hits to validate:** 2" in text
    assert "WS-0042" in text and "jdoe" in text
    assert "WS-9" in text and "asmith" in text
    assert "2026-11-17T14:30:00Z" in text


def test_worksheet_computes_a_search_window():
    text = rd.validation_worksheet([_hit()])
    # +/- 5 minutes around 14:30:00
    assert "2026-11-17T14:25:00Z" in text
    assert "2026-11-17T14:35:00Z" in text


def test_worksheet_tolerates_a_bad_timestamp():
    text = rd.validation_worksheet([_hit(timestamp_utc="not-a-date",
                                         received_utc="")])
    assert "Search window" not in text    # omitted rather than wrong
    assert "WS-0042" in text              # the hit is still listed


def test_worksheet_counts_by_vector():
    hits = [_hit(), _hit(vector="link"), _hit(vector="link")]
    text = rd.validation_worksheet(hits)
    assert "link=2" in text
    assert "usb=1" in text


def test_worksheet_notes_excluded_hits():
    text = rd.validation_worksheet([_hit(excluded=1)])
    assert "safe-listed" in text


def test_worksheet_includes_the_engagement_when_config_given():
    cfg = CampaignConfig(engagement_id="ENG-77")
    assert "ENG-77" in rd.validation_worksheet([_hit()], cfg)


def test_search_hints_are_vector_specific():
    usb = " ".join(rd.hit_search_hints(_hit(vector="usb"))).lower()
    assert "process creation" in usb
    assert "e:\\" in usb or "removable" in usb

    link = " ".join(rd.hit_search_hints(_hit(vector="link"))).lower()
    assert "proxy" in link or "gateway" in link
    assert "dns" in link

    qr = " ".join(rd.hit_search_hints(_hit(vector="qr"))).lower()
    assert "personal" in qr or "cellular" in qr


def test_search_hints_default_for_unknown_vector():
    assert rd.hit_search_hints(_hit(vector="carrier-pigeon"))


def test_shift_handles_offsets_and_bad_input():
    assert rd._shift("2026-11-17T14:30:00Z", 5) == "2026-11-17T14:35:00Z"
    assert rd._shift("2026-11-17T14:30:00+00:00", -30) == "2026-11-17T14:00:00Z"
    assert rd._shift("", 5) == ""
    assert rd._shift("garbage", 5) == ""
