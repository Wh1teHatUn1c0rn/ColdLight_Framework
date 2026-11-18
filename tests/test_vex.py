"""Tests for coldlight_vex: canonical model, validation, and the three emitters."""

import json

import pytest

import coldlight_vex as vx
from coldlight_vulnintel import Finding

TS = "2026-11-17T12:00:00Z"
DOC_ID = "coldlight-vex-11111111-2222-3333-4444-555555555555"


def _doc(*statements, **over):
    kwargs = dict(
        product=vx.Product(name="vendor-appliance", version="4.2.1",
                           purl="pkg:oci/vendor-appliance@4.2.1"),
        author="Offensive Unicorn Crew",
        document_id=DOC_ID,
        timestamp=TS,
    )
    kwargs.update(over)
    doc = vx.VexDocument(**kwargs)
    doc.statements = list(statements)
    return doc


def _stmt(**over):
    base = dict(
        vulnerability="CVE-2021-44228",
        components=["pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"],
        status=vx.STATUS_UNDER_INVESTIGATION,
    )
    base.update(over)
    return vx.Statement(**base)


# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------

def test_canonical_statuses():
    assert set(vx.STATUSES) == {
        "not_affected", "affected", "fixed", "under_investigation"}


def test_the_five_standard_justifications():
    assert set(vx.JUSTIFICATIONS) == {
        "component_not_present",
        "vulnerable_code_not_present",
        "vulnerable_code_not_in_execute_path",
        "vulnerable_code_cannot_be_controlled_by_adversary",
        "inline_mitigations_already_exist",
    }


def test_every_status_maps_to_every_format():
    for status in vx.STATUSES:
        assert status in vx.CDX_STATE
        assert status in vx.CSAF_STATUS


def test_every_justification_maps_to_cyclonedx():
    # CycloneDX uses a different vocabulary, so each one needs a mapping.
    for justification in vx.JUSTIFICATIONS:
        assert justification in vx.CDX_JUSTIFICATION


# ---------------------------------------------------------------------------
# Product identity
# ---------------------------------------------------------------------------

def test_product_prefers_its_purl():
    product = vx.Product(name="app", version="1.0", purl="pkg:oci/app@1.0")
    assert product.identifier == "pkg:oci/app@1.0"


def test_product_synthesises_an_identifier_when_no_purl():
    # A bare name isn't matchable by consumers, so a pkg:generic id is used.
    product = vx.Product(name="Vendor Appliance", version="4.2.1")
    assert product.identifier == "pkg:generic/vendor-appliance@4.2.1"


def test_product_label():
    assert vx.Product(name="app", version="1.0").label == "app 1.0"
    assert vx.Product().label == "unnamed product"


# ---------------------------------------------------------------------------
# Building from scan findings
# ---------------------------------------------------------------------------

def test_from_scan_starts_everything_under_investigation():
    findings = [
        Finding(identifier="CVE-1", package="jinja2", installed_version="2.4.1",
                ecosystem="PyPI", severity="HIGH"),
    ]
    doc = vx.from_scan(findings, product=vx.Product(name="app"))
    assert len(doc.statements) == 1
    assert doc.statements[0].status == "under_investigation"


def test_from_scan_merges_one_cve_across_components():
    findings = [
        Finding(identifier="CVE-1", package="a", installed_version="1.0",
                ecosystem="PyPI", fixed_versions=["1.1"]),
        Finding(identifier="CVE-1", package="b", installed_version="2.0",
                ecosystem="npm", fixed_versions=["2.1"]),
    ]
    doc = vx.from_scan(findings, product=vx.Product(name="app"))
    assert len(doc.statements) == 1
    statement = doc.statements[0]
    assert len(statement.components) == 2
    assert set(statement.fix_versions) == {"1.1", "2.1"}


def test_from_scan_sorts_kev_first():
    findings = [
        Finding(identifier="CVE-low", severity="LOW", package="a",
                installed_version="1", ecosystem="PyPI"),
        Finding(identifier="CVE-crit", severity="CRITICAL", package="b",
                installed_version="1", ecosystem="PyPI"),
        Finding(identifier="CVE-kev", severity="MEDIUM", kev=True, package="c",
                installed_version="1", ecosystem="PyPI"),
    ]
    doc = vx.from_scan(findings, product=vx.Product(name="app"))
    assert [s.vulnerability for s in doc.statements] == [
        "CVE-kev", "CVE-crit", "CVE-low"]


def test_from_scan_carries_kev_flag_for_triage_priority():
    findings = [Finding(identifier="CVE-1", kev=True, package="a",
                        installed_version="1", ecosystem="PyPI")]
    doc = vx.from_scan(findings, product=vx.Product(name="app"))
    assert doc.statements[0].known_exploited is True


def test_from_scan_skips_findings_with_no_id():
    doc = vx.from_scan([Finding(identifier="")], product=vx.Product(name="a"))
    assert doc.statements == []


def test_from_scan_generates_a_document_id_and_timestamp():
    doc = vx.from_scan([], product=vx.Product(name="app"))
    assert doc.document_id.startswith("coldlight-vex-")
    assert doc.timestamp.endswith("Z")


@pytest.mark.parametrize("ecosystem,package,expected", [
    ("PyPI", "jinja2", "pkg:pypi/jinja2@2.4.1"),
    ("npm", "lodash", "pkg:npm/lodash@2.4.1"),
    ("Go", "golang.org/x/text", "pkg:golang/golang.org/x/text@2.4.1"),
    ("crates.io", "smallvec", "pkg:cargo/smallvec@2.4.1"),
])
def test_component_refs_are_rebuilt_as_purls(ecosystem, package, expected):
    finding = Finding(identifier="CVE-1", package=package,
                      installed_version="2.4.1", ecosystem=ecosystem)
    assert vx._component_ref(finding) == expected


def test_maven_component_ref_splits_group_and_artifact():
    finding = Finding(identifier="CVE-1", ecosystem="Maven",
                      package="org.apache.logging.log4j:log4j-core",
                      installed_version="2.14.1")
    assert vx._component_ref(finding) == (
        "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")


def test_component_ref_falls_back_for_unknown_ecosystem():
    finding = Finding(identifier="CVE-1", package="bash",
                      installed_version="5.1", ecosystem="Debian:11")
    assert vx._component_ref(finding) == "bash@5.1"


# ---------------------------------------------------------------------------
# Validation -- the guard against non-conformant VEX
# ---------------------------------------------------------------------------

def test_under_investigation_document_is_valid():
    errors, _ = vx.validate(_doc(_stmt()))
    assert errors == []


def test_not_affected_without_a_reason_is_an_error():
    errors, _ = vx.validate(_doc(_stmt(status="not_affected")))
    assert any("not_affected" in e and "justification" in e for e in errors)


def test_not_affected_accepts_a_justification():
    errors, _ = vx.validate(_doc(_stmt(
        status="not_affected", justification="vulnerable_code_not_in_execute_path")))
    assert errors == []


def test_not_affected_accepts_an_impact_statement_instead():
    errors, _ = vx.validate(_doc(_stmt(
        status="not_affected",
        impact_statement="The logging backend is never initialised.")))
    assert errors == []


def test_affected_without_an_action_statement_is_an_error():
    errors, _ = vx.validate(_doc(_stmt(status="affected")))
    assert any("action_statement" in e for e in errors)


def test_affected_with_an_action_statement_is_valid():
    errors, _ = vx.validate(_doc(_stmt(
        status="affected", action_statement="Upgrade to 2.17.0.")))
    assert errors == []


def test_unknown_status_is_an_error():
    errors, _ = vx.validate(_doc(_stmt(status="probably_fine")))
    assert any("not one of" in e for e in errors)


def test_nonstandard_justification_is_an_error():
    errors, _ = vx.validate(_doc(_stmt(
        status="not_affected", justification="we-looked-and-its-fine")))
    assert any("not a standard VEX justification" in e for e in errors)


def test_missing_components_is_an_error():
    errors, _ = vx.validate(_doc(_stmt(components=[])))
    assert any("no components" in e for e in errors)


def test_empty_vulnerability_id_is_an_error():
    errors, _ = vx.validate(_doc(_stmt(vulnerability="")))
    assert any("vulnerability id is empty" in e for e in errors)


def test_duplicate_statements_are_an_error():
    errors, _ = vx.validate(_doc(_stmt(), _stmt()))
    assert any("duplicate" in e for e in errors)


def test_missing_product_name_is_an_error():
    doc = _doc(_stmt(), product=vx.Product(name="", version="1"))
    errors, _ = vx.validate(doc)
    assert any("product.name" in e for e in errors)


def test_justification_on_wrong_status_warns():
    _, warnings = vx.validate(_doc(_stmt(
        status="fixed", justification="component_not_present",
        fix_versions=["2.15.0"])))
    assert any("only meaningful for" in w for w in warnings)


def test_missing_product_purl_warns():
    doc = _doc(_stmt(), product=vx.Product(name="app", version="1"))
    _, warnings = vx.validate(doc)
    assert any("purl" in w for w in warnings)


def test_kev_still_under_investigation_warns():
    _, warnings = vx.validate(_doc(_stmt(known_exploited=True)))
    assert any("triage this first" in w for w in warnings)


def test_fixed_without_versions_warns():
    _, warnings = vx.validate(_doc(_stmt(status="fixed")))
    assert any("no fix_versions" in w for w in warnings)


def test_emitters_refuse_invalid_documents():
    doc = _doc(_stmt(status="not_affected"))     # no justification
    for fmt in vx.FORMATS:
        with pytest.raises(vx.VexError, match="non-conformant"):
            vx.emit(doc, fmt)


def test_unknown_format_raises():
    with pytest.raises(vx.VexError, match="unknown VEX format"):
        vx.emit(_doc(_stmt()), "spdx-vex")


# ---------------------------------------------------------------------------
# OpenVEX
# ---------------------------------------------------------------------------

def test_openvex_document_shape():
    doc = _doc(_stmt(status="affected", action_statement="Upgrade to 2.17.0."))
    out = vx.to_openvex(doc)

    assert out["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert DOC_ID in out["@id"]
    assert out["author"] == "Offensive Unicorn Crew"
    assert out["timestamp"] == TS
    assert out["version"] == 1
    assert len(out["statements"]) == 1

    statement = out["statements"][0]
    assert statement["vulnerability"]["name"] == "CVE-2021-44228"
    assert statement["status"] == "affected"
    assert statement["action_statement"] == "Upgrade to 2.17.0."
    assert statement["products"][0]["@id"] == "pkg:oci/vendor-appliance@4.2.1"
    assert statement["products"][0]["subcomponents"][0]["@id"].startswith(
        "pkg:maven/")


def test_openvex_includes_justification_only_for_not_affected():
    affected = vx.to_openvex(_doc(_stmt(
        status="affected", action_statement="Patch.",
        justification="component_not_present")))
    assert "justification" not in affected["statements"][0]

    not_affected = vx.to_openvex(_doc(_stmt(
        status="not_affected", justification="component_not_present")))
    assert not_affected["statements"][0]["justification"] == (
        "component_not_present")


def test_openvex_carries_aliases_and_description():
    doc = _doc(_stmt(aliases=["GHSA-jfh8-c2jp-5v3q"],
                     description="Remote code injection in Log4j"))
    vulnerability = vx.to_openvex(doc)["statements"][0]["vulnerability"]
    assert vulnerability["aliases"] == ["GHSA-jfh8-c2jp-5v3q"]
    assert "Log4j" in vulnerability["description"]


def test_openvex_is_json_serialisable():
    json.dumps(vx.to_openvex(_doc(_stmt())))


# ---------------------------------------------------------------------------
# CycloneDX VEX
# ---------------------------------------------------------------------------

def test_cyclonedx_document_shape():
    doc = _doc(_stmt(severity="CRITICAL", description="RCE",
                     fix_versions=["2.15.0"]))
    out = vx.to_cyclonedx_vex(doc)

    assert out["bomFormat"] == "CycloneDX"
    assert out["specVersion"] == "1.5"
    assert out["serialNumber"].startswith("urn:uuid:")
    assert out["metadata"]["component"]["name"] == "vendor-appliance"

    vulnerability = out["vulnerabilities"][0]
    assert vulnerability["id"] == "CVE-2021-44228"
    assert vulnerability["analysis"]["state"] == "in_triage"
    assert vulnerability["ratings"] == [{"severity": "critical"}]
    assert "2.15.0" in vulnerability["recommendation"]
    assert vulnerability["source"]["url"].endswith("CVE-2021-44228")


def test_cyclonedx_affects_refs_resolve_to_components():
    """A dangling affects[].ref makes the BOM unusable, so every referenced
    component must be present with a matching bom-ref."""
    doc = _doc(
        _stmt(),
        _stmt(vulnerability="CVE-2020-1", components=["pkg:pypi/jinja2@2.4.1"]),
    )
    out = vx.to_cyclonedx_vex(doc)

    bom_refs = {c["bom-ref"] for c in out["components"]}
    for vulnerability in out["vulnerabilities"]:
        for affects in vulnerability["affects"]:
            assert affects["ref"] in bom_refs


def test_cyclonedx_components_are_deduped():
    shared = ["pkg:pypi/jinja2@2.4.1"]
    doc = _doc(
        _stmt(vulnerability="CVE-A", components=shared),
        _stmt(vulnerability="CVE-B", components=shared),
    )
    out = vx.to_cyclonedx_vex(doc)
    assert len(out["components"]) == 1


def test_cyclonedx_component_name_comes_from_the_purl():
    doc = _doc(_stmt(components=["pkg:pypi/jinja2@2.4.1"]))
    component = vx.to_cyclonedx_vex(doc)["components"][0]
    assert component["name"] == "jinja2"        # not "pkg:pypi/jinja2"
    assert component["version"] == "2.4.1"
    assert component["purl"] == "pkg:pypi/jinja2@2.4.1"
    assert component["bom-ref"] == "pkg:pypi/jinja2@2.4.1"


def test_cyclonedx_maven_namespace_becomes_group():
    doc = _doc(_stmt(
        components=["pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"]))
    component = vx.to_cyclonedx_vex(doc)["components"][0]
    assert component["name"] == "log4j-core"
    assert component["group"] == "org.apache.logging.log4j"
    assert component["version"] == "2.14.1"


def test_cyclonedx_component_falls_back_for_non_purl_refs():
    doc = _doc(_stmt(components=["bash@5.1"]))
    component = vx.to_cyclonedx_vex(doc)["components"][0]
    assert component["name"] == "bash"
    assert component["version"] == "5.1"
    assert "purl" not in component


@pytest.mark.parametrize("status,state", [
    ("under_investigation", "in_triage"),
    ("not_affected", "not_affected"),
    ("fixed", "resolved"),
])
def test_cyclonedx_state_mapping(status, state):
    statement = _stmt(status=status, justification="component_not_present"
                      if status == "not_affected" else "",
                      fix_versions=["1.0"] if status == "fixed" else [])
    out = vx.to_cyclonedx_vex(_doc(statement))
    assert out["vulnerabilities"][0]["analysis"]["state"] == state


def test_cyclonedx_affected_maps_to_exploitable_with_response():
    doc = _doc(_stmt(status="affected", action_statement="Upgrade.",
                     fix_versions=["2.15.0"]))
    analysis = vx.to_cyclonedx_vex(doc)["vulnerabilities"][0]["analysis"]
    assert analysis["state"] == "exploitable"
    assert analysis["response"] == ["update"]
    assert "Upgrade." in analysis["detail"]


def test_cyclonedx_affected_without_a_fix_suggests_workaround():
    doc = _doc(_stmt(status="affected", action_statement="Disable the feature."))
    analysis = vx.to_cyclonedx_vex(doc)["vulnerabilities"][0]["analysis"]
    assert analysis["response"] == ["workaround_available"]


def test_cyclonedx_translates_the_justification_vocabulary():
    doc = _doc(_stmt(status="not_affected",
                     justification="vulnerable_code_not_in_execute_path"))
    analysis = vx.to_cyclonedx_vex(doc)["vulnerabilities"][0]["analysis"]
    # CycloneDX spells this differently from OpenVEX/CSAF.
    assert analysis["justification"] == "code_not_reachable"


def test_cyclonedx_serial_number_is_stable():
    doc = _doc(_stmt())
    assert (vx.to_cyclonedx_vex(doc)["serialNumber"]
            == vx.to_cyclonedx_vex(doc)["serialNumber"])


# ---------------------------------------------------------------------------
# CSAF 2.0
# ---------------------------------------------------------------------------

def test_csaf_document_shape():
    doc = _doc(_stmt())
    out = vx.to_csaf(doc)

    document = out["document"]
    assert document["category"] == "csaf_vex"
    assert document["csaf_version"] == "2.0"
    assert document["publisher"]["name"] == "Offensive Unicorn Crew"

    tracking = document["tracking"]
    assert tracking["id"] == DOC_ID
    assert tracking["status"] == "final"
    assert tracking["version"] == "1"
    assert tracking["initial_release_date"] == TS
    assert tracking["revision_history"][0]["number"] == "1"
    assert tracking["generator"]["engine"]["name"] == "ColdLight"


def test_csaf_models_components_as_relationships():
    """CSAF expresses 'this library inside this product' via
    default_component_of, and VEX statements reference that relationship id."""
    doc = _doc(_stmt())
    out = vx.to_csaf(doc)

    tree = out["product_tree"]
    product_ids = {p["product_id"] for p in tree["full_product_names"]}
    assert "CSAFPID-0001" in product_ids          # the product itself
    assert "CSAFPID-C0001" in product_ids         # the component

    relationship = tree["relationships"][0]
    assert relationship["category"] == "default_component_of"
    assert relationship["product_reference"] == "CSAFPID-C0001"
    assert relationship["relates_to_product_reference"] == "CSAFPID-0001"
    rel_id = relationship["full_product_name"]["product_id"]

    # The statement must reference the relationship, not the bare component.
    status = out["vulnerabilities"][0]["product_status"]
    assert status["under_investigation"] == [rel_id]


def test_csaf_product_status_buckets():
    cases = {
        "under_investigation": "under_investigation",
        "not_affected": "known_not_affected",
        "affected": "known_affected",
        "fixed": "fixed",
    }
    for status, bucket in cases.items():
        statement = _stmt(
            status=status,
            justification="component_not_present" if status == "not_affected" else "",
            action_statement="Upgrade." if status == "affected" else "",
            fix_versions=["2.15.0"] if status == "fixed" else [],
        )
        out = vx.to_csaf(_doc(statement))
        assert bucket in out["vulnerabilities"][0]["product_status"]


def test_csaf_not_affected_carries_a_machine_readable_flag():
    doc = _doc(_stmt(status="not_affected",
                     justification="vulnerable_code_not_present"))
    vulnerability = vx.to_csaf(doc)["vulnerabilities"][0]
    # CSAF adopted the VEX justification labels verbatim.
    assert vulnerability["flags"][0]["label"] == "vulnerable_code_not_present"
    assert vulnerability["flags"][0]["product_ids"]


def test_csaf_impact_statement_becomes_a_threat():
    doc = _doc(_stmt(status="not_affected",
                     impact_statement="Logging is never initialised."))
    vulnerability = vx.to_csaf(doc)["vulnerabilities"][0]
    assert vulnerability["threats"][0]["category"] == "impact"
    assert "Logging" in vulnerability["threats"][0]["details"]


def test_csaf_affected_carries_a_remediation():
    doc = _doc(_stmt(status="affected", action_statement="Upgrade to 2.17.0.",
                     fix_versions=["2.17.0"]))
    remediation = vx.to_csaf(doc)["vulnerabilities"][0]["remediations"][0]
    assert remediation["category"] == "vendor_fix"
    assert "2.17.0" in remediation["details"]


def test_csaf_affected_without_fix_versions_is_a_workaround():
    doc = _doc(_stmt(status="affected", action_statement="Disable the endpoint."))
    remediation = vx.to_csaf(doc)["vulnerabilities"][0]["remediations"][0]
    assert remediation["category"] == "workaround"


def test_csaf_uses_cve_field_for_cves_and_ids_otherwise():
    cve_doc = vx.to_csaf(_doc(_stmt(vulnerability="CVE-2021-44228")))
    assert cve_doc["vulnerabilities"][0]["cve"] == "CVE-2021-44228"

    ghsa_doc = vx.to_csaf(_doc(_stmt(vulnerability="GHSA-abcd-1234-efgh")))
    entry = ghsa_doc["vulnerabilities"][0]
    assert "cve" not in entry
    assert entry["ids"][0]["text"] == "GHSA-abcd-1234-efgh"


def test_csaf_is_json_serialisable():
    json.dumps(vx.to_csaf(_doc(_stmt())))


# ---------------------------------------------------------------------------
# Triage round-trip
# ---------------------------------------------------------------------------

def test_triage_round_trip(tmp_path):
    doc = _doc(_stmt(
        status="not_affected",
        justification="vulnerable_code_not_in_execute_path",
        impact_statement="Never initialised.",
        description="RCE",
        aliases=["GHSA-x"],
        fix_versions=["2.15.0"],
        severity="CRITICAL",
        known_exploited=True,
    ))
    path = tmp_path / "triage.json"
    vx.save_triage(doc, path)

    loaded = vx.load_triage(path)
    assert loaded.product.name == doc.product.name
    assert loaded.product.purl == doc.product.purl
    assert loaded.author == doc.author
    assert loaded.document_id == doc.document_id
    assert loaded.timestamp == doc.timestamp

    original, restored = doc.statements[0], loaded.statements[0]
    assert restored.vulnerability == original.vulnerability
    assert restored.status == original.status
    assert restored.justification == original.justification
    assert restored.impact_statement == original.impact_statement
    assert restored.components == original.components
    assert restored.fix_versions == original.fix_versions
    assert restored.severity == original.severity
    assert restored.known_exploited is True


def test_edited_triage_file_emits_the_new_decision(tmp_path):
    """The whole workflow: init writes under_investigation, a human edits it,
    emit reflects the decision."""
    path = tmp_path / "triage.json"
    vx.save_triage(_doc(_stmt()), path)

    data = json.loads(path.read_text(encoding="utf-8"))
    data["statements"][0]["status"] = "not_affected"
    data["statements"][0]["justification"] = "vulnerable_code_not_in_execute_path"
    path.write_text(json.dumps(data), encoding="utf-8")

    out = vx.to_openvex(vx.load_triage(path))
    assert out["statements"][0]["status"] == "not_affected"
    assert out["statements"][0]["justification"] == (
        "vulnerable_code_not_in_execute_path")


def test_load_missing_triage_raises():
    with pytest.raises(vx.VexError, match="no such triage file"):
        vx.load_triage("nope.json")


def test_load_bad_json_raises(tmp_path):
    path = tmp_path / "triage.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(vx.VexError, match="not valid JSON"):
        vx.load_triage(path)


def test_load_non_object_raises(tmp_path):
    path = tmp_path / "triage.json"
    path.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(vx.VexError, match="expected a JSON object"):
        vx.load_triage(path)


def test_load_tolerates_junk_statements(tmp_path):
    path = tmp_path / "triage.json"
    path.write_text(json.dumps({
        "product": {"name": "app"},
        "statements": ["not a dict", {"vulnerability": "CVE-1"}],
    }), encoding="utf-8")
    doc = vx.load_triage(path)
    assert len(doc.statements) == 1
    assert doc.statements[0].vulnerability == "CVE-1"


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def test_summary_counts_statuses():
    doc = _doc(
        _stmt(vulnerability="CVE-A"),
        _stmt(vulnerability="CVE-B", status="not_affected",
              justification="component_not_present"),
    )
    assert doc.status_counts() == {"not_affected": 1, "under_investigation": 1}

    text = vx.text_summary(doc)
    assert "vendor-appliance 4.2.1" in text
    assert "under_investigation=1" in text


def test_summary_explains_what_triage_needs():
    text = vx.text_summary(_doc(_stmt()))
    assert "under investigation" in text
    assert "needs a justification" in text
    assert "needs an action_statement" in text
    for justification in vx.JUSTIFICATIONS:
        assert justification in text


def test_summary_highlights_kev():
    text = vx.text_summary(_doc(_stmt(known_exploited=True)))
    assert "known-exploited" in text


def test_summary_of_fully_triaged_document_has_no_todo():
    doc = _doc(_stmt(status="not_affected",
                     justification="component_not_present"))
    assert "still under investigation" not in vx.text_summary(doc)
