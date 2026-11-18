"""Tests for coldlight_sbom (CycloneDX / SPDX ingest and purl mapping)."""

import json

import pytest

import coldlight_sbom as sb


# ---------------------------------------------------------------------------
# purl parsing
# ---------------------------------------------------------------------------

def test_parse_simple_purl():
    purl = sb.parse_purl("pkg:pypi/jinja2@2.4.1")
    assert (purl.type, purl.namespace, purl.name, purl.version) == (
        "pypi", "", "jinja2", "2.4.1")


def test_parse_purl_with_namespace():
    purl = sb.parse_purl("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")
    assert purl.type == "maven"
    assert purl.namespace == "org.apache.logging.log4j"
    assert purl.name == "log4j-core"
    assert purl.version == "2.14.1"


def test_parse_purl_with_multi_segment_namespace():
    purl = sb.parse_purl("pkg:golang/golang.org/x/text@v0.3.2")
    assert purl.namespace == "golang.org/x"
    assert purl.name == "text"
    assert purl.version == "v0.3.2"


def test_parse_purl_percent_decodes():
    purl = sb.parse_purl("pkg:npm/%40babel/core@7.0.0")
    assert purl.namespace == "@babel"
    assert purl.name == "core"


def test_parse_purl_qualifiers_and_subpath():
    purl = sb.parse_purl(
        "pkg:deb/debian/bash@5.1-2?arch=amd64&distro=debian-11#some/path")
    assert purl.type == "deb"
    assert purl.name == "bash"
    assert purl.version == "5.1-2"
    assert purl.qualifiers["distro"] == "debian-11"
    assert purl.qualifiers["arch"] == "amd64"


def test_parse_purl_version_split_takes_last_at():
    purl = sb.parse_purl("pkg:npm/%40scope/pkg@1.0.0")
    assert purl.name == "pkg"
    assert purl.version == "1.0.0"


@pytest.mark.parametrize("bad", [
    "", "jinja2==2.4.1", "http://example.com/x", "pkg:", "pkg:pypi", "pkg:/",
])
def test_parse_purl_rejects_junk(bad):
    assert sb.parse_purl(bad) is None


# ---------------------------------------------------------------------------
# purl -> OSV ecosystem mapping
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("purl,expected", [
    ("pkg:pypi/jinja2@2.4.1", ("PyPI", "jinja2", "2.4.1")),
    ("pkg:npm/lodash@4.17.11", ("npm", "lodash", "4.17.11")),
    ("pkg:npm/%40babel/core@7.0.0", ("npm", "@babel/core", "7.0.0")),
    ("pkg:cargo/smallvec@0.6.13", ("crates.io", "smallvec", "0.6.13")),
    ("pkg:gem/rails@6.0.0", ("RubyGems", "rails", "6.0.0")),
    ("pkg:nuget/Newtonsoft.Json@12.0.1", ("NuGet", "Newtonsoft.Json", "12.0.1")),
    ("pkg:composer/symfony/http-kernel@4.4.0",
     ("Packagist", "symfony/http-kernel", "4.4.0")),
])
def test_language_ecosystem_mapping(purl, expected):
    assert sb.purl_to_osv(sb.parse_purl(purl)) == expected


def test_maven_uses_group_colon_artifact():
    got = sb.purl_to_osv(
        sb.parse_purl("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"))
    assert got == ("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1")


def test_golang_rebuilds_module_path_and_strips_v():
    got = sb.purl_to_osv(sb.parse_purl("pkg:golang/golang.org/x/text@v0.3.2"))
    assert got == ("Go", "golang.org/x/text", "0.3.2")


def test_pypi_names_are_normalised():
    # OSV keys PyPI on the PEP 503 normalised name.
    got = sb.purl_to_osv(sb.parse_purl("pkg:pypi/Flask_SQLAlchemy@2.4.1"))
    assert got == ("PyPI", "flask-sqlalchemy", "2.4.1")


def test_unversioned_component_is_not_queryable():
    assert sb.purl_to_osv(sb.parse_purl("pkg:pypi/jinja2")) == ("", "", "")


def test_unsupported_purl_type_is_not_queryable():
    assert sb.purl_to_osv(sb.parse_purl("pkg:docker/library/nginx@1.21")) == (
        "", "", "")
    assert sb.purl_to_osv(sb.parse_purl("pkg:generic/openssl@1.1.1")) == (
        "", "", "")


# ---------------------------------------------------------------------------
# OS packages: the dangerous case
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("purl,expected_eco", [
    ("pkg:deb/debian/bash@5.1-2?distro=debian-11", "Debian:11"),
    ("pkg:deb/ubuntu/openssl@3.0.2?distro=ubuntu-22.04", "Ubuntu:22.04"),
    ("pkg:apk/alpine/busybox@1.36.1?distro=alpine-3.18.4", "Alpine:v3.18"),
    ("pkg:rpm/redhat/bash@5.1?distro=rhel-9.2", "Red Hat"),
    ("pkg:rpm/rocky/bash@5.1?distro=rocky-9.3", "Rocky Linux:9"),
    ("pkg:rpm/almalinux/bash@5.1?distro=almalinux-9", "AlmaLinux:9"),
])
def test_os_package_ecosystems(purl, expected_eco):
    eco, name, version = sb.purl_to_osv(sb.parse_purl(purl))
    assert eco == expected_eco
    assert name and version


def test_os_package_without_distro_is_skipped_not_guessed():
    """The important one: a wrong ecosystem returns zero OSV results, which
    would look like 'clean'. It must refuse to guess instead."""
    eco, _, _ = sb.purl_to_osv(sb.parse_purl("pkg:deb/debian/bash@5.1-2"))
    assert eco == ""


def test_os_package_with_unknown_distro_is_skipped():
    eco, _, _ = sb.purl_to_osv(
        sb.parse_purl("pkg:rpm/weirdos/bash@5.1?distro=weirdos-1"))
    assert eco == ""


def test_debian_uses_major_only_and_ubuntu_keeps_minor():
    assert sb.purl_to_osv(
        sb.parse_purl("pkg:deb/debian/x@1?distro=debian-11.7"))[0] == "Debian:11"
    assert sb.purl_to_osv(
        sb.parse_purl("pkg:deb/ubuntu/x@1?distro=ubuntu-20.04"))[0] == "Ubuntu:20.04"


# ---------------------------------------------------------------------------
# Component construction
# ---------------------------------------------------------------------------

def test_component_without_purl_is_skipped_with_a_reason():
    comp = sb._component_from("mystery", "1.0", "")
    assert not comp.checkable
    assert "no purl" in comp.skip_reason


def test_component_with_bad_purl_is_skipped_with_a_reason():
    comp = sb._component_from("x", "1.0", "not-a-purl")
    assert not comp.checkable
    assert "unparseable" in comp.skip_reason


def test_component_with_unsupported_type_names_the_type():
    comp = sb._component_from("nginx", "1.21", "pkg:docker/library/nginx@1.21")
    assert not comp.checkable
    assert "docker" in comp.skip_reason


def test_os_component_skip_reason_explains_the_distro_requirement():
    comp = sb._component_from("bash", "5.1", "pkg:deb/debian/bash@5.1")
    assert not comp.checkable
    assert "distro" in comp.skip_reason.lower()


def test_purl_version_wins_over_sbom_version_field():
    # The purl is authoritative; a stale name/version field must not be used.
    comp = sb._component_from("jinja2", "999.0", "pkg:pypi/jinja2@2.4.1")
    assert comp.checkable
    assert comp.version == "2.4.1"


# ---------------------------------------------------------------------------
# CycloneDX
# ---------------------------------------------------------------------------

CYCLONEDX = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": "urn:uuid:1234",
    "metadata": {
        "component": {"type": "application", "name": "vendor-appliance"},
        "tools": {"components": [{"name": "syft", "version": "1.4.1"}]},
    },
    "components": [
        {"type": "library", "name": "jinja2", "version": "2.4.1",
         "purl": "pkg:pypi/jinja2@2.4.1"},
        {"type": "library", "name": "lodash", "version": "4.17.11",
         "purl": "pkg:npm/lodash@4.17.11",
         "components": [
             {"type": "library", "name": "smallvec", "version": "0.6.13",
              "purl": "pkg:cargo/smallvec@0.6.13"},
         ]},
        {"type": "operating-system", "name": "alpine", "version": "3.18"},
    ],
}


def test_parse_cyclonedx_metadata():
    sbom = sb.parse_cyclonedx(CYCLONEDX)
    assert sbom.fmt == "CycloneDX"
    assert sbom.spec_version == "1.5"
    assert sbom.document_name == "vendor-appliance"
    assert sbom.tools == ["syft 1.4.1"]
    assert "CycloneDX 1.5" in sbom.label
    assert "syft" in sbom.label


def test_parse_cyclonedx_walks_nested_components():
    sbom = sb.parse_cyclonedx(CYCLONEDX)
    names = {c.name for c in sbom.checkable}
    assert names == {"jinja2", "lodash", "smallvec"}      # nested one included
    assert len(sbom.skipped) == 1                          # the OS entry, no purl


def test_cyclonedx_1_4_tools_shape():
    data = dict(CYCLONEDX)
    data["metadata"] = {"tools": [{"vendor": "x", "name": "cdxgen",
                                   "version": "9.0"}]}
    assert sb.parse_cyclonedx(data).tools == ["cdxgen 9.0"]


def test_cyclonedx_handles_missing_sections():
    sbom = sb.parse_cyclonedx({"bomFormat": "CycloneDX", "specVersion": "1.4"})
    assert sbom.components == []
    assert sbom.checkable == []


# ---------------------------------------------------------------------------
# SPDX JSON
# ---------------------------------------------------------------------------

SPDX_JSON = {
    "spdxVersion": "SPDX-2.3",
    "name": "vendor-image-sbom",
    "creationInfo": {
        "creators": ["Tool: trivy-0.50.1", "Organization: Acme"],
    },
    "packages": [
        {
            "name": "jinja2", "versionInfo": "2.4.1", "SPDXID": "SPDXRef-1",
            "externalRefs": [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": "pkg:pypi/jinja2@2.4.1",
            }],
        },
        {
            "name": "bash", "versionInfo": "5.1-2", "SPDXID": "SPDXRef-2",
            "externalRefs": [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": "pkg:deb/debian/bash@5.1-2?distro=debian-11",
            }],
        },
        {"name": "vendor-image", "versionInfo": "1.0", "SPDXID": "SPDXRef-root"},
    ],
}


def test_parse_spdx_json():
    sbom = sb.parse_spdx_json(SPDX_JSON)
    assert sbom.fmt == "SPDX"
    assert sbom.spec_version == "SPDX-2.3"
    assert sbom.document_name == "vendor-image-sbom"
    assert sbom.tools == ["trivy-0.50.1"]          # Organization filtered out

    checkable = {(c.name, c.ecosystem) for c in sbom.checkable}
    assert ("jinja2", "PyPI") in checkable
    assert ("bash", "Debian:11") in checkable
    assert len(sbom.skipped) == 1                   # the root package, no purl


def test_spdx_json_ignores_non_purl_external_refs():
    package = {
        "name": "x", "versionInfo": "1.0",
        "externalRefs": [
            {"referenceType": "cpe23Type",
             "referenceLocator": "cpe:2.3:a:x:x:1.0:*:*:*:*:*:*:*"},
        ],
    }
    sbom = sb.parse_spdx_json({"packages": [package]})
    assert not sbom.checkable
    assert "no purl" in sbom.skipped[0].skip_reason


# ---------------------------------------------------------------------------
# SPDX tag-value
# ---------------------------------------------------------------------------

SPDX_TAG = """
SPDXVersion: SPDX-2.2
DataLicense: CC0-1.0
DocumentName: tag-value-example
Creator: Tool: syft-1.0.0
Creator: Person: someone

PackageName: jinja2
SPDXID: SPDXRef-Package-jinja2
PackageVersion: 2.4.1
ExternalRef: PACKAGE-MANAGER purl pkg:pypi/jinja2@2.4.1

PackageName: lodash
SPDXID: SPDXRef-Package-lodash
PackageVersion: 4.17.11
ExternalRef: PACKAGE-MANAGER purl pkg:npm/lodash@4.17.11

PackageName: no-purl-here
PackageVersion: 9.9
"""


def test_parse_spdx_tag_value():
    sbom = sb.parse_spdx_tag_value(SPDX_TAG)
    assert sbom.fmt == "SPDX"
    assert sbom.spec_version == "SPDX-2.2"
    assert sbom.document_name == "tag-value-example"
    assert sbom.tools == ["syft-1.0.0"]

    assert len(sbom.components) == 3
    checkable = {c.name for c in sbom.checkable}
    assert checkable == {"jinja2", "lodash"}
    assert sbom.skipped[0].name == "no-purl-here"


def test_tag_value_packages_do_not_bleed_into_each_other():
    """A missing version on one package must not inherit the previous one's."""
    text = ("SPDXVersion: SPDX-2.2\n"
            "PackageName: first\nPackageVersion: 1.0\n"
            "ExternalRef: PACKAGE-MANAGER purl pkg:pypi/first@1.0\n"
            "PackageName: second\n")
    sbom = sb.parse_spdx_tag_value(text)
    names = [c.name for c in sbom.components]
    assert names == ["first", "second"]
    second = sbom.components[1]
    assert second.version == ""
    assert not second.checkable


# ---------------------------------------------------------------------------
# Format detection and loading
# ---------------------------------------------------------------------------

def test_detect_formats():
    assert sb.detect_format(json.dumps(CYCLONEDX)) == "cyclonedx"
    assert sb.detect_format(json.dumps(SPDX_JSON)) == "spdx-json"
    assert sb.detect_format(SPDX_TAG) == "spdx-tag"
    assert sb.detect_format("<bom xmlns='...'></bom>") == "xml"
    assert sb.detect_format("hello world") == ""
    assert sb.detect_format("{bad json") == ""


def test_load_cyclonedx_file(tmp_path):
    path = tmp_path / "bom.json"
    path.write_text(json.dumps(CYCLONEDX), encoding="utf-8")
    sbom = sb.load_sbom(path)
    assert sbom.fmt == "CycloneDX"
    assert sbom.path == str(path)
    assert len(sbom.checkable) == 3


def test_load_spdx_json_file(tmp_path):
    path = tmp_path / "sbom.spdx.json"
    path.write_text(json.dumps(SPDX_JSON), encoding="utf-8")
    assert sb.load_sbom(path).fmt == "SPDX"


def test_load_spdx_tag_file(tmp_path):
    path = tmp_path / "sbom.spdx"
    path.write_text(SPDX_TAG, encoding="utf-8")
    assert sb.load_sbom(path).spec_version == "SPDX-2.2"


def test_load_missing_file_raises():
    with pytest.raises(sb.SbomError, match="no such file"):
        sb.load_sbom("definitely-not-here.json")


def test_load_xml_explains_how_to_convert(tmp_path):
    path = tmp_path / "bom.xml"
    path.write_text("<bom></bom>", encoding="utf-8")
    with pytest.raises(sb.SbomError, match="XML"):
        sb.load_sbom(path)


def test_load_unrecognised_raises(tmp_path):
    path = tmp_path / "notes.txt"
    path.write_text("just some notes", encoding="utf-8")
    with pytest.raises(sb.SbomError, match="unrecognised"):
        sb.load_sbom(path)


# ---------------------------------------------------------------------------
# Jobs and reporting
# ---------------------------------------------------------------------------

def test_to_jobs_shape_matches_the_scanner():
    sbom = sb.parse_cyclonedx(CYCLONEDX)
    sbom.path = "bom.json"
    jobs = sb.to_jobs(sbom)
    assert len(jobs) == 3
    for name, version, ecosystem, location in jobs:
        assert name and version and ecosystem
        assert location == "bom.json"


def test_skip_summary_groups_identical_reasons():
    sbom = sb.Sbom()
    sbom.components = [
        sb._component_from("a", "1", "pkg:docker/library/a@1"),
        sb._component_from("b", "1", "pkg:docker/library/b@1"),
        sb._component_from("c", "1", ""),
    ]
    summary = sbom.skip_summary()
    assert sum(summary.values()) == 3
    assert len(summary) == 2                       # two distinct reasons
    assert summary["unsupported purl type: 'docker'"] == 2


def test_skip_summary_keeps_the_actionable_detail():
    """Knowing WHICH purl type was unsupported is the whole point -- the
    reason must not be collapsed into a placeholder."""
    sbom = sb.Sbom()
    sbom.components = [
        sb._component_from("a", "1", "pkg:docker/library/a@1"),
        sb._component_from("b", "1", "pkg:generic/b@1"),
    ]
    reasons = " ".join(sbom.skip_summary())
    assert "docker" in reasons
    assert "generic" in reasons
    assert "'...'" not in reasons


def test_inventory_report_warns_about_unchecked_components():
    sbom = sb.parse_spdx_json(SPDX_JSON)
    text = sb.inventory_report(sbom)
    assert "NOT CHECKED" in text
    assert "not as clean" in text
    assert "PyPI" in text and "Debian:11" in text


def test_inventory_report_can_suppress_the_skip_block():
    """The scan report repeats the warning, so the inventory header can omit
    it -- but the counts must still be shown."""
    sbom = sb.parse_spdx_json(SPDX_JSON)
    text = sb.inventory_report(sbom, show_skips=False)
    assert "NOT CHECKED" not in text
    assert "not checkable : 1" in text


def test_inventory_report_has_no_warning_when_all_checkable():
    data = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [
        {"name": "jinja2", "version": "2.4.1", "purl": "pkg:pypi/jinja2@2.4.1"},
    ]}
    text = sb.inventory_report(sb.parse_cyclonedx(data))
    assert "NOT CHECKED" not in text


def test_component_label_is_readable():
    comp = sb._component_from("jinja2", "2.4.1", "pkg:pypi/jinja2@2.4.1")
    assert "jinja2@2.4.1" in comp.label
    assert "pkg:pypi" in comp.label
