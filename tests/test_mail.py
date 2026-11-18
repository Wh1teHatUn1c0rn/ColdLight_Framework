"""Tests for coldlight_mail. DNS is stubbed, so these run offline."""

import base64

import pytest

import coldlight_mail as rm


def make_query(zone, *, dnssec=False):
    """A fake resolver over a dict of {(name, rtype): [records]}."""
    def query(name, rtype="TXT"):
        records = zone.get((name.lower(), rtype.upper()), [])
        return rm.DnsAnswer(
            status=0 if records else 3,
            authenticated=dnssec,
            records=list(records),
        )
    return query


def zone_for(domain="example.com", *, spf=None, dmarc=None, mx=("10 mail.example.com.",),
             dkim=None, mta_sts=None, tls_rpt=None, extra=None):
    zone = {}
    if spf is not None:
        zone[(domain, "TXT")] = spf if isinstance(spf, list) else [spf]
    if mx:
        zone[(domain, "MX")] = list(mx)
    if dmarc is not None:
        zone[(f"_dmarc.{domain}", "TXT")] = (
            dmarc if isinstance(dmarc, list) else [dmarc])
    for selector, record in (dkim or {}).items():
        zone[(f"{selector}._domainkey.{domain}", "TXT")] = [record]
    if mta_sts:
        zone[(f"_mta-sts.{domain}", "TXT")] = [mta_sts]
    if tls_rpt:
        zone[(f"_smtp._tls.{domain}", "TXT")] = [tls_rpt]
    zone.update(extra or {})
    return zone


def audit(zone, *, domain="example.com", dnssec=False, selectors=("google",)):
    return rm.audit_domain(domain, query=make_query(zone, dnssec=dnssec),
                           fetch_policy=False, selectors=selectors, workers=2)


def titles(findings):
    return [f.title for f in findings]


# ---------------------------------------------------------------------------
# TXT chunk joining -- silently corrupting a DKIM key would be invisible
# ---------------------------------------------------------------------------

def test_unquote_single_string():
    assert rm.unquote_txt('"v=spf1 -all"') == "v=spf1 -all"


def test_unquote_joins_chunks_with_no_separator():
    # TXT strings cap at 255 bytes, so long records arrive split.
    raw = '"v=DKIM1; k=rsa; p=AAAA" "BBBB" "CCCC"'
    assert rm.unquote_txt(raw) == "v=DKIM1; k=rsa; p=AAAABBBBCCCC"


def test_unquote_handles_unquoted_and_empty():
    assert rm.unquote_txt("v=spf1 -all") == "v=spf1 -all"
    assert rm.unquote_txt("") == ""


def test_unquote_preserves_escaped_quotes():
    assert rm.unquote_txt(r'"say \"hi\""') == 'say "hi"'


# ---------------------------------------------------------------------------
# SPF parsing
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("record,qualifier", [
    ("v=spf1 include:_spf.google.com -all", "-"),
    ("v=spf1 include:_spf.google.com ~all", "~"),
    ("v=spf1 ?all", "?"),
    ("v=spf1 +all", "+"),
    ("v=spf1 ip4:192.0.2.0/24", ""),
])
def test_spf_all_qualifier(record, qualifier):
    assert rm.parse_spf(record)[0] == qualifier


def test_spf_collects_includes():
    _q, includes, _ptr, _m = rm.parse_spf(
        "v=spf1 include:a.com include:b.com ip4:192.0.2.1 -all")
    assert includes == ["a.com", "b.com"]


def test_spf_counts_only_dns_querying_mechanisms():
    # ip4/ip6/all are free; include/a/mx/exists/redirect each cost a lookup.
    _q, _i, _p, mechanisms = rm.parse_spf(
        "v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 a mx include:x.com "
        "exists:%{i}.y.com -all")
    assert len(mechanisms) == 4


def test_spf_detects_ptr():
    assert rm.parse_spf("v=spf1 ptr -all")[2] is True
    assert rm.parse_spf("v=spf1 ptr:example.com -all")[2] is True
    assert rm.parse_spf("v=spf1 -all")[2] is False


def test_spf_all_meaning_is_explained():
    for qualifier in ("-", "~", "?", "+", ""):
        result = rm.SpfResult(all_qualifier=qualifier)
        assert result.all_meaning and "unknown" not in result.all_meaning


# ---------------------------------------------------------------------------
# The 10-lookup limit -- a record can look fine and still not evaluate
# ---------------------------------------------------------------------------

def test_lookup_count_follows_includes_recursively():
    zone = {
        ("example.com", "TXT"): ["v=spf1 include:a.com include:b.com -all"],
        ("a.com", "TXT"): ["v=spf1 include:deep.com mx -all"],
        ("b.com", "TXT"): ["v=spf1 a -all"],
        ("deep.com", "TXT"): ["v=spf1 ip4:192.0.2.0/24 -all"],
    }
    count, truncated, _errors = rm.count_spf_lookups(
        "example.com", make_query(zone))
    # 2 includes + (1 include + 1 mx) + 1 a + 0 = 5
    assert count == 5
    assert truncated is False


def test_lookup_count_survives_include_loops():
    zone = {
        ("example.com", "TXT"): ["v=spf1 include:loop.com -all"],
        ("loop.com", "TXT"): ["v=spf1 include:example.com -all"],
    }
    count, _truncated, _errors = rm.count_spf_lookups(
        "example.com", make_query(zone))
    assert count == 2          # each visited once, no infinite recursion


def test_over_limit_is_reported_as_high():
    includes = " ".join(f"include:s{i}.com" for i in range(12))
    zone = {("example.com", "TXT"): [f"v=spf1 {includes} -all"]}
    for i in range(12):
        zone[(f"s{i}.com", "TXT")] = ["v=spf1 ip4:192.0.2.0/24 -all"]

    result = rm.check_spf("example.com", make_query(zone))
    assert result.lookups == 12

    found = rm.audit_domain("example.com", query=make_query(zone),
                            fetch_policy=False, selectors=()).findings
    over = next(f for f in found if "lookup limit" in f.title)
    assert over.severity == "HIGH"
    assert "permerror" in over.detail
    assert "OPEN" in over.detail      # the dangerous part: it fails open


def test_close_to_limit_warns():
    includes = " ".join(f"include:s{i}.com" for i in range(9))
    zone = {("example.com", "TXT"): [f"v=spf1 {includes} -all"]}
    for i in range(9):
        zone[(f"s{i}.com", "TXT")] = ["v=spf1 ip4:192.0.2.0/24 -all"]

    found = rm.audit_domain("example.com", query=make_query(zone),
                            fetch_policy=False, selectors=()).findings
    assert any("close to the DNS lookup limit" in t for t in titles(found))


def test_multiple_spf_records_is_a_permerror():
    zone = zone_for(spf=["v=spf1 include:a.com -all", "v=spf1 include:b.com ~all"])
    result = rm.check_spf("example.com", make_query(zone))
    assert result.multiple_records is True
    assert any("exactly one" in e for e in result.errors)


# ---------------------------------------------------------------------------
# DMARC parsing
# ---------------------------------------------------------------------------

def test_dmarc_full_parse():
    zone = zone_for(dmarc="v=DMARC1; p=reject; sp=quarantine; pct=50; "
                          "rua=mailto:a@x.com,mailto:b@x.com; "
                          "ruf=mailto:f@x.com; adkim=s; aspf=s")
    result = rm.check_dmarc("example.com", make_query(zone))
    assert result.present and result.policy == "reject"
    assert result.subdomain_policy == "quarantine"
    assert result.percent == 50
    assert result.rua == ["mailto:a@x.com", "mailto:b@x.com"]
    assert result.ruf == ["mailto:f@x.com"]
    assert result.adkim == "s" and result.aspf == "s"


def test_dmarc_defaults():
    zone = zone_for(dmarc="v=DMARC1; p=none")
    result = rm.check_dmarc("example.com", make_query(zone))
    assert result.percent == 100
    assert result.adkim == "r" and result.aspf == "r"
    assert result.subdomain_policy == ""
    assert result.effective_subdomain_policy == "none"


def test_dmarc_subdomain_policy_falls_back_to_p():
    zone = zone_for(dmarc="v=DMARC1; p=reject")
    assert rm.check_dmarc("example.com",
                          make_query(zone)).effective_subdomain_policy == "reject"


def test_dmarc_absent():
    result = rm.check_dmarc("example.com", make_query({}))
    assert result.present is False
    assert result.enforcing is False


def test_dmarc_bad_pct_is_reported():
    zone = zone_for(dmarc="v=DMARC1; p=reject; pct=abc")
    result = rm.check_dmarc("example.com", make_query(zone))
    assert result.percent == 100
    assert any("not a number" in e for e in result.errors)


def test_dmarc_invalid_policy_is_reported():
    zone = zone_for(dmarc="v=DMARC1; p=maybe")
    result = rm.check_dmarc("example.com", make_query(zone))
    assert any("not valid" in e for e in result.errors)


def test_multiple_dmarc_records_means_no_dmarc():
    zone = zone_for(dmarc=["v=DMARC1; p=reject", "v=DMARC1; p=none"])
    result = rm.check_dmarc("example.com", make_query(zone))
    assert result.multiple_records is True
    assert any("ignore all of them" in e for e in result.errors)


# ---------------------------------------------------------------------------
# Spoofability -- decided by DMARC, never by SPF
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("dmarc,spoofable", [
    (None, True),                                   # no DMARC at all
    ("v=DMARC1; p=none", True),                     # monitor only
    ("v=DMARC1; p=quarantine", True),               # accepted, filed to spam
    ("v=DMARC1; p=reject; pct=50", True),           # enforced on half of mail
    ("v=DMARC1; p=reject", False),                  # refused outright
])
def test_spoofability_is_decided_by_dmarc(dmarc, spoofable):
    result = audit(zone_for(spf="v=spf1 -all", dmarc=dmarc))
    assert result.spoofable is spoofable


@pytest.mark.parametrize("dmarc,level", [
    (None, "none"),
    ("v=DMARC1; p=none", "none"),
    ("v=DMARC1; p=quarantine", "partial"),
    ("v=DMARC1; p=reject; pct=50", "partial"),
    ("v=DMARC1; p=reject", "full"),
    ("v=DMARC1; p=reject; pct=100", "full"),
])
def test_protection_level_keeps_the_three_way_nuance(dmarc, level):
    """A bool alone would flatten quarantine and 'no DMARC' together."""
    result = audit(zone_for(spf="v=spf1 -all", dmarc=dmarc))
    assert result.protection_level == level


def test_quarantine_report_says_accepted_not_delivered_to_inbox():
    result = audit(zone_for(spf="v=spf1 -all", dmarc="v=DMARC1; p=quarantine"))
    report = rm.text_report(result)
    assert "ACCEPTED, not refused" in report
    assert "would reach recipients' inboxes" not in report


def test_no_dmarc_report_says_reaches_the_inbox():
    report = rm.text_report(audit(zone_for(spf="v=spf1 -all", dmarc=None)))
    assert "would reach recipients' inboxes" in report


def test_perfect_spf_does_not_make_a_domain_safe():
    """The misconception this module exists to correct: a flawless hard-fail
    SPF record leaves the visible From: header wide open."""
    result = audit(zone_for(spf="v=spf1 ip4:192.0.2.1 -all", dmarc=None))
    assert result.spf.present
    assert result.spf.all_qualifier == "-"
    assert result.spoofable is True

    report = rm.text_report(result)
    assert "SPF cannot prevent this" in report
    assert "envelope sender" in report


def test_subdomains_spoofable_when_sp_is_none():
    result = audit(zone_for(spf="v=spf1 -all", dmarc="v=DMARC1; p=reject; sp=none"))
    assert result.spoofable is False          # the apex is protected
    assert result.subdomains_spoofable is True
    assert any("Subdomains are not covered" in t for t in titles(result.findings))


def test_sp_reject_covers_subdomains():
    result = audit(zone_for(spf="v=spf1 -all",
                            dmarc="v=DMARC1; p=reject; sp=reject; rua=mailto:a@x.com"))
    assert result.subdomains_spoofable is False
    assert not any("Subdomains" in t for t in titles(result.findings))


@pytest.mark.parametrize("dmarc,expected", [
    (None, "SPOOFABLE"),
    ("v=DMARC1; p=none", "SPOOFABLE"),
    ("v=DMARC1; p=quarantine", "PARTIALLY PROTECTED"),
    ("v=DMARC1; p=reject; pct=10", "PARTIALLY PROTECTED"),
    ("v=DMARC1; p=reject", "PROTECTED"),
])
def test_verdict_wording(dmarc, expected):
    result = audit(zone_for(spf="v=spf1 -all", dmarc=dmarc))
    assert result.verdict.startswith(expected)


# ---------------------------------------------------------------------------
# DKIM
# ---------------------------------------------------------------------------

def _der(tag: int, value: bytes) -> bytes:
    if len(value) < 0x80:
        return bytes([tag, len(value)]) + value
    length = len(value).to_bytes((len(value).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(length)]) + length + value


def make_rsa_spki(bits: int) -> bytes:
    """A syntactically real RSA SubjectPublicKeyInfo of the given size."""
    modulus = bytes([0xFF]) + b"\xAB" * (bits // 8 - 1)   # high bit set
    rsa_key = _der(0x30, _der(0x02, b"\x00" + modulus)
                   + _der(0x02, b"\x01\x00\x01"))
    algorithm = _der(0x30, bytes.fromhex("06092a864886f70d010101")
                     + bytes.fromhex("0500"))
    return _der(0x30, algorithm + _der(0x03, b"\x00" + rsa_key))


@pytest.mark.parametrize("bits", [1024, 2048, 4096])
def test_rsa_key_bits_walks_the_der(bits):
    assert rm.rsa_key_bits(make_rsa_spki(bits)) == bits


def test_rsa_key_bits_rejects_garbage():
    assert rm.rsa_key_bits(b"not der at all") is None
    assert rm.rsa_key_bits(b"") is None
    assert rm.rsa_key_bits(b"\x30\x82\xff\xff") is None     # truncated


def test_dkim_parses_key_and_size():
    key_material = base64.b64encode(make_rsa_spki(2048)).decode()
    key = rm.parse_dkim("sel", f"v=DKIM1; k=rsa; p={key_material}")
    assert key.key_type == "rsa"
    assert key.bits == 2048
    assert not key.revoked and not key.testing


def test_dkim_detects_weak_key():
    key_material = base64.b64encode(make_rsa_spki(1024)).decode()
    zone = zone_for(spf="v=spf1 -all", dmarc="v=DMARC1; p=reject; rua=mailto:a@x.com",
                    dkim={"google": f"v=DKIM1; k=rsa; p={key_material}"})
    result = audit(zone)
    weak = next(f for f in result.findings if "1024-bit" in f.title)
    assert weak.severity == "MEDIUM"


def test_dkim_detects_revoked_key():
    key = rm.parse_dkim("sel", "v=DKIM1; k=rsa; p=")
    assert key.revoked is True
    assert key.bits is None


def test_revoked_selector_is_informational_not_a_vulnerability():
    """An empty p= is the RFC 6376 way to retire a selector, so normal key
    rotation must not be reported as a finding against the domain."""
    zone = zone_for(spf="v=spf1 -all",
                    dmarc="v=DMARC1; p=reject; sp=reject; rua=mailto:a@x.com",
                    dkim={"old": "v=DKIM1; k=rsa; p="})
    result = rm.audit_domain("example.com", query=make_query(zone),
                             fetch_policy=False, selectors=("old",))
    finding = next(f for f in result.findings if "revoked" in f.title)
    assert finding.severity == "INFO"
    assert "normal after key" in finding.detail


def test_dkim_detects_test_mode():
    key_material = base64.b64encode(make_rsa_spki(2048)).decode()
    key = rm.parse_dkim("sel", f"v=DKIM1; k=rsa; t=y; p={key_material}")
    assert key.testing is True


def test_dkim_ed25519_key_size():
    key_material = base64.b64encode(b"\x01" * 32).decode()
    key = rm.parse_dkim("sel", f"v=DKIM1; k=ed25519; p={key_material}")
    assert key.key_type == "ed25519"
    assert key.bits == 256


def test_dkim_negative_result_is_explicitly_inconclusive():
    """Selectors are arbitrary, so finding none proves nothing. Reporting it
    as 'DKIM missing' would be a false finding."""
    result = audit(zone_for(spf="v=spf1 -all", dmarc="v=DMARC1; p=reject"))
    assert result.dkim.found is False
    assert result.dkim.conclusive is False

    finding = next(f for f in result.findings if f.check == "DKIM")
    assert finding.severity == "INFO"          # not a vulnerability
    assert "NOT evidence" in finding.detail
    assert "inconclusive" in finding.detail

    assert "inconclusive" in rm.text_report(result)


def wildcard_query(record, *, mx=("10 mail.example.com.",)):
    """A zone where *._domainkey answers for ANY selector name."""
    def query(name, rtype="TXT"):
        lowered = name.lower()
        if rtype.upper() == "MX" and lowered == "example.com":
            return rm.DnsAnswer(status=0, records=list(mx))
        if "._domainkey." in lowered and rtype.upper() == "TXT":
            return rm.DnsAnswer(status=0, records=[record])
        return rm.DnsAnswer(status=3, records=[])
    return query


def test_wildcard_domainkey_is_detected_by_a_control_probe():
    """Without a control probe every selector appears to exist, producing
    dozens of bogus 'found' entries instead of one real observation."""
    result = rm.check_dkim("example.com",
                           wildcard_query("v=DKIM1; k=rsa; p="),
                           selectors=("google", "s1", "s2", "dkim"), workers=2)
    assert result.wildcard is True
    assert len(result.keys) == 1              # collapsed, not one per selector
    assert result.keys[0].selector == "*"
    assert result.keys[0].revoked is True


def test_wildcard_revocation_is_informational():
    result = rm.audit_domain("example.com",
                             query=wildcard_query("v=DKIM1; k=rsa; p="),
                             fetch_policy=False, selectors=("google",))
    finding = next(f for f in result.findings if f.check == "DKIM")
    assert finding.severity == "INFO"
    assert "revocation" in finding.title.lower()

    report = rm.text_report(result)
    assert "WILDCARD" in report
    assert "per-selector probing is meaningless" in report


def test_wildcard_with_a_live_key_is_a_real_finding():
    key_material = base64.b64encode(make_rsa_spki(2048)).decode()
    result = rm.audit_domain(
        "example.com",
        query=wildcard_query(f"v=DKIM1; k=rsa; p={key_material}"),
        fetch_policy=False, selectors=("google",))
    finding = next(f for f in result.findings if f.check == "DKIM")
    assert finding.severity == "MEDIUM"
    assert "any selector" in finding.detail.lower()


def test_no_wildcard_on_a_normal_zone():
    key_material = base64.b64encode(make_rsa_spki(2048)).decode()
    zone = zone_for(dkim={"google": f"v=DKIM1; k=rsa; p={key_material}"})
    result = rm.check_dkim("example.com", make_query(zone),
                           selectors=("google",), workers=2)
    assert result.wildcard is False
    assert [k.selector for k in result.keys] == ["google"]


def test_dkim_probes_multiple_selectors():
    key_material = base64.b64encode(make_rsa_spki(2048)).decode()
    record = f"v=DKIM1; k=rsa; p={key_material}"
    zone = zone_for(dkim={"selector1": record, "selector2": record})
    result = rm.check_dkim("example.com", make_query(zone),
                           selectors=("selector1", "selector2", "nope"),
                           workers=3)
    assert [k.selector for k in result.keys] == ["selector1", "selector2"]
    assert result.selectors_probed == 3


# ---------------------------------------------------------------------------
# MTA-STS / TLS-RPT / DNSSEC / MX
# ---------------------------------------------------------------------------

def test_mta_sts_dns_only():
    zone = zone_for(mta_sts="v=STSv1; id=20260101000000")
    result = rm.check_mta_sts("example.com", make_query(zone), fetch=False)
    assert result.dns_present is True
    assert result.policy_id == "20260101000000"
    assert result.policy_fetched is False


def test_mta_sts_absent():
    result = rm.check_mta_sts("example.com", make_query({}), fetch=False)
    assert result.dns_present is False


def test_no_fetch_does_not_manufacture_an_mta_sts_finding():
    """With --no-fetch we never looked at the policy, so claiming it is
    unusable would be a false finding created by our own flag."""
    zone = zone_for(spf="v=spf1 -all", dmarc="v=DMARC1; p=reject; rua=mailto:a@x.com",
                    mta_sts="v=STSv1; id=1")
    result = audit(zone)                      # fetch_policy=False
    assert result.mta_sts.dns_present is True
    assert result.mta_sts.fetch_attempted is False
    assert not any(f.check == "MTA-STS" for f in result.findings)

    report = rm.text_report(result)
    assert "policy not fetched" in report
    assert "FAILED" not in report


def test_failed_policy_fetch_is_a_finding():
    zone = zone_for(spf="v=spf1 -all", dmarc="v=DMARC1; p=reject; rua=mailto:a@x.com",
                    mta_sts="v=STSv1; id=1")
    result = rm.audit_domain("example.com", query=make_query(zone),
                             fetch_policy=False, selectors=())
    # Simulate "we looked and it failed", then re-evaluate.
    result.mta_sts.fetch_attempted = True
    result.mta_sts.fetch_error = "connection refused"
    result.findings = rm._evaluate(result)

    finding = next(f for f in result.findings if f.check == "MTA-STS")
    assert "without a usable policy" in finding.title
    assert finding.severity == "MEDIUM"
    assert "connection refused" in finding.detail
    assert "policy fetch FAILED" in rm.text_report(result)


def test_tls_rpt_detected():
    zone = zone_for(tls_rpt="v=TLSRPTv1; rua=mailto:t@x.com")
    assert rm.check_tls_rpt("example.com", make_query(zone)).startswith("v=TLSRPTv1")
    assert rm.check_tls_rpt("example.com", make_query({})) == ""


def test_dnssec_flag_is_read_from_the_resolver():
    zone = zone_for(spf="v=spf1 -all", dmarc="v=DMARC1; p=reject")
    assert audit(zone, dnssec=True).dnssec is True
    assert audit(zone, dnssec=False).dnssec is False
    assert any("DNSSEC" in t for t in titles(audit(zone, dnssec=False).findings))


def test_mx_records_are_collected():
    zone = zone_for(mx=["20 b.example.com.", "10 a.example.com."])
    assert audit(zone).mx == ["10 a.example.com.", "20 b.example.com."]


def test_transport_findings_skipped_when_domain_receives_no_mail():
    zone = zone_for(spf="v=spf1 -all",
                    dmarc="v=DMARC1; p=reject; rua=mailto:a@x.com", mx=())
    checks = {f.check for f in audit(zone).findings}
    assert "MTA-STS" not in checks
    assert "TLS-RPT" not in checks


def test_null_mx_is_recognised_as_correct_practice():
    """RFC 7505 '0 .' declares the domain accepts no mail. Recommending
    inbound TLS controls for it would be a false finding."""
    zone = zone_for(spf="v=spf1 -all",
                    dmarc="v=DMARC1; p=reject; sp=reject; rua=mailto:a@x.com",
                    mx=["0 ."])
    result = audit(zone)

    assert result.null_mx is True
    assert result.receives_mail is False

    checks = {f.check for f in result.findings}
    assert "MTA-STS" not in checks
    assert "TLS-RPT" not in checks

    finding = next(f for f in result.findings if f.check == "MX")
    assert finding.severity == "INFO"
    assert "accepts no mail" in finding.title

    report = rm.text_report(result)
    assert "null MX" in report
    records = "\n".join(rm.recommended_records(result))
    assert "mta-sts" not in records.lower()
    assert "tlsrpt" not in records.lower()


def test_real_mx_means_the_domain_receives_mail():
    zone = zone_for(mx=["10 mail.example.com."])
    result = audit(zone)
    assert result.null_mx is False
    assert result.receives_mail is True


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

def test_plus_all_is_critical():
    result = audit(zone_for(spf="v=spf1 +all", dmarc="v=DMARC1; p=reject"))
    finding = next(f for f in result.findings if "+all" in f.title)
    assert finding.severity == "CRITICAL"
    assert "worse than having" in finding.detail


@pytest.mark.parametrize("spf,severity", [
    ("v=spf1 ?all", "MEDIUM"),
    ("v=spf1 ip4:192.0.2.1", "MEDIUM"),       # no all mechanism
    ("v=spf1 ~all", "LOW"),
])
def test_weak_spf_qualifiers(spf, severity):
    result = audit(zone_for(spf=spf, dmarc="v=DMARC1; p=reject; rua=mailto:a@x.com"))
    spf_findings = [f for f in result.findings
                    if f.check == "SPF" and "all" in f.title]
    assert spf_findings and spf_findings[0].severity == severity


def test_missing_spf_is_high():
    result = audit(zone_for(spf=None, dmarc="v=DMARC1; p=reject"))
    finding = next(f for f in result.findings if f.title == "No SPF record")
    assert finding.severity == "HIGH"


def test_missing_rua_is_a_finding():
    result = audit(zone_for(spf="v=spf1 -all", dmarc="v=DMARC1; p=reject"))
    assert any("aggregate reporting" in t for t in titles(result.findings))


def test_ptr_mechanism_is_low():
    result = audit(zone_for(spf="v=spf1 ptr -all",
                            dmarc="v=DMARC1; p=reject; rua=mailto:a@x.com"))
    finding = next(f for f in result.findings if "ptr" in f.title)
    assert finding.severity == "LOW"


def test_worst_case_domain_is_high_or_critical():
    result = audit(zone_for(spf=None, dmarc=None))
    assert result.spoofable is True
    assert result.worst_severity() in ("HIGH", "CRITICAL")


def test_well_configured_domain_has_no_serious_findings():
    key_material = base64.b64encode(make_rsa_spki(2048)).decode()
    zone = zone_for(
        spf="v=spf1 include:_spf.example.net -all",
        dmarc="v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@example.com",
        dkim={"google": f"v=DKIM1; k=rsa; p={key_material}"},
        mta_sts="v=STSv1; id=1",
        tls_rpt="v=TLSRPTv1; rua=mailto:t@example.com",
        extra={("_spf.example.net", "TXT"): ["v=spf1 ip4:192.0.2.0/24 -all"]},
    )
    result = rm.audit_domain("example.com", query=make_query(zone, dnssec=True),
                             fetch_policy=False, selectors=("google",))
    assert result.spoofable is False
    assert result.subdomains_spoofable is False
    serious = [f for f in result.findings
               if rm.SEVERITY_ORDER[f.severity] >= rm.SEVERITY_ORDER["MEDIUM"]]
    # Only the unfetched MTA-STS policy, which --no-fetch caused.
    assert all(f.check == "MTA-STS" for f in serious)


def test_findings_sorted_by_severity():
    result = audit(zone_for(spf="v=spf1 +all", dmarc=None))
    ranks = [rm.SEVERITY_ORDER[f.severity] for f in result.findings]
    assert ranks == sorted(ranks, reverse=True)


def test_every_finding_carries_remediation():
    result = audit(zone_for(spf=None, dmarc=None))
    for finding in result.findings:
        assert finding.remediation, f"{finding.title} has no remediation"


# ---------------------------------------------------------------------------
# Recommended records
# ---------------------------------------------------------------------------

def test_recommended_records_for_a_bare_domain():
    result = audit(zone_for(spf=None, dmarc=None))
    records = "\n".join(rm.recommended_records(result))
    assert "v=spf1" in records
    assert "_dmarc.example.com" in records
    assert "p=none" in records            # staged, not straight to reject


def test_recommendation_for_a_non_sending_domain_is_spf_minus_all():
    result = audit(zone_for(spf=None, dmarc=None, mx=()))
    records = "\n".join(rm.recommended_records(result))
    assert '"v=spf1 -all"' in records
    assert "sends no mail" in records


def test_recommendation_targets_reject_once_dmarc_exists():
    result = audit(zone_for(spf="v=spf1 -all", dmarc="v=DMARC1; p=none"))
    records = "\n".join(rm.recommended_records(result))
    assert "p=reject" in records and "sp=reject" in records


def test_enforcing_domain_without_rua_still_gets_a_record():
    """Every finding must have a matching record, or --records-only would say
    'nothing to add' while the audit reports a gap."""
    result = audit(zone_for(spf="v=spf1 -all",
                            dmarc="v=DMARC1; p=reject; sp=reject"))
    assert any("aggregate reporting" in t for t in titles(result.findings))
    records = "\n".join(rm.recommended_records(result))
    assert "rua=mailto:dmarc@example.com" in records


def test_records_and_findings_do_not_disagree():
    zones = [
        zone_for(spf=None, dmarc=None),
        zone_for(spf="v=spf1 ~all", dmarc="v=DMARC1; p=none"),
        zone_for(spf="v=spf1 -all", dmarc="v=DMARC1; p=reject; sp=reject"),
        zone_for(spf="v=spf1 -all", dmarc="v=DMARC1; p=reject; sp=reject",
                 mx=["0 ."]),
    ]
    for zone in zones:
        result = audit(zone)
        actionable = [f for f in result.findings if f.severity != "INFO"]
        records = rm.recommended_records(result)
        if actionable:
            assert records, f"{[f.title for f in actionable]} but no records"


def test_no_recommendations_for_a_clean_domain():
    zone = zone_for(
        spf="v=spf1 -all",
        dmarc="v=DMARC1; p=reject; sp=reject; rua=mailto:d@example.com",
        mta_sts="v=STSv1; id=1",
        tls_rpt="v=TLSRPTv1; rua=mailto:t@example.com",
    )
    assert rm.recommended_records(audit(zone)) == []


# ---------------------------------------------------------------------------
# Input handling, gating, reporting
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("given", [
    "example.com", "EXAMPLE.COM", "example.com.",
    "https://example.com/path", "user@example.com",
])
def test_domain_normalisation(given):
    zone = zone_for(spf="v=spf1 -all", dmarc="v=DMARC1; p=reject")
    result = rm.audit_domain(given, query=make_query(zone), fetch_policy=False,
                             selectors=())
    assert result.domain == "example.com"


@pytest.mark.parametrize("bad", ["", "   ", "localhost", "not-a-domain"])
def test_invalid_domain_raises(bad):
    with pytest.raises(rm.MailAuditError, match="not a domain"):
        rm.audit_domain(bad, query=make_query({}), fetch_policy=False)


def test_unreachable_resolver_raises():
    with pytest.raises(rm.MailAuditError, match="could not reach"):
        rm.doh_query("example.com", "TXT", resolvers=())


def test_meets_threshold():
    findings = [rm.MailFinding("SPF", "MEDIUM", "x")]
    assert rm.meets_threshold(findings, "medium")
    assert not rm.meets_threshold(findings, "high")
    with pytest.raises(ValueError):
        rm.meets_threshold(findings, "bogus")


def test_text_report_contains_the_essentials():
    result = audit(zone_for(spf="v=spf1 include:a.com ~all",
                            dmarc="v=DMARC1; p=none"))
    report = rm.text_report(result, verbose=True)
    assert "example.com" in report
    assert "SPF" in report and "DMARC" in report
    assert "DNS lookups" in report
    assert "SPOOFABLE" in report
    assert "Recommended DNS records" in report


def test_to_dict_is_json_serialisable():
    import json
    result = audit(zone_for(spf="v=spf1 -all", dmarc="v=DMARC1; p=none"))
    payload = result.to_dict()
    assert payload["domain"] == "example.com"
    assert payload["spoofable"] is True
    assert payload["findings"]
    json.dumps(payload)
