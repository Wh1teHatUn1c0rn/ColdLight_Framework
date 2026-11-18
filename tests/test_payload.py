import coldlight_awareness as pay
from coldlight_config import CampaignConfig


def test_collect_context_fields():
    rec = pay.collect_context(CampaignConfig(engagement_id="E"))
    for k in ("engagement_id", "run_id", "timestamp_utc", "hostname", "username", "os", "ran_from"):
        assert k in rec
    assert rec["engagement_id"] == "E"


def test_write_local_log(tmp_path, monkeypatch):
    monkeypatch.setattr(pay, "run_dir", lambda: tmp_path)
    monkeypatch.setenv("TEMP", str(tmp_path))
    paths = pay.write_local_log({"run_id": "x"})
    assert paths
    assert (tmp_path / pay.LOG_FILENAME).is_file()


def test_beacon_no_url_is_noop():
    assert pay.beacon({"a": 1}, "", "") is False


def test_awareness_text_default_includes_config():
    cfg = CampaignConfig(sponsor="SP", authorization_reference="AR", engagement_id="EG")
    text = pay.awareness_text(cfg)
    assert "SP" in text and "AR" in text and "EG" in text


def test_awareness_text_override_formats():
    cfg = CampaignConfig(message_text="Hi {sponsor} / {engagement_id}")
    assert pay.awareness_text(cfg) == "Hi the security team / CHANGE-ME-ENGAGEMENT-ID"
