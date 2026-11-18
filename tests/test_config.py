import json
import sys

import coldlight_config as rc
from coldlight_config import CampaignConfig


def test_from_dict_ignores_unknown_and_fills_defaults():
    cfg = CampaignConfig.from_dict({"sponsor": "X", "bogus": 1})
    assert cfg.sponsor == "X"
    assert cfg.engagement_id == CampaignConfig().engagement_id


def test_load_config_toml(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text(
        '[campaign]\n'
        'engagement_id="E1"\n'
        'authorization_reference="A1"\n'
        'sponsor="S"\n'
        '[payload]\n'
        'lure_filename="x.exe"\n'
        'show_gui=false\n'
        '[collector]\n'
        'url="https://h/x"\n'
        'token="t"\n'
        '[message]\n'
        'text="hi {sponsor}"\n',
        encoding="utf-8",
    )
    cfg = rc.load_config(p)
    assert cfg.engagement_id == "E1"
    assert cfg.show_gui is False
    assert cfg.collector_url == "https://h/x"
    assert cfg.collector_token == "t"
    assert cfg.message_text == "hi {sponsor}"


def test_validate_blocks_placeholders():
    errors, _ = rc.validate(CampaignConfig())
    assert any("engagement_id" in e for e in errors)
    assert any("authorization_reference" in e for e in errors)


def test_validate_ok_with_warnings():
    cfg = CampaignConfig(engagement_id="E", authorization_reference="A", sponsor="S",
                         lure_filename="a.exe", collector_url="http://h", collector_token="")
    errors, warnings = rc.validate(cfg)
    assert errors == []
    assert any("http://" in w for w in warnings)
    assert any("token" in w for w in warnings)


def test_validate_bad_collector_url():
    cfg = CampaignConfig(engagement_id="E", authorization_reference="A", collector_url="ftp://h")
    errors, _ = rc.validate(cfg)
    assert any("collector_url" in e for e in errors)


def test_runtime_config_external_wins(tmp_path, monkeypatch):
    monkeypatch.setattr(rc, "run_dir", lambda: tmp_path)
    (tmp_path / rc.EXTERNAL_CONFIG_NAME).write_text(
        json.dumps({"sponsor": "EXT", "engagement_id": "E", "authorization_reference": "A"}),
        encoding="utf-8",
    )
    cfg, source = rc.load_runtime_config()
    assert cfg.sponsor == "EXT"
    assert source.startswith("external")


def test_runtime_config_defaults(tmp_path, monkeypatch):
    monkeypatch.setattr(rc, "run_dir", lambda: tmp_path)  # empty dir, no campaign.json
    monkeypatch.delattr(sys, "_MEIPASS", raising=False)
    cfg, source = rc.load_runtime_config()
    assert source == "defaults"
    assert cfg.engagement_id == CampaignConfig().engagement_id
