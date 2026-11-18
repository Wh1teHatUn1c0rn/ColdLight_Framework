import json

import coldlight_report as rr


def _conn():
    return rr.connect(":memory:")


def _hit(run_id="r1", host="h", day="01"):
    return {"run_id": run_id, "engagement_id": "E",
            "timestamp_utc": f"2026-01-{day}T00:00:00+00:00",
            "hostname": host, "username": "u", "os": "w", "ran_from": "E:"}


def test_insert_dedup():
    c = _conn()
    assert rr.insert_hit(c, _hit()) is True
    assert rr.insert_hit(c, _hit()) is False
    assert rr.compute_stats(c)["total_runs"] == 1


def test_insert_requires_run_id():
    c = _conn()
    assert rr.insert_hit(c, {"engagement_id": "E"}) is False


def test_ingest_jsonl(tmp_path):
    c = _conn()
    recs = [_hit(f"r{i}", f"h{i}", f"0{i + 1}") for i in range(3)]
    recs.append(recs[0])  # duplicate
    p = tmp_path / "log.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in recs) + "\nGARBAGE\n", encoding="utf-8")
    new, seen = rr.ingest_jsonl(c, p)
    assert new == 3
    assert seen == 4  # 4 valid json lines (incl. dup); GARBAGE ignored
    stats = rr.compute_stats(c)
    assert stats["total_runs"] == 3
    assert stats["unique_hosts"] == 3


def test_compute_stats_per_engagement():
    c = _conn()
    rr.insert_hit(c, {"run_id": "a", "engagement_id": "E1", "timestamp_utc": "2026-01-01T00:00:00+00:00",
                      "hostname": "h1", "username": "u", "os": "w", "ran_from": "E:"})
    rr.insert_hit(c, {"run_id": "b", "engagement_id": "E2", "timestamp_utc": "2026-01-02T00:00:00+00:00",
                      "hostname": "h2", "username": "u", "os": "w", "ran_from": "F:"})
    stats = rr.compute_stats(c)
    assert set(stats["per_engagement"]) == {"E1", "E2"}
    assert stats["by_day"] == {"2026-01-01": 1, "2026-01-02": 1}


def test_export_csv(tmp_path):
    c = _conn()
    rr.insert_hit(c, _hit())
    out = tmp_path / "o.csv"
    assert rr.export_csv(c, out) == 1
    assert "run_id" in out.read_text(encoding="utf-8")


def test_text_summary_runs():
    assert "Total runs" in rr.text_summary(rr.compute_stats(_conn()))


def test_by_vector_breakdown():
    c = _conn()
    rr.insert_hit(c, _hit("u1", "h1"), vector="usb")
    rr.insert_hit(c, {"run_id": "L1", "engagement_id": "E", "hostname": "", "username": "",
                      "timestamp_utc": "2026-01-01T00:00:00+00:00", "os": "", "ran_from": "flyer"},
                  vector="link")
    stats = rr.compute_stats(c)
    assert stats["by_vector"] == {"usb": 1, "link": 1}


def test_excluded_rows_not_counted():
    c = _conn()
    rr.insert_hit(c, _hit("keep", "h1"), excluded=False)
    rr.insert_hit(c, _hit("drop", "h2"), excluded=True)
    stats = rr.compute_stats(c)
    assert stats["total_runs"] == 1
    assert stats["unique_hosts"] == 1
    assert stats["excluded_runs"] == 1


def test_purge_by_engagement():
    c = _conn()
    rr.insert_hit(c, {"run_id": "a", "engagement_id": "OLD", "timestamp_utc": "2026-01-01T00:00:00+00:00",
                      "received_utc": "2026-01-01T00:00:00+00:00", "hostname": "h", "username": "u",
                      "os": "w", "ran_from": "E:"})
    rr.insert_hit(c, {"run_id": "b", "engagement_id": "NEW", "timestamp_utc": "2026-01-02T00:00:00+00:00",
                      "received_utc": "2026-01-02T00:00:00+00:00", "hostname": "h2", "username": "u",
                      "os": "w", "ran_from": "E:"})
    assert rr.purge(c, engagement="OLD", dry_run=True) == 1
    assert rr.compute_stats(c)["total_runs"] == 2   # dry-run deleted nothing
    assert rr.purge(c, engagement="OLD") == 1
    assert rr.compute_stats(c)["total_runs"] == 1


def test_purge_older_than_days():
    c = _conn()
    rr.insert_hit(c, {"run_id": "old", "engagement_id": "E", "received_utc": "2000-01-01T00:00:00+00:00",
                      "timestamp_utc": "2000-01-01T00:00:00+00:00", "hostname": "h", "username": "u",
                      "os": "w", "ran_from": "E:"})
    rr.insert_hit(c, {"run_id": "recent", "engagement_id": "E", "received_utc": "2099-01-01T00:00:00+00:00",
                      "timestamp_utc": "2099-01-01T00:00:00+00:00", "hostname": "h2", "username": "u",
                      "os": "w", "ran_from": "E:"})
    deleted = rr.purge(c, older_than_days=30)
    assert deleted == 1   # only the year-2000 row is older than 30 days


def test_purge_requires_criterion():
    import pytest
    with pytest.raises(ValueError):
        rr.purge(_conn())
