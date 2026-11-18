import coldlight_safelist as sl


def test_bare_pattern_matches_host_or_user():
    assert sl.matches(["jdoe"], hostname="x", username="JDOE")
    assert sl.matches(["ws-ceo"], hostname="WS-CEO", username="y")
    assert not sl.matches(["jdoe"], hostname="x", username="y")


def test_scoped_patterns():
    assert sl.matches(["host:WS-CEO-*"], hostname="ws-ceo-01", username="anyone")
    assert not sl.matches(["host:WS-CEO-*"], hostname="ws-dev-01", username="ws-ceo-01")
    assert sl.matches(["user:svc-*"], hostname="h", username="SVC-BACKUP")
    assert not sl.matches(["user:svc-*"], hostname="svc-x", username="alice")


def test_empty_and_none():
    assert not sl.matches([], hostname="h", username="u")
    assert not sl.matches(None, hostname="h", username="u")


def test_load_patterns_skips_comments(tmp_path):
    p = tmp_path / "safe.txt"
    p.write_text("# comment\nhost:WS-CEO-*\n\nuser:svc-*\n", encoding="utf-8")
    assert sl.load_patterns(p) == ["host:WS-CEO-*", "user:svc-*"]
