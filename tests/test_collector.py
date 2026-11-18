import json
import threading
import urllib.error
import urllib.request

import pytest

import coldlight_collector as rc

HIT = {"engagement_id": "E", "run_id": "z1", "timestamp_utc": "2026-01-01T00:00:00+00:00",
       "hostname": "h", "username": "u", "os": "w", "ran_from": "E:"}


@pytest.fixture
def port(tmp_path):
    srv = rc.CollectorServer(("127.0.0.1", 0), token="tok", db_path=str(tmp_path / "h.db"))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield srv.server_address[1]
    finally:
        srv.shutdown()


def _req(port, method, path, token=None, body=None, raw=None):
    url = f"http://127.0.0.1:{port}{path}"
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request(url, data=data, method=method)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        resp = urllib.request.urlopen(req, timeout=5)
        return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def test_requires_auth(port):
    assert _req(port, "POST", "/awareness/hit", None, HIT)[0] == 401
    assert _req(port, "POST", "/awareness/hit", "bad", HIT)[0] == 401


def test_ingest_and_dedup(port):
    assert json.loads(_req(port, "POST", "/awareness/hit", "tok", HIT)[1])["new"] is True
    assert json.loads(_req(port, "POST", "/awareness/hit", "tok", HIT)[1])["new"] is False


def test_oversized_and_bad_json(port):
    assert _req(port, "POST", "/awareness/hit", "tok", raw=b"x" * (65 * 1024))[0] == 413
    assert _req(port, "POST", "/awareness/hit", "tok", raw=b"not-json")[0] == 400


def test_stats_gated(port):
    assert _req(port, "GET", "/api/stats")[0] == 401
    _req(port, "POST", "/awareness/hit", "tok", HIT)
    code, payload = _req(port, "GET", "/api/stats", "tok")
    assert code == 200
    assert json.loads(payload)["total_runs"] == 1


def test_dashboard_and_health(port):
    assert _req(port, "GET", "/healthz")[0] == 200
    code, body = _req(port, "GET", "/")
    assert code == 200
    assert "collector token" in body


def _get_with_cookie(port, path, cookie=None):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method="GET")
    if cookie:
        req.add_header("Cookie", cookie)
    resp = urllib.request.urlopen(req, timeout=5)
    set_cookie = resp.headers.get("Set-Cookie")
    return resp.status, resp.read().decode(), set_cookie


def test_landing_tracks_click_and_dedups(port):
    # first visit: 200, training page, a visitor cookie is set
    code, body, set_cookie = _get_with_cookie(port, "/land?c=LINK-TEST&t=flyer")
    assert code == 200
    assert "awareness test" in body.lower()
    assert "<input" not in body.lower()          # benign: no form, no credential capture
    assert set_cookie and "rv=" in set_cookie

    rv = set_cookie.split("rv=", 1)[1].split(";", 1)[0]
    # same visitor revisits -> deduped
    _get_with_cookie(port, "/land?c=LINK-TEST", cookie=f"rv={rv}")
    # a different visitor (no cookie) -> counts separately
    _get_with_cookie(port, "/land?c=LINK-TEST")

    stats = json.loads(_req(port, "GET", "/api/stats", "tok")[1])
    assert stats["by_vector"].get("link") == 2
    assert stats["total_runs"] == 2


def test_safelist_excludes_from_stats(tmp_path):
    srv = rc.CollectorServer(("127.0.0.1", 0), token="tok",
                             db_path=str(tmp_path / "h.db"),
                             safelist=["host:WS-SECRET-*"])
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        p = srv.server_address[1]
        safe_hit = dict(HIT, run_id="s1", hostname="WS-SECRET-01")
        resp = json.loads(_req(p, "POST", "/awareness/hit", "tok", safe_hit)[1])
        assert resp["excluded"] is True
        _req(p, "POST", "/awareness/hit", "tok", HIT)  # normal host
        stats = json.loads(_req(p, "GET", "/api/stats", "tok")[1])
        assert stats["total_runs"] == 1       # the excluded one is not counted
        assert stats["excluded_runs"] == 1
    finally:
        srv.shutdown()
