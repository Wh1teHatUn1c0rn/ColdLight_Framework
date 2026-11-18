import pytest

import coldlight_qr as q


def test_make_url_no_existing_query():
    assert q.make_url("https://h/land", "E1", "flyer") == "https://h/land?c=E1&t=flyer"


def test_make_url_with_existing_query_uses_amp():
    url = q.make_url("https://h/land?x=1", "E1")
    assert url.startswith("https://h/land?x=1&")
    assert "c=E1" in url


def test_matrix_to_svg_renders_dark_modules():
    matrix = [[True, False], [False, True]]
    svg = q.matrix_to_svg(matrix, scale=10, border=0)
    assert svg.startswith("<svg")
    assert svg.count('fill="#000000"') == 2  # two dark modules
    assert "</svg>" in svg


def test_matrix_to_svg_caption_escaped():
    svg = q.matrix_to_svg([[True]], caption="A&B")
    assert "A&amp;B" in svg


def test_qr_matrix_real():
    qrcode = pytest.importorskip("qrcode")  # noqa: F841
    m = q.qr_matrix("https://h/land?c=E1")
    assert len(m) == len(m[0]) and len(m) >= 21  # square, >= version-1 size
