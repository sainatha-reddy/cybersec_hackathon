"""Phase 5: web dashboard API, security headers and the standalone HTML report."""

import json
import re

import pytest
from fastapi.testclient import TestClient

from packetdoctor.report.html import render_html
from packetdoctor.web import app as webapp


@pytest.fixture(scope="module")
def client():
    return TestClient(webapp.app)


def test_index_and_static(client):
    r = client.get("/")
    assert r.status_code == 200 and "PacketDoctor" in r.text
    assert client.get("/static/report.js").status_code == 200
    assert client.get("/static/style.css").status_code == 200


def test_security_headers(client):
    r = client.get("/")
    csp = r.headers["content-security-policy"]
    assert "default-src 'self'" in csp and "script-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert "unsafe-inline" not in csp
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert client.post("/api/analyze-sample/clean.pcap").headers["cache-control"] == "no-store"


def test_no_api_docs_exposed(client):
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404


def test_samples_listing(client):
    names = {s["name"] for s in client.get("/api/samples").json()}
    assert "mixed_fault_and_attack.pcap" in names and "clean.pcapng" in names


def test_analyze_sample(client):
    r = client.post("/api/analyze-sample/mixed_fault_and_attack.pcap")
    assert r.status_code == 200
    data = r.json()
    assert data["summary"] == {"incidents": 3, "attacks": 2, "faults": 1, "uncertain": 0}


@pytest.mark.parametrize("name", ["../README.md", "..%2F..%2Fpyproject.toml", "generate.py", "C:\\Windows\\win.ini"])
def test_sample_path_traversal_rejected(client, name):
    r = client.post(f"/api/analyze-sample/{name}")
    assert r.status_code in (404, 405)


def test_upload(client, samples_dir):
    with open(samples_dir / "dns_hijack.pcap", "rb") as fh:
        r = client.post("/api/analyze", files={"file": ("my capture.pcap", fh, "application/octet-stream")})
    assert r.status_code == 200
    data = r.json()
    assert data["capture"]["file_name"] == "my capture.pcap"
    assert data["incidents"][0]["kind"] == "dns_hijack"


def test_upload_anonymized(client, samples_dir):
    with open(samples_dir / "arp_spoofing.pcap", "rb") as fh:
        r = client.post("/api/analyze", files={"file": ("x.pcap", fh)}, data={"anonymize": "true"})
    assert r.status_code == 200
    assert "192.168.1." not in r.text and "de:ad:be:ef" not in r.text


def test_upload_rejects_non_capture(client):
    r = client.post("/api/analyze", files={"file": ("evil.pcap", b"<script>alert(1)</script>" * 10)})
    assert r.status_code == 400
    assert "not a pcap" in r.json()["detail"]
    assert ".cap" not in r.json()["detail"]  # internal temp name never leaks


def test_upload_empty(client):
    r = client.post("/api/analyze", files={"file": ("empty.pcap", b"")})
    assert r.status_code == 400


def test_upload_size_limit(client, monkeypatch, samples_dir):
    monkeypatch.setattr(webapp, "MAX_UPLOAD", 10_000)
    with open(samples_dir / "clean.pcap", "rb") as fh:
        r = client.post("/api/analyze", files={"file": ("big.pcap", fh)})
    assert r.status_code == 413


def test_upload_filename_is_sanitised(client, samples_dir):
    with open(samples_dir / "clean.pcap", "rb") as fh:
        r = client.post("/api/analyze", files={"file": ("../../etc/<img src=x onerror=alert(1)>.pcap", fh)})
    assert r.status_code == 200
    name = r.json()["capture"]["file_name"]
    assert "<" not in name and "/" not in name


def test_temp_files_are_deleted(client, samples_dir, tmp_path, monkeypatch):
    import tempfile

    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    with open(samples_dir / "clean.pcap", "rb") as fh:
        assert client.post("/api/analyze", files={"file": ("c.pcap", fh)}).status_code == 200
    assert list(tmp_path.iterdir()) == []


# --- standalone HTML report ----------------------------------------------------


def test_html_report_is_self_contained(client):
    report = client.post("/api/analyze-sample/mixed_fault_and_attack.pcap").json()
    page = render_html(report)
    assert page.startswith("<!doctype html>")
    assert "default-src 'none'" in page
    assert not re.search(r"(src|href)=\"https?://", page)  # nothing loaded from the network
    blob = re.search(r'<script type="application/json" id="report-data">(.*?)</script>', page, re.S).group(1)
    assert json.loads(blob)["summary"]["attacks"] == 2


def test_html_report_cannot_be_broken_by_hostile_capture_strings(client):
    report = client.post("/api/analyze-sample/clean.pcap").json()
    evil = "</script><script>alert('pwned')</script><!--"
    report["capture"]["file_name"] = evil
    report["health"]["summary"] = evil
    page = render_html(report)
    assert "<script>alert('pwned')" not in page
    assert page.count("</script>") == 2  # only our own two script blocks close
    blob = re.search(r'<script type="application/json" id="report-data">(.*?)</script>', page, re.S).group(1)
    assert json.loads(blob)["health"]["summary"] == evil  # data preserved exactly, just inert


def test_renderer_never_uses_innerhtml():
    from pathlib import Path

    static = Path(webapp.__file__).parent / "static"
    for js in static.glob("*.js"):
        code = js.read_text(encoding="utf-8")
        assert not re.search(r"\.(inner|outer)HTML|insertAdjacentHTML|document\.write|\beval\(|new Function", code), js.name


def test_cli_html_output(samples_dir, tmp_path):
    from typer.testing import CliRunner

    from packetdoctor.cli import app

    out = tmp_path / "report.html"
    res = CliRunner().invoke(app, ["analyze", str(samples_dir / "rogue_dhcp.pcap"), "-q", "--html", str(out)])
    assert res.exit_code == 0, res.output
    assert "Rogue DHCP" in out.read_text(encoding="utf-8")


def test_hosted_mode_headers_and_health(monkeypatch):
    monkeypatch.setenv("PACKETDOCTOR_HOSTED", "1")
    import importlib
    hosted = importlib.reload(webapp)
    try:
        client = TestClient(hosted.app)
        r = client.get("/")
        assert "frame-ancestors https://huggingface.co" in r.headers["content-security-policy"]
        assert "x-frame-options" not in r.headers
        assert client.get("/api/health").json()["hosted"] is True
    finally:
        monkeypatch.delenv("PACKETDOCTOR_HOSTED")
        importlib.reload(webapp)
