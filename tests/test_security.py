"""Phase 6: hostile input, resource limits and repository hygiene."""

import json
import random
import re
import subprocess
from pathlib import Path

import pytest
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from packetdoctor.config import Limits, Settings
from packetdoctor.engine import analyze
from packetdoctor.ingest import CaptureError
from packetdoctor.report.html import render_html

ROOT = Path(__file__).resolve().parent.parent


def safe_analyze(path, settings=Settings()):
    """Analysis must either succeed or raise the user-facing CaptureError."""
    try:
        return analyze(path, settings)
    except CaptureError:
        return None


@pytest.mark.parametrize("sample", ["mixed_fault_and_attack", "rogue_dhcp", "dns_hijack", "clean"])
def test_fuzzed_captures_never_crash(samples_dir, tmp_path, sample):
    data = (samples_dir / f"{sample}.pcap").read_bytes()
    rng = random.Random(sample)
    for i in range(15):
        buf = bytearray(data)
        mode = i % 3
        if mode == 0:  # random byte flips everywhere (including record headers)
            for _ in range(rng.randint(5, 200)):
                buf[rng.randrange(24, len(buf))] = rng.randrange(256)
        elif mode == 1:  # random truncation
            buf = buf[: rng.randrange(24, len(buf))]
        else:  # garbage spliced into the middle
            pos = rng.randrange(24, len(buf))
            buf[pos:pos] = rng.randbytes(rng.randint(1, 4000))
        f = tmp_path / f"fuzz{i}.pcap"
        f.write_bytes(bytes(buf))
        report = safe_analyze(f)
        if report is not None:
            json.dumps(report)
            render_html(report)


def test_address_flood_respects_memory_caps(tmp_path):
    rng = random.Random(1)
    pkts = []
    for i in range(3000):  # 3000 spoofed sources, each opening a new flow
        src = f"10.{rng.randrange(256)}.{rng.randrange(256)}.{rng.randrange(1, 255)}"
        p = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src=src, dst="192.168.1.20") / TCP(sport=rng.randrange(1024, 65535), dport=80, flags="S")
        p.time = 1_700_000_000 + i * 0.001
        pkts.append(p)
    f = tmp_path / "flood.pcap"
    wrpcap(str(f), pkts)
    settings = Settings(limits=Limits(max_flows=200, max_hosts=200))
    from packetdoctor.pipeline import detect

    result = detect(f, settings)
    assert len(result.state.flows.flows) <= 200
    assert result.state.flows.flows.evicted >= 2800
    assert len(result.state.hosts.ip_macs) <= 200


def test_zero_packet_capture(samples_dir, tmp_path):
    f = tmp_path / "empty.pcap"
    f.write_bytes((samples_dir / "clean.pcap").read_bytes()[:24])
    report = analyze(f)
    assert report["capture"]["packets"] == 0
    assert report["incidents"] == []
    render_html(report)


def test_timeout_stops_cleanly(samples_dir):
    report = analyze(samples_dir / "clean.pcap", Settings(limits=Limits(timeout_seconds=0)))
    assert report["capture"]["timed_out"] is True
    assert any("time limit" in w for w in report["capture"]["warnings"])


def test_raw_ip_linktype_without_ethernet(tmp_path):
    pkts = []
    for i in range(30):
        p = IP(src="192.168.1.10", dst="192.168.1.1") / UDP(sport=5000 + i, dport=53) / DNS(id=i, qd=DNSQR(qname="example.com"))
        p.time = 1_700_000_000 + i
        pkts.append(p)
    f = tmp_path / "rawip.pcap"
    wrpcap(str(f), pkts, linktype=101)
    report = analyze(f)
    assert report["capture"]["decoded"] == 30
    assert report["capture"]["malformed"] == 0


def test_hostile_strings_are_neutralised(tmp_path):
    evil = b"\x1b]0;pwned\x07\x1b[2J<script>alert(1)</script>.evil.com"
    pkts = []
    for i in range(6):  # forged-looking answers with a hostile name, so it reaches the report
        q = Ether(src="02:00:00:00:00:10", dst="02:00:00:00:00:01") / IP(src="192.168.1.10", dst="192.168.1.1") / UDP(sport=4000 + i, dport=53) / DNS(id=i, qd=DNSQR(qname=evil))
        a = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:10") / IP(src="192.168.1.1", dst="192.168.1.10") / UDP(sport=53, dport=4000 + i) / DNS(id=i, qr=1, qd=DNSQR(qname=evil), an=[DNSRR(rrname=evil, rdata="93.184.216.34")])
        b = Ether(src="02:00:00:00:00:66", dst="02:00:00:00:00:10") / IP(src="192.168.1.1", dst="192.168.1.10") / UDP(sport=53, dport=4000 + i) / DNS(id=i, qr=1, qd=DNSQR(qname=evil), an=[DNSRR(rrname=evil, rdata="192.168.1.66")])
        for k, p in enumerate((q, b, a)):
            p.time = 1_700_000_000 + i + k * 0.01
            pkts.append(p)
    f = tmp_path / "evil.pcap"
    wrpcap(str(f), pkts)
    report = analyze(f)
    blob = json.dumps(report)
    assert "\x1b" not in blob and "\\u001b" not in blob and "\x07" not in blob
    assert any(i["kind"] == "dns_hijack" for i in report["incidents"])
    page = render_html(report)
    assert "<script>alert(1)" not in page

    from typer.testing import CliRunner

    from packetdoctor.cli import app

    out = CliRunner().invoke(app, ["analyze", str(f)]).output
    assert "\x1b]0;" not in out and "\x1b[2J" not in out


def test_symlink_or_device_paths_rejected(tmp_path):
    with pytest.raises(CaptureError):
        analyze(tmp_path)  # a directory


def test_no_secrets_committed():
    try:
        files = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.split()
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("not a git checkout")
    pattern = re.compile(
        r"(api[_-]?key|secret[_-]?key|passw(or)?d)\s*[:=]\s*['\"][^'\"]{6,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16}|ghp_[0-9A-Za-z]{30,}|sk-[0-9A-Za-z]{20,}",
        re.I,
    )
    for name in files:
        path = ROOT / name
        if path.suffix in (".pcap", ".pcapng", ".png", ".jpg", ".mp4") or not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        assert not pattern.search(text), f"possible secret in {name}"
