"""Phase 1: safe capture loading and decoding."""

import os

import pytest

from packetdoctor.config import Limits, Settings
from packetdoctor.ingest import CaptureError, read_capture, validate_capture
from packetdoctor.models import IngestStats
from packetdoctor.utils import safe_text


def load(path, settings=Settings()):
    stats = IngestStats()
    records = list(read_capture(path, stats, settings))
    return records, stats


# --- validation ------------------------------------------------------------


def test_rejects_missing_file(tmp_path):
    with pytest.raises(CaptureError, match="not found"):
        validate_capture(tmp_path / "nope.pcap")


def test_rejects_directory(tmp_path):
    with pytest.raises(CaptureError, match="regular file"):
        validate_capture(tmp_path)


def test_rejects_tiny_file(tmp_path):
    f = tmp_path / "tiny.pcap"
    f.write_bytes(b"\xd4\xc3\xb2\xa1")
    with pytest.raises(CaptureError, match="too small"):
        validate_capture(f)


def test_rejects_wrong_magic_even_with_pcap_extension(tmp_path):
    f = tmp_path / "evil.pcap"
    f.write_bytes(b"<script>alert(1)</script>" + b"A" * 100)
    with pytest.raises(CaptureError, match="not a pcap"):
        validate_capture(f)


def test_rejects_oversized_file(samples_dir):
    small = Settings(limits=Limits(max_file_bytes=1024))
    with pytest.raises(CaptureError, match="limit"):
        validate_capture(samples_dir / "clean.pcap", small)


def test_error_message_does_not_leak_full_path(tmp_path):
    f = tmp_path / "secret_dir_name" / "x.pcap"
    f.parent.mkdir()
    f.write_bytes(b"garbage" * 10)
    with pytest.raises(CaptureError) as exc:
        validate_capture(f)
    assert "secret_dir_name" not in str(exc.value)


def test_detects_formats(samples_dir):
    assert validate_capture(samples_dir / "clean.pcap") == "pcap"
    assert validate_capture(samples_dir / "clean.pcapng") == "pcapng"


# --- reading ---------------------------------------------------------------


def test_reads_every_sample_without_errors(samples_dir):
    for f in sorted(samples_dir.glob("*.pcap")):
        records, stats = load(f)
        assert stats.packets_read > 100, f.name
        assert stats.malformed == 0, f.name
        assert stats.packets_decoded == len(records) == stats.packets_read
        assert not stats.truncated
        assert stats.duration > 10
        assert [r.idx for r in records] == list(range(1, len(records) + 1))


def test_pcapng_matches_pcap(samples_dir):
    a, _ = load(samples_dir / "clean.pcap")
    b, _ = load(samples_dir / "clean.pcapng")
    assert len(a) == len(b)
    assert [(r.src_ip, r.dst_ip, r.tcp_flags) for r in a] == [(r.src_ip, r.dst_ip, r.tcp_flags) for r in b]


def test_truncated_capture_is_handled(samples_dir, tmp_path):
    data = (samples_dir / "clean.pcap").read_bytes()
    cut = tmp_path / "cut.pcap"
    cut.write_bytes(data[: len(data) // 2 + 7])  # cut in the middle of a packet
    records, stats = load(cut)
    assert 0 < len(records) < 619


def test_garbage_after_header_does_not_crash(samples_dir, tmp_path):
    header = (samples_dir / "clean.pcap").read_bytes()[:24]
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(header + os.urandom(5000))
    records, stats = load(bad)  # must not raise
    assert stats.packets_read >= 0


def test_corrupted_bytes_inside_packets(samples_dir, tmp_path):
    data = bytearray((samples_dir / "clean.pcap").read_bytes())
    for pos in range(200, len(data), 997):  # flip bytes all over the file
        data[pos] ^= 0xFF
    bad = tmp_path / "flipped.pcap"
    bad.write_bytes(bytes(data))
    load(bad)  # must not raise


def test_packet_limit(samples_dir):
    settings = Settings(limits=Limits(max_packets=50))
    records, stats = load(samples_dir / "clean.pcap", settings)
    assert len(records) == 50
    assert stats.packet_limit_hit
    assert stats.warnings


# --- decoding --------------------------------------------------------------


def test_decodes_tcp_fields(samples_dir):
    records, _ = load(samples_dir / "clean.pcap")
    syns = [r for r in records if r.is_tcp and r.tcp_flags == 0x02]
    assert syns and all(r.mss == 1460 for r in syns)
    data = [r for r in records if r.is_tcp and r.payload_len > 0]
    assert data and all(r.payload_len <= 1460 for r in data)


def test_decodes_dns(samples_dir):
    records, _ = load(samples_dir / "dns_failure.pcap")
    responses = [r for r in records if r.dns and r.dns.is_response]
    assert any(r.dns.rcode == 2 for r in responses)
    ok = [r for r in responses if r.dns.rcode == 0]
    assert ok and ok[0].dns.answers
    assert ok[0].dns.qname.split(".")[-1] in ("com", "org", "net")


def test_decodes_dhcp(samples_dir):
    records, _ = load(samples_dir / "rogue_dhcp.pcap")
    offers = [r.dhcp for r in records if r.dhcp and r.dhcp.msg_type == 2]
    assert {o.server_id for o in offers} == {"192.168.1.1", "192.168.1.66"}
    assert all(o.router and o.dns_servers for o in offers)


def test_decodes_arp(samples_dir):
    records, _ = load(samples_dir / "arp_spoofing.pcap")
    replies = [r.arp for r in records if r.arp and r.arp.op == 2]
    assert any(a.psrc == "192.168.1.1" and a.hwsrc == "de:ad:be:ef:00:66" for a in replies)


def test_decodes_icmp_frag_needed(samples_dir):
    records, _ = load(samples_dir / "mtu_problems.pcap")
    icmp = [r for r in records if r.icmp_mtu]
    assert len(icmp) == 1
    assert icmp[0].icmp_mtu == 1400
    assert icmp[0].icmp_inner[1] == "203.0.113.50"
    assert icmp[0].sport is None  # quoted header is not treated as real traffic


def test_safe_text_strips_control_chars():
    assert safe_text(b"evil\x1b[31m\x00name") == "evil?[31m?name"
    assert len(safe_text("a" * 1000)) == 255
