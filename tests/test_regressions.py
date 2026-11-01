import json
import struct
import threading
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from scapy.packet import Raw

from packetdoctor._scapy import DNS, DNSQR, DNSRR, Ether, IP, IPv6, TCP, UDP, wrpcap
from packetdoctor.config import Limits, Settings
from packetdoctor.engine import analyze
from packetdoctor.engine.correlate import correlate
from packetdoctor.ingest import CaptureError
from packetdoctor.models import Category, Symptom
from packetdoctor.report.anonymize import Anonymizer
from packetdoctor.worker import analyze_isolated


def write_capture(path, packets):
    for index, packet in enumerate(packets):
        packet[Ether].src = "02:00:00:00:00:10"
        packet[Ether].dst = "02:00:00:00:00:20"
        if not hasattr(packet, "audit_time"):
            packet.time = 1_800_000_000 + index * 0.01
    wrpcap(str(path), packets)
    return path


def test_ipv6_anonymization_is_canonical_and_complete(tmp_path):
    anonymizer = Anonymizer(b"regression-key")
    assert anonymizer.text("2001:0db8:0000:0000:0000:0000:0000:0010") == anonymizer.text("2001:db8::10")
    assert "192.0.2.1" not in anonymizer.text("[::ffff:192.0.2.1]")
    assert "fe80::1" not in anonymizer.text("device fe80::1%eth0.")
    packets = []
    for index in range(3):
        packets.extend([Ether() / IPv6(src="2001:db8::10", dst="2001:db8::20") / TCP(sport=40000 + index, dport=80, flags="S", seq=1),
                        Ether() / IPv6(src="2001:db8::20", dst="2001:db8::10") / TCP(sport=80, dport=40000 + index, flags="RA", ack=2)])
    path = write_capture(tmp_path / "ipv6.pcap", packets)
    report = analyze(path, anonymize=True)
    assert report["incidents"]
    assert "2001:db8" not in json.dumps(report)
    plain = analyze(path)
    assert plain["incidents"][0]["wireshark_filter"].startswith("ipv6.addr")


def test_dns_identifiers_can_be_reused_without_false_alarm(tmp_path):
    packets = []
    for index in range(3):
        question = DNSQR(qname=f"host{index}.example.com")
        query = Ether() / IP(src="192.168.1.10", dst="192.168.1.1") / UDP(sport=40000, dport=53) / DNS(id=42, qd=question)
        answer = Ether() / IP(src="192.168.1.1", dst="192.168.1.10") / UDP(sport=53, dport=40000) / DNS(id=42, qr=1, qd=question, an=[DNSRR(rrname=question.qname, rdata=f"93.184.216.{30 + index}")])
        packets.extend([query, answer])
    report = analyze(write_capture(tmp_path / "dns-reuse.pcap", packets))
    assert report["network"]["dns_queries"] == 3
    assert not report["incidents"]


def test_fragment_id_can_be_reused_after_completion(tmp_path):
    packets = []
    for offset, size, more in [(0, 1480, True), (1480, 520, False), (0, 800, True), (800, 800, False)]:
        packets.append(Ether() / IP(src="192.168.1.10", dst="192.168.1.20", id=123, proto=17, frag=offset // 8, flags="MF" if more else 0) / Raw(b"x" * size))
    assert not analyze(write_capture(tmp_path / "fragment-reuse.pcap", packets))["incidents"]


def test_extreme_timestamp_does_not_crash(tmp_path):
    def block(kind, body):
        length = len(body) + 12
        return struct.pack("<II", kind, length) + body + struct.pack("<I", length)

    frame = bytes(Ether(src="02:00:00:00:00:10", dst="02:00:00:00:00:20") / IP(src="192.168.1.10", dst="192.168.1.20") / UDP(sport=1200, dport=1201))
    frame_padded = frame + bytes((-len(frame)) % 4)
    path = tmp_path / "timestamp.pcapng"
    path.write_bytes(block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)) + block(1, struct.pack("<HHI", 1, 0, 65535)) + block(6, struct.pack("<IIIII", 0, 0xffffffff, 0xffffffff, len(frame), len(frame)) + frame_padded))
    report = analyze(path)
    assert report["capture"]["malformed"] == 1
    assert report["health"]["score"] is None
    assert report["analysis"]["coverage"] == "insufficient_data"


def test_oversized_pcapng_block_is_rejected_before_body_allocation(tmp_path, samples_dir):
    path = tmp_path / "oversized-block.pcapng"
    header = (samples_dir / "clean.pcapng").read_bytes()
    section_length = struct.unpack("<I", header[4:8])[0]
    path.write_bytes(header[:section_length] + struct.pack("<II", 6, 0x7ffffffc) + bytes(32))
    report = analyze(path)
    assert report["analysis"]["coverage"] == "insufficient_data"
    assert any("allocation limit" in warning for warning in report["capture"]["warnings"])


def test_truncated_record_cannot_be_reported_as_complete(tmp_path, samples_dir):
    data = (samples_dir / "clean.pcap").read_bytes()
    path = tmp_path / "truncated.pcap"
    path.write_bytes(data[:len(data) // 2 + 7])
    report = analyze(path)
    assert report["capture"]["truncated"]
    assert report["analysis"]["coverage"] == "partial"


def test_zero_coverage_and_uncertainty_are_not_reassuring(samples_dir):
    partial = analyze(samples_dir / "clean.pcap", Settings(limits=Limits(timeout_seconds=0)))
    assert partial["health"]["score"] is None
    uncertain = analyze(samples_dir / "arp_sweep.pcap")
    assert "none of them malicious" not in uncertain["health"]["summary"]
    assert uncertain["health"]["grade"] == "Needs review"


def test_correlation_does_not_merge_disjoint_events():
    cause = Symptom(kind="mtu_blackhole", category=Category.FAULT, severity=4, title="early", t_start=0, t_end=5, metrics={"src": "10.0.0.1", "dst": "10.0.0.2"})
    effect = Symptom(kind="tcp_retransmissions", category=Category.FAULT, severity=3, title="later", t_start=3600, t_end=3610, metrics={"client": "10.0.0.1", "server": "10.0.0.2"})
    assert len(correlate([cause, effect])) == 2


def test_state_budget_stops_with_partial_results(samples_dir):
    report = analyze(samples_dir / "arp_spoofing.pcap", Settings(limits=Limits(max_state_items=200)))
    assert report["analysis"]["coverage"] == "partial"
    assert any("budget" in warning.lower() for warning in report["capture"]["warnings"])


def test_every_wrapped_collection_has_an_entry_limit():
    from packetdoctor.state.budget import StateBudget, StateLimitReached

    budget = StateBudget(1000, max_entries=2)
    mapping = budget.wrap({})
    mapping["first"] = []
    mapping["second"] = set()
    with pytest.raises(StateLimitReached, match="entry limit"):
        mapping["third"] = 1
    mapping["first"].extend([1, 2])
    with pytest.raises(StateLimitReached, match="entry limit"):
        mapping["first"].append(3)


def test_reused_tcp_tuple_starts_a_new_connection(tmp_path):
    packets = []
    for sequence in (100, 1000, 2000):
        packets.extend([Ether() / IP(src="192.168.1.10", dst="192.168.1.20") / TCP(sport=40000, dport=80, flags="S", seq=sequence),
                        Ether() / IP(src="192.168.1.20", dst="192.168.1.10") / TCP(sport=80, dport=40000, flags="RA", ack=sequence + 1)])
    report = analyze(write_capture(tmp_path / "tuple-reuse.pcap", packets))
    assert report["network"]["flows"] == 3
    assert report["incidents"][0]["metrics"]["attempts"] == 3


def test_fault_evidence_survives_flow_eviction(tmp_path):
    packets = []
    for index in range(3):
        packets.extend([Ether() / IP(src="192.168.1.10", dst="192.168.1.20") / TCP(sport=40000 + index, dport=80, flags="S", seq=100),
                        Ether() / IP(src="192.168.1.20", dst="192.168.1.10") / TCP(sport=80, dport=40000 + index, flags="RA", ack=101)])
    report = analyze(write_capture(tmp_path / "eviction.pcap", packets), Settings(limits=Limits(max_flows=2)))
    assert report["incidents"][0]["kind"] == "tcp_connection_refused"
    assert report["incidents"][0]["metrics"]["attempts"] == 3
    assert report["analysis"]["coverage"] == "partial"


def test_worker_cancellation_and_whole_job_deadline(samples_dir):
    cancelled = threading.Event()
    cancelled.set()
    with pytest.raises(CaptureError, match="cancelled"):
        analyze_isolated(samples_dir / "clean.pcap", cancelled=cancelled)
    with pytest.raises(CaptureError, match="whole-job time limit"):
        analyze_isolated(samples_dir / "clean.pcap", Settings(limits=Limits(timeout_seconds=0.001)))


def test_worker_enforces_memory_budget(samples_dir):
    with pytest.raises(CaptureError, match="memory budget"):
        analyze_isolated(samples_dir / "clean.pcap", Settings(limits=Limits(max_memory_mb=1)))


def test_background_admission_cancellation_and_cleanup(monkeypatch, samples_dir, tmp_path):
    import tempfile
    from packetdoctor.web import app as webapp

    def wait_for_cancellation(path, settings, anonymize, cancelled):
        cancelled.wait(5)
        raise CaptureError("Analysis cancelled.")

    monkeypatch.setattr(webapp, "analyze_isolated", wait_for_cancellation)
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    with TestClient(webapp.app) as client:
        with (samples_dir / "clean.pcap").open("rb") as stream:
            first = client.post("/api/analyze?background=true", files={"file": ("capture.pcap", stream)})
        assert first.status_code == 202
        second = client.post("/api/analyze-sample/clean.pcap?background=true")
        assert second.status_code == 202
        assert client.post("/api/analyze-sample/clean.pcap?background=true").status_code == 429
        assert client.delete("/api/jobs/" + first.json()["job_id"]).status_code == 200
        assert client.delete("/api/jobs/" + second.json()["job_id"]).status_code == 200
        for attempt in range(100):
            if not list(tmp_path.iterdir()):
                break
            time.sleep(0.01)
        assert not list(tmp_path.iterdir())


def test_body_limit_covers_declared_and_chunked_uploads(monkeypatch):
    from packetdoctor.web import app as webapp

    monkeypatch.setattr(webapp, "MAX_UPLOAD", 10)
    with TestClient(webapp.app) as client:
        response = client.post("/api/analyze", content=bytes(70_000), headers={"Content-Type": "application/octet-stream"})
        assert response.status_code == 413
        response = client.post("/api/analyze", content=iter([bytes(35_000), bytes(35_000)]), headers={"Content-Type": "multipart/form-data; boundary=audit"})
        assert response.status_code == 413


def test_benchmark_does_not_credit_wrong_linked_verdict(monkeypatch):
    import importlib.util

    spec = importlib.util.spec_from_file_location("regression_benchmark", Path(__file__).resolve().parents[1] / "benchmark/run.py")
    bench = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bench)
    monkeypatch.setattr(bench, "analyze", lambda path: {"incidents": [{"kind": "rogue_dhcp", "verdict": "FAULT", "related": [], "consequences": [{"kind": "dns_hijack", "verdict": "FAULT", "packet_ids": [5]}]}]})
    result = bench.score_case({"path": "unused", "expected": [{"kind": "dns_hijack", "verdict": "ATTACK", "packet_ids": [5]}], "negatives": []})
    assert result["outcomes"] == [("dns_hijack", "wrong verdict (FAULT)")]
    result = bench.score_case({"path": "unused", "expected": [{"kind": "dns_hijack", "verdict": "ATTACK", "packet_ids": [99]}], "negatives": []})
    assert result["outcomes"] == [("dns_hijack", "missed")]
    monkeypatch.setattr(bench, "analyze", lambda path: {"incidents": [{"kind": "dns_hijack", "verdict": "ATTACK", "packet_ids": [5], "related": [], "consequences": []}]})
    result = bench.score_case({"path": "unused", "expected": [{"kind": "dns_hijack", "verdict": "FAULT", "packet_ids": [5]}], "negatives": []})
    result["seed"] = 1
    assert bench.summarise([result], 0)["false_attack_cases"] == 1
