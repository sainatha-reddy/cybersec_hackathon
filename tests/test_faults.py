"""Phase 2: network state tracking and fault detectors."""

import pytest

from packetdoctor.config import DEFAULT_SETTINGS
from packetdoctor.detectors import FAULT_DETECTORS
from packetdoctor.models import Category
from packetdoctor.pipeline import detect
from packetdoctor.state.lru import LRUDict


def run(samples_dir, name):
    return detect(samples_dir / f"{name}.pcap", detectors=FAULT_DETECTORS)


def kinds(result):
    return {s.kind for s in result.symptoms}


def only(result, kind):
    found = [s for s in result.symptoms if s.kind == kind]
    assert len(found) == 1, f"expected one {kind}, got {[s.title for s in result.symptoms]}"
    return found[0]


def test_clean_capture_has_no_findings(samples_dir):
    r = run(samples_dir, "clean")
    assert r.symptoms == [], [s.title for s in r.symptoms]
    assert r.detector_errors == []


def test_single_lost_packet_is_not_reported(samples_dir):
    # clean.pcap contains exactly one retransmission on purpose
    r = run(samples_dir, "clean")
    total = sum(d.retrans for f in r.state.flows.flows.values() for d in f.dirs)
    assert total == 1


def test_retransmissions(samples_dir):
    s = only(run(samples_dir, "tcp_retransmissions"), "tcp_retransmissions")
    assert s.category == Category.FAULT
    assert s.metrics["server"] == "203.0.113.50"
    assert s.metrics["retransmissions"] == 36  # 4 downloads x 9 lost segments
    assert s.metrics["ratio"] > 0.15
    assert s.severity >= 4
    assert s.packet_ids


def test_resets_refused_and_aborted(samples_dir):
    r = run(samples_dir, "tcp_resets")
    refused = only(r, "tcp_connection_refused")
    assert (refused.metrics["server"], refused.metrics["port"]) == ("192.168.1.30", 9100)
    assert refused.metrics["attempts"] == 6
    aborted = only(r, "tcp_connection_aborted")
    assert aborted.metrics["server"] == "140.82.112.3"
    assert aborted.metrics["reset_by"] == "the server"


def test_port_scan_resets_are_not_a_fault(samples_dir):
    r = run(samples_dir, "port_scan")
    assert "tcp_connection_refused" not in kinds(r)


def test_dns_failure(samples_dir):
    r = run(samples_dir, "dns_failure")
    s = only(r, "dns_failure")
    assert s.metrics["server"] == "192.168.1.1"
    assert s.metrics["servfail"] > 5 and s.metrics["timeouts"] > 5
    assert 19 <= s.t_start - 1793563200 <= 21


def test_nxdomain_alone_is_not_a_failure(samples_dir):
    r = run(samples_dir, "clean")
    nx = [q for q in r.state.dns.all_queries() if q.first and q.first.rcode == 3]
    assert len(nx) == 2
    assert "dns_failure" not in kinds(r)


def test_duplicate_ip(samples_dir):
    r = run(samples_dir, "duplicate_ip")
    s = only(r, "duplicate_ip")
    assert s.metrics["ip"] == "192.168.1.20"
    assert s.metrics["original_mac"] == "3c:22:fb:00:00:20"
    assert s.metrics["new_mac"] == "3c:22:fb:00:00:99"
    c = only(r, "arp_conflict")
    assert set(c.metrics["conflict_types"]) == {"announcement", "two_answers"}


def test_arp_spoofer_is_not_a_duplicate_ip(samples_dir):
    # forged ARP replies + relayed packets must not look like two honest hosts
    r = run(samples_dir, "arp_spoofing")
    assert "duplicate_ip" not in kinds(r)
    assert "tcp_retransmissions" not in kinds(r)  # relayed copies are not retransmissions
    assert r.state.relay.by_mac["de:ad:be:ef:00:66"].count > 50


def test_mtu(samples_dir):
    r = run(samples_dir, "mtu_problems")
    m = only(r, "mtu_mismatch")
    assert m.metrics["path_mtu"] == 1400 and m.metrics["sender_adapted"] is True
    b = only(r, "mtu_blackhole")
    assert b.metrics["dst"] == "198.51.100.20" and b.metrics["flows"] == 2


def test_latency_and_zero_window(samples_dir):
    r = run(samples_dir, "high_latency")
    lat = [s for s in r.symptoms if s.kind == "high_latency"]
    assert {s.metrics["what"].split()[0] for s in lat} == {"connection", "DNS"}
    for s in lat:
        assert 29 <= s.t_start - 1793563200 <= 32
        assert s.metrics["slow_median_ms"] > 10 * s.metrics["baseline_ms"]
    zw = only(r, "tcp_zero_window")
    assert zw.metrics["receiver"] == "192.168.1.30"


def test_gateway_inference(samples_dir):
    r = run(samples_dir, "arp_spoofing")
    assert r.state.hosts.gateway() == ("192.168.1.1", "00:1a:2b:3c:00:01")


@pytest.mark.parametrize("name", ["clean", "tcp_retransmissions", "mixed_fault_and_attack"])
def test_every_symptom_is_well_formed(samples_dir, name):
    for s in run(samples_dir, name).symptoms:
        assert 1 <= s.severity <= 5
        assert s.t_start <= s.t_end
        assert s.packet_ids == sorted(s.packet_ids)
        assert len(s.packet_ids) <= DEFAULT_SETTINGS.limits.max_evidence_per_symptom
        assert s.title and s.hosts
        s.to_dict()  # serialisable


def test_lru_cap():
    d = LRUDict(3)
    for i in range(10):
        d.get_or_create(i, dict)
    assert len(d) == 3 and d.evicted == 7 and list(d) == [7, 8, 9]
