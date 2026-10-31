"""Phase 3: attack detectors, including benign look-alikes that must not be
mistaken for attacks."""

from scapy.layers.l2 import ARP, Ether

from packetdoctor.detectors import ALL_DETECTORS
from packetdoctor.models import Category
from packetdoctor.pipeline import detect
from samples import generate as g


def run(path):
    return detect(path, detectors=ALL_DETECTORS)


def attacks(result):
    return [s for s in result.symptoms if s.category == Category.ATTACK]


def only(result, kind):
    found = [s for s in result.symptoms if s.kind == kind]
    assert len(found) == 1, [s.title for s in result.symptoms]
    return found[0]


def build(tmp_path, name, fn, seed=7):
    cap = g.Capture(seed=seed)
    fn(cap)
    path = tmp_path / f"{name}.pcap"
    cap.write(path)
    return path


# --- positive detections on the samples -----------------------------------------


def test_clean_has_no_attacks(samples_dir):
    assert attacks(run(samples_dir / "clean.pcap")) == []


def test_port_scan(samples_dir):
    s = only(run(samples_dir / "port_scan.pcap"), "port_scan")
    m = s.metrics
    assert m["scanner"] == "192.168.1.66"
    assert m["vertical_targets"]["192.168.1.20"] >= 300
    assert m["horizontal_ports"][22] >= 70
    assert m["open_ports_found"]["192.168.1.20"] == [22, 80, 445]
    assert m["completion"] == 0
    assert sum(e.weight for e in s.attack_evidence) >= 1.0


def test_arp_spoofing(samples_dir):
    s = only(run(samples_dir / "arp_spoofing.pcap"), "arp_spoofing")
    m = s.metrics
    assert m["attacker_mac"] == "de:ad:be:ef:00:66"
    assert m["gateway_targeted"] is True
    assert set(m["impersonated"]) == {"192.168.1.1", "192.168.1.10"}
    assert m["attacker_ips"] == ["192.168.1.66"]
    assert m["relayed_packets"] > 100
    assert s.severity == 5
    assert any("clockwork" in e.text for e in s.attack_evidence)


def test_dns_hijack_race(samples_dir):
    s = only(run(samples_dir / "dns_hijack.pcap"), "dns_hijack")
    m = s.metrics
    assert m["suspect"] == "de:ad:be:ef:00:66"
    assert m["claimed_resolver"] == "192.168.1.1"
    assert m["names"] == ["mail.example.com", "mybank.example.com"]
    assert m["forged_addresses"] == ["192.168.1.66"]
    assert m["real_addresses"]["mybank.example.com"] == ["203.0.113.80"]
    texts = " ".join(e.text for e in s.attack_evidence)
    assert "Two different answers" in texts and "different device" in texts


def test_rogue_dhcp_and_its_dns(samples_dir):
    r = run(samples_dir / "rogue_dhcp.pcap")
    s = only(r, "rogue_dhcp")
    assert s.metrics["rogue_server"] == "192.168.1.66"
    assert s.metrics["legit_server"] == "192.168.1.1"
    assert s.metrics["clients_accepted"] == 2
    assert s.benign_evidence == []
    h = only(r, "dns_hijack")
    assert h.metrics["suspect"] == "192.168.1.66"


def test_mixed_capture_finds_both_attacks_and_the_fault(samples_dir):
    r = run(samples_dir / "mixed_fault_and_attack.pcap")
    found = {s.kind for s in r.symptoms}
    assert {"port_scan", "arp_spoofing", "dns_failure"} <= found


def test_faults_have_no_attack_findings(samples_dir):
    for name in ("tcp_retransmissions", "tcp_resets", "dns_failure", "duplicate_ip", "mtu_problems", "high_latency"):
        assert attacks(run(samples_dir / f"{name}.pcap")) == [], name


# --- benign look-alikes --------------------------------------------------------


def test_backup_dhcp_server_is_flagged_with_benign_evidence(tmp_path):
    def scenario(cap):
        g.baseline(cap, 0, 30)
        g._dhcp(cap, 5.0, "3c:22:fb:00:00:55", 0x11, [(g.GW_IP, g.GW_IP, g.GW_IP, "192.168.1.120", 0.003)])
        # a second, properly configured server (same gateway and DNS)
        g.MACS["192.168.1.2"] = "00:1a:2b:3c:00:02"
        try:
            g._dhcp(cap, 15.0, "3c:22:fb:00:00:56", 0x12, [("192.168.1.2", g.GW_IP, g.GW_IP, "192.168.1.121", 0.003)])
        finally:
            del g.MACS["192.168.1.2"]

    s = only(run(build(tmp_path, "backup_dhcp", scenario)), "rogue_dhcp")
    assert s.benign_evidence, "same gateway/DNS should count as benign evidence"
    assert not any("gateway instead" in e.text for e in s.attack_evidence)


def test_busy_client_is_not_a_port_scan(tmp_path):
    def scenario(cap):
        g.baseline(cap, 0, 20)
        for i in range(25):  # 25 different web servers within a few seconds, all real downloads
            g.tcp_session(cap, 5 + 0.2 * i, g.LAPTOP, f"151.101.{i}.10", 443, nseg=4)

    r = run(build(tmp_path, "busy_client", scenario))
    scans = [s for s in r.symptoms if s.kind == "port_scan"]
    for s in scans:  # if reported at all, it must carry strong benign evidence
        assert s.metrics["completion"] > 0.9
        assert s.benign_evidence


def test_router_failover_is_not_arp_spoofing(tmp_path):
    def scenario(cap):
        g.baseline(cap, 0, 40)
        new_mac = "00:1a:2b:3c:00:99"  # standby router takes over the gateway IP once
        cap.add(20.0, Ether(src=new_mac, dst=g.BROADCAST) / ARP(op=2, hwsrc=new_mac, psrc=g.GW_IP, hwdst=g.BROADCAST, pdst=g.GW_IP))

    r = run(build(tmp_path, "failover", scenario))
    assert not [s for s in r.symptoms if s.kind == "arp_spoofing"]


def test_split_horizon_dns_alone_is_not_hijack(tmp_path):
    # an internal name that only ever resolves to a private address is normal
    def scenario(cap):
        g.baseline(cap, 0, 30)
        for t in (5.0, 12.0, 19.0):
            g.dns_lookup(cap, t, g.LAPTOP, "intranet.office.lan", answers=["192.168.1.5"])

    r = run(build(tmp_path, "split_horizon", scenario))
    assert not [s for s in r.symptoms if s.kind == "dns_hijack"]
