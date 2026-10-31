"""Phase 7: lessons from real captures, new detectors, Wireshark hand-off."""

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import rdpcap, wrpcap

from packetdoctor.engine import analyze
from packetdoctor.pipeline import detect
from samples import generate as g

A, B = "02:00:00:00:00:0a", "02:00:00:00:00:0b"


def _tcp(src, dst, sp, dp, flags, seq, ack, plen=0, t=0.0):
    p = Ether(src=A if src.endswith(".10") else B, dst=B if src.endswith(".10") else A) / IP(src=src, dst=dst) / TCP(sport=sp, dport=dp, flags=flags, seq=seq, ack=ack)
    if plen:
        p = p / Raw(b"\x00" * plen)
    p.time = 1_700_000_000 + t
    return p


# --- consequences / chains on the new samples --------------------------------------


def test_gateway_down_explains_dns_and_dhcp(samples_dir):
    inc = analyze(samples_dir / "gateway_down.pcap")["incidents"]
    assert len(inc) == 1
    gw = inc[0]
    assert gw["metrics"]["is_gateway"] and gw["severity"] == 5
    assert "stopped answering" in gw["title"]
    assert sorted(c["kind"] for c in gw["consequences"]) == ["dhcp_failure", "dns_failure"]


def test_dhcp_starvation_blocks_real_client(samples_dir):
    inc = analyze(samples_dir / "dhcp_starvation.pcap")["incidents"][0]
    assert inc["metrics"]["fake_clients"] == 150
    assert inc["metrics"]["sent_from"] == ["de:ad:be:ef:00:66"]
    assert [c["kind"] for c in inc["consequences"]] == ["dhcp_failure"]


def test_arp_sweep_is_uncertain_not_attack(samples_dir):
    inc = analyze(samples_dir / "arp_sweep.pcap")["incidents"][0]
    assert inc["verdict"] == "UNCERTAIN"
    assert inc["metrics"]["sequential_share"] > 0.9
    assert "suspicious but not conclusive" not in inc["explanation"]["what"]  # fault-type detector keeps its own wording


def test_fragment_attack_ignores_normal_fragmentation(samples_dir):
    inc = analyze(samples_dir / "ip_fragment_attack.pcap")["incidents"]
    assert len(inc) == 1
    assert inc[0]["metrics"]["src"] == "192.168.1.66"  # the laptop's legitimate fragments are not flagged
    assert inc[0]["metrics"]["overlaps"] == 8 and inc[0]["metrics"]["tiny_fragments"] == 4


# --- receiver-side loss -----------------------------------------------------------


def test_loss_before_capture_point_is_counted(tmp_path):
    """Capture taken after the lossy link: the lost segment never appears,
    there is a gap, and the data arrives later as a retransmission."""
    c, s = "192.168.1.10", "203.0.113.5"
    pkts = [_tcp(c, s, 5000, 80, "S", 100, 0, t=0), _tcp(s, c, 80, 5000, "SA", 900, 101, t=0.02), _tcp(c, s, 5000, 80, "A", 101, 901, t=0.04)]
    seq, t = 901, 0.05
    for k in range(40):
        if k % 5 == 2:  # every 5th segment is lost upstream: skip it now...
            lost_seq = seq
        else:
            pkts.append(_tcp(s, c, 80, 5000, "PA", seq, 101, 1000, t=t))
        if k % 5 == 4:  # ...and it shows up 300 ms later
            pkts.append(_tcp(s, c, 80, 5000, "PA", lost_seq, 101, 1000, t=t + 0.3))
        seq += 1000
        t += 0.002
    f = tmp_path / "rx_side.pcap"
    wrpcap(str(f), sorted(pkts, key=lambda p: p.time))
    r = detect(f)
    flow = next(iter(r.state.flows.flows.values()))
    assert flow.dirs[1].retrans_kinds["lost_before_capture"] == 8
    assert any(s.kind == "tcp_retransmissions" for s in r.symptoms)


def test_reordering_is_not_loss(tmp_path):
    c, s = "192.168.1.10", "203.0.113.5"
    pkts = [_tcp(c, s, 5000, 80, "S", 100, 0, t=0), _tcp(s, c, 80, 5000, "SA", 900, 101, t=0.02)]
    seq, t = 901, 0.05
    for k in range(0, 20, 2):  # pairs swapped, 1 ms apart
        pkts.append(_tcp(s, c, 80, 5000, "PA", seq + 1000, 101, 1000, t=t))
        pkts.append(_tcp(s, c, 80, 5000, "PA", seq, 101, 1000, t=t + 0.001))
        seq += 2000
        t += 0.01
    f = tmp_path / "reorder.pcap"
    wrpcap(str(f), pkts)
    flow = next(iter(detect(f).state.flows.flows.values()))
    assert flow.dirs[1].retrans == 0 and flow.dirs[1].reordered == 10


# --- false-alarm fixes from real captures --------------------------------------------


def test_client_side_resets_are_normal(tmp_path):
    def scenario(cap):
        g.baseline(cap, 0, 30)
        for t in (5.0, 10.0, 15.0, 20.0):  # browser aborts its own downloads
            sport, isn, sisn = 50000 + int(t), 1000, 5000
            srv = "151.101.1.69"
            cap.add(t, g.tcp_pkt(g.LAPTOP, srv, sport, 443, "S", isn, 0, mss=1460))
            cap.add(t + 0.01, g.tcp_pkt(srv, g.LAPTOP, 443, sport, "SA", sisn, isn + 1, mss=1460))
            cap.add(t + 0.02, g.tcp_pkt(g.LAPTOP, srv, sport, 443, "PA", isn + 1, sisn + 1, plen=300))
            cap.add(t + 0.03, g.tcp_pkt(srv, g.LAPTOP, 443, sport, "PA", sisn + 1, isn + 301, plen=1200))
            cap.add(t + 0.04, g.tcp_pkt(g.LAPTOP, srv, sport, 443, "RA", isn + 301, sisn + 1201))

    cap = g.Capture(seed=3)
    scenario(cap)
    f = tmp_path / "client_rst.pcap"
    cap.write(f)
    assert analyze(f)["incidents"] == []


def test_clock_jump_is_handled(samples_dir, tmp_path):
    pkts = rdpcap(str(samples_dir / "clean.pcap"))
    for p in pkts[:20]:  # device booted without a clock
        p.time = 50 + float(p.time) % 10
    f = tmp_path / "jump.pcap"
    wrpcap(str(f), pkts)
    r = analyze(f)
    assert 50 < r["capture"]["duration_s"] < 70
    assert any("clock jumps" in w for w in r["capture"]["warnings"])
    assert len(r["timeline"]["series"]) < 100


def test_dns_records_without_rdata_are_tolerated(tmp_path):
    from scapy.layers.dns import DNSRRSOA

    q = Ether(src=A, dst=B) / IP(src="192.168.1.10", dst="192.168.1.1") / UDP(sport=4000, dport=53) / DNS(id=1, qd=DNSQR(qname="example.com", qtype="SOA"))
    a = Ether(src=B, dst=A) / IP(src="192.168.1.1", dst="192.168.1.10") / UDP(sport=53, dport=4000) / DNS(id=1, qr=1, qd=DNSQR(qname="example.com", qtype="SOA"), an=[DNSRRSOA(rrname="example.com")])
    q.time, a.time = 1_700_000_000, 1_700_000_000.01
    f = tmp_path / "soa.pcap"
    wrpcap(str(f), [q, a])
    assert analyze(f)["capture"]["malformed"] == 0


def test_benign_verdict_gets_benign_label(tmp_path):
    def scenario(cap):
        g.baseline(cap, 0, 30)
        g._dhcp(cap, 5.0, "3c:22:fb:00:00:55", 0x11, [(g.GW_IP, g.GW_IP, g.GW_IP, "192.168.1.120", 0.003)])
        g.MACS["192.168.1.2"] = "00:1a:2b:3c:00:02"
        try:
            g._dhcp(cap, 15.0, "3c:22:fb:00:00:56", 0x12, [("192.168.1.2", g.GW_IP, g.GW_IP, "192.168.1.121", 0.003)])
        finally:
            del g.MACS["192.168.1.2"]

    cap = g.Capture(seed=5)
    scenario(cap)
    f = tmp_path / "backup.pcap"
    cap.write(f)
    inc = analyze(f)["incidents"][0]
    assert inc["verdict"] != "ATTACK"
    assert inc["label"] == "Extra DHCP server"
    assert "Unauthorised" not in inc["title"]
    assert inc["severity"] <= 3


# --- Wireshark hand-off ------------------------------------------------------------------


def test_every_incident_has_wireshark_filters(samples_dir):
    for f in sorted(samples_dir.glob("*.pcap")):
        for inc in analyze(f)["incidents"]:
            assert inc["wireshark_filter"], (f.name, inc["kind"])
            assert inc["wireshark_exact"].startswith("frame.number in {")
            ids = inc["wireshark_exact"][len("frame.number in {"):-1].split()
            assert [int(i) for i in ids] == inc["packet_ids"]


def test_export_evidence_writes_exact_packets(samples_dir, tmp_path):
    from packetdoctor.report.export import export_evidence

    path = samples_dir / "mixed_fault_and_attack.pcap"
    report = analyze(path)
    files = export_evidence(path, report, tmp_path)
    assert len(files) == 3
    for inc in report["incidents"]:
        f = tmp_path / f"{inc['id']}_{inc['kind']}.pcap"
        assert len(rdpcap(str(f))) == len(inc["packet_ids"])


def test_cli_refuses_export_with_anonymize(samples_dir, tmp_path):
    from typer.testing import CliRunner

    from packetdoctor.cli import app

    res = CliRunner().invoke(app, ["analyze", str(samples_dir / "clean.pcap"), "--anonymize", "--export-evidence", str(tmp_path)])
    assert res.exit_code == 2
    assert list(tmp_path.iterdir()) == []
