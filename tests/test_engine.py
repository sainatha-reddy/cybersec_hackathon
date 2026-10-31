"""Phase 4: correlation, verdicts, explanations, health score, report, CLI."""

import json
import re

import pytest
from typer.testing import CliRunner

from packetdoctor.cli import app
from packetdoctor.engine import analyze
from packetdoctor.engine.verdict import decide, noisy_or
from packetdoctor.models import Category, Evidence, Verdict

# sample -> expected (verdict, kind) of every incident, in any order
EXPECTED = {
    "clean": [],
    "tcp_retransmissions": [("FAULT", "tcp_retransmissions")],
    "tcp_resets": [("FAULT", "tcp_connection_refused"), ("FAULT", "tcp_connection_aborted")],
    "dns_failure": [("FAULT", "dns_failure")],
    "duplicate_ip": [("FAULT", "duplicate_ip")],
    "mtu_problems": [("FAULT", "mtu_blackhole"), ("FAULT", "mtu_mismatch")],
    "high_latency": [("FAULT", "high_latency"), ("FAULT", "high_latency"), ("FAULT", "tcp_zero_window")],
    "port_scan": [("ATTACK", "port_scan")],
    "arp_spoofing": [("ATTACK", "arp_spoofing")],
    "dns_hijack": [("ATTACK", "dns_hijack")],
    "rogue_dhcp": [("ATTACK", "rogue_dhcp")],
    "mixed_fault_and_attack": [("ATTACK", "arp_spoofing"), ("ATTACK", "port_scan"), ("FAULT", "dns_failure")],
    "gateway_down": [("FAULT", "host_unreachable")],
    "dhcp_starvation": [("ATTACK", "dhcp_starvation")],
    "arp_sweep": [("UNCERTAIN", "arp_sweep")],
    "ip_fragment_attack": [("ATTACK", "fragment_attack")],
}


@pytest.fixture(scope="module")
def reports(samples_dir):
    return {name: analyze(samples_dir / f"{name}.pcap") for name in EXPECTED}


@pytest.mark.parametrize("name", list(EXPECTED))
def test_expected_incidents_and_verdicts(reports, name):
    got = sorted((i["verdict"], i["kind"]) for i in reports[name]["incidents"])
    assert got == sorted(EXPECTED[name])


def test_no_false_alarms_on_fault_only_captures(reports):
    for name, exp in EXPECTED.items():
        if all(v == "FAULT" for v, _ in exp):
            assert reports[name]["summary"]["attacks"] == 0, name


def test_mixed_capture_separates_fault_from_attack(reports):
    r = reports["mixed_fault_and_attack"]
    by_kind = {i["kind"]: i for i in r["incidents"]}
    spoof = by_kind["arp_spoofing"]
    # the victim's retransmissions are explained as a consequence of the attack
    assert [c["kind"] for c in spoof["consequences"]] == ["tcp_retransmissions"]
    assert spoof["confidence"] >= 0.8
    dns = by_kind["dns_failure"]
    assert dns["verdict"] == "FAULT"
    assert [c["kind"] for c in dns["consequences"]] == ["high_latency"]
    assert any("genuine fault" in n for n in dns["notes"])
    # attacks are listed first
    assert [i["verdict"] for i in r["incidents"]] == ["ATTACK", "ATTACK", "FAULT"]


def test_correlation_chains(reports):
    rogue = reports["rogue_dhcp"]["incidents"][0]
    assert [c["kind"] for c in rogue["consequences"]] == ["dns_hijack"]
    hole = next(i for i in reports["mtu_problems"]["incidents"] if i["kind"] == "mtu_blackhole")
    assert [c["kind"] for c in hole["consequences"]] == ["tcp_retransmissions"]
    dup = reports["duplicate_ip"]["incidents"][0]
    assert [r["kind"] for r in dup["related"]] == ["arp_conflict"]
    assert [c["kind"] for c in dup["consequences"]] == ["tcp_connection_aborted"]
    spoof = reports["arp_spoofing"]["incidents"][0]
    assert [r["kind"] for r in spoof["related"]] == ["arp_conflict"]
    assert spoof["benign_score"] == 0


def test_health_scores(reports):
    assert reports["clean"]["health"]["score"] == 100
    assert reports["clean"]["health"]["grade"] == "Healthy"
    assert reports["mixed_fault_and_attack"]["health"]["score"] < reports["dns_failure"]["health"]["score"]
    for r in reports.values():
        assert 0 <= r["health"]["score"] <= 100


def test_every_incident_is_explained_with_fixes_and_evidence(reports):
    for name, r in reports.items():
        for inc in r["incidents"]:
            ex = inc["explanation"]
            assert ex["what"] and ex["why"] and ex["cause"], (name, inc["kind"])
            assert len(ex["fixes"]) >= 1
            assert inc["packet_ids"]
            # every cited packet is resolved in the evidence table
            missing = [p for p in inc["packet_ids"] if str(p) not in r["evidence"]]
            assert not missing, (name, inc["kind"], missing[:5])
            assert "{" not in ex["what"] or "}" not in ex["what"].split("{", 1)[1][:2]  # no unfilled templates


def test_evidence_rows_match_packets(reports):
    ev = reports["arp_spoofing"]["evidence"]
    inc = reports["arp_spoofing"]["incidents"][0]
    first = ev[str(inc["packet_ids"][0])]
    assert first["proto"] == "ARP"
    assert "is-at de:ad:be:ef:00:66" in first["info"]


def test_report_is_json_serialisable(reports):
    for r in reports.values():
        json.loads(json.dumps(r))


def test_timeline(reports):
    tl = reports["mixed_fault_and_attack"]["timeline"]
    assert 0 < len(tl["series"]) <= 300
    assert sum(p["packets"] for p in tl["series"]) == reports["mixed_fault_and_attack"]["capture"]["packets"]
    assert {e["id"] for e in tl["events"]} == {"INC-1", "INC-2", "INC-3"}


def test_anonymize_removes_addresses(samples_dir):
    r = analyze(samples_dir / "arp_spoofing.pcap", anonymize=True)
    blob = json.dumps(r)
    assert "192.168.1." not in blob
    assert "de:ad:be:ef:00:66" not in blob
    assert "arp_spoofing.pcap" not in blob
    assert r["anonymized"] is True
    assert re.search(r"lan-[0-9a-f]{6}", blob) and re.search(r"mac-[0-9a-f]{6}", blob)
    # consistent within the report
    inc = r["incidents"][0]
    assert inc["metrics"]["attacker_mac"] in inc["title"]


# --- verdict logic ------------------------------------------------------------------


def test_noisy_or():
    assert noisy_or([]) == 0
    assert noisy_or([Evidence("a", 0.5), Evidence("b", 0.5)]) == pytest.approx(0.75)


def test_weak_attack_evidence_gives_uncertain_not_attack():
    v, conf, a, b = decide(Category.ATTACK, [Evidence("x", 0.3)], [])
    assert v == Verdict.UNCERTAIN
    v, *_ = decide(Category.ATTACK, [Evidence("x", 0.5), Evidence("y", 0.4)], [Evidence("z", 0.6)])
    assert v == Verdict.UNCERTAIN


def test_strong_benign_evidence_turns_attack_detector_into_fault():
    v, *_ = decide(Category.ATTACK, [Evidence("second server", 0.3)], [Evidence("same settings", 0.6), Evidence("x", 0.3)])
    assert v == Verdict.FAULT


def test_fault_with_attack_clues_becomes_suspicious():
    v, *_ = decide(Category.FAULT, [Evidence("unsolicited replies", 0.5)], [Evidence("normal hosts", 0.3)])
    assert v == Verdict.UNCERTAIN


# --- CLI -------------------------------------------------------------------------


def test_cli_analyze(samples_dir, tmp_path):
    out = tmp_path / "r.json"
    res = CliRunner().invoke(app, ["analyze", str(samples_dir / "mixed_fault_and_attack.pcap"), "--json", str(out)])
    assert res.exit_code == 0, res.output
    assert "ATTACK" in res.output and "FAULT" in res.output
    assert "What to do" in res.output
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["summary"]["attacks"] == 2


def test_cli_rejects_bad_file_cleanly(tmp_path):
    bad = tmp_path / "bad.pcap"
    bad.write_text("not a capture at all, just text" * 3)
    res = CliRunner().invoke(app, ["analyze", str(bad)])
    assert res.exit_code == 2
    assert "Cannot analyse" in res.output
    assert "Traceback" not in res.output


def test_cli_quiet_clean(samples_dir):
    res = CliRunner().invoke(app, ["analyze", str(samples_dir / "clean.pcap"), "-q"])
    assert res.exit_code == 0
    assert "100/100" in res.output and "No problems found" in res.output
