"""Wireshark display filters for each finding.

Two filters per incident: a *focused* filter that shows the traffic pattern
behind the diagnosis (useful for digging further), and an *exact* filter that
selects precisely the evidence packets PacketDoctor cited. We only generate
the filter text; Wireshark itself is never run or required.
"""

from __future__ import annotations

import re

from ..models import Symptom


def _ip(addr: str, direction: str = "addr") -> str:
    protocol = "ipv6" if ":" in addr else "ip"
    return f"{protocol}.{direction} == {addr}"


def focused_filter(s: Symptom) -> str | None:
    m = s.metrics
    k = s.kind
    if k == "tcp_retransmissions":
        return f"({_ip(m['client'])} && {_ip(m['server'])}) && (tcp.analysis.retransmission || tcp.analysis.lost_segment)"
    if k == "tcp_connection_refused":
        return f"{_ip(m['server'])} && tcp.port == {m['port']} && tcp.flags.reset == 1"
    if k == "tcp_connection_aborted":
        return f"{_ip(m['server'], 'src')} && tcp.srcport == {m['port']} && tcp.flags.reset == 1"
    if k == "dns_failure":
        return f"dns && {_ip(m['server'])} && (dns.flags.rcode != 0 || !dns.response_in)"
    if k == "high_latency":
        return "dns.time > 0.25" if m["what"].startswith("DNS") else "tcp.flags.syn == 1 && tcp.flags.ack == 1 && tcp.analysis.ack_rtt > 0.25"
    if k == "tcp_zero_window":
        return f"tcp.analysis.zero_window && {_ip(m['receiver'], 'src')}"
    if k in ("duplicate_ip", "arp_conflict"):
        return f"arp.src.proto_ipv4 == {m['ip']} || arp.dst.proto_ipv4 == {m['ip']} || ip.src == {m['ip']}"
    if k == "mtu_mismatch":
        return f"(icmp.type == 3 && icmp.code == 4) || icmpv6.type == 2 || ({_ip(m['src'], 'src')} && {_ip(m['dst'], 'dst')} && tcp.len > 1300)"
    if k == "mtu_blackhole":
        return f"{_ip(m['src'], 'src')} && {_ip(m['dst'], 'dst')} && tcp.len >= 1200"
    if k == "port_scan":
        return f"{_ip(m['scanner'], 'src')} && tcp.flags.syn == 1 && tcp.flags.ack == 0"
    if k == "arp_spoofing":
        return f"arp.src.hw_mac == {m['attacker_mac']} || eth.src == {m['attacker_mac']}"
    if k == "dns_hijack":
        suspect = m["suspect"]
        return f"dns.flags.response == 1 && eth.src == {suspect}" if re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", suspect) else f"dns.flags.response == 1 && {_ip(suspect, 'src')}"
    if k == "rogue_dhcp":
        return f"dhcp.option.dhcp_server_id == {m['rogue_server']}"
    if k in ("arp_storm", "arp_sweep"):
        return f"arp.opcode == 1 && eth.src == {m['mac']}"
    if k == "host_unreachable":
        return f"arp.dst.proto_ipv4 == {m['ip']} || ip.addr == {m['ip']}"
    if k == "icmp_unreachable":
        return f"ip.src == {m['reporter']} && (icmp.type == 3 || icmp.type == 11)"
    if k in ("dhcp_failure", "dhcp_starvation"):
        return "dhcp"
    if k == "fragment_attack":
        return f"ip.src == {m['src']} && (ip.flags.mf == 1 || ip.frag_offset > 0)"
    return None


def exact_filter(packet_ids: list[int]) -> str:
    """Selects exactly the cited packets (Wireshark 3.x+ set membership)."""
    if not packet_ids:
        return ""
    return "frame.number in {" + " ".join(str(i) for i in packet_ids) + "}"
