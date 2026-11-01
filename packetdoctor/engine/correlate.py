"""Group symptoms into incidents and work out what caused what.

Detectors report *symptoms*. Several symptoms are often one problem seen from
different angles (an ARP conflict and a duplicate IP), or a chain where one
problem causes another (ARP spoofing -> the victim's retransmissions). This
module links them with explicit, explainable rules:

    cause --(rule, reason)--> effect

Rules only point from a higher-ranked kind to a lower-ranked one, so the graph
is acyclic. Every symptom that is not the effect of anything becomes the root
of an incident; its descendants become that incident's consequences.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from ..models import Symptom

# Higher rank = more fundamental. Causes must outrank their effects.
RANK = {
    "arp_spoofing": 10,
    "rogue_dhcp": 10,
    "dhcp_starvation": 9,
    "dns_hijack": 8,
    "port_scan": 8,
    "fragment_attack": 8,
    "duplicate_ip": 7,
    "dhcp_failure": 5,
    "host_unreachable": 6,
    "mtu_blackhole": 6,
    "arp_storm": 5,
    "arp_sweep": 5,
    "mtu_mismatch": 5,
    "dns_failure": 5,
    "arp_conflict": 4,
    "icmp_unreachable": 3,
    "tcp_connection_refused": 3,
    "tcp_connection_aborted": 3,
    "tcp_retransmissions": 2,
    "high_latency": 1,
    "tcp_zero_window": 1,
}

SLACK = 5.0  # seconds of tolerance when comparing time ranges


def overlaps(a: Symptom, b: Symptom, slack: float = SLACK) -> bool:
    return b.t_start <= a.t_end + slack and b.t_end >= a.t_start - slack


def _ips(s: Symptom) -> set[str]:
    return {h for h in s.hosts if h.count(".") == 3}


def _macs(s: Symptom) -> set[str]:
    return {h for h in s.hosts if h.count(":") == 5}


# --- rule predicates: (cause, effect) -> bool ----------------------------------------


def _spoof_affects(cause: Symptom, effect: Symptom) -> bool:
    victims = set(cause.metrics.get("victims", [])) | set(cause.metrics.get("impersonated", {}))
    return bool(victims & _ips(effect)) and overlaps(cause, effect)


def _spoof_same_device(cause: Symptom, effect: Symptom) -> bool:
    mac = cause.metrics.get("attacker_mac")
    ip = effect.metrics.get("ip")
    return overlaps(cause, effect) and ((mac in _macs(effect)) or ip in cause.metrics.get("impersonated", {}))


def _dup_ip_affects(cause: Symptom, effect: Symptom) -> bool:
    return cause.metrics.get("ip") in _ips(effect) and overlaps(cause, effect)


def _same_ip_conflict(cause: Symptom, effect: Symptom) -> bool:
    return cause.metrics.get("ip") == effect.metrics.get("ip") and overlaps(cause, effect)


def _same_path(cause: Symptom, effect: Symptom) -> bool:
    pair = {cause.metrics.get("src"), cause.metrics.get("dst")}
    other = {effect.metrics.get("client"), effect.metrics.get("server")} | {effect.metrics.get("src"), effect.metrics.get("dst")}
    return None not in pair and len(pair & other) == 2 and overlaps(cause, effect)


def _mtu_aborts(cause: Symptom, effect: Symptom) -> bool:
    return cause.metrics.get("dst") == effect.metrics.get("server") and overlaps(cause, effect)


def _dns_slow(cause: Symptom, effect: Symptom) -> bool:
    return (
        effect.metrics.get("what", "").startswith("DNS")
        and cause.metrics.get("server") in effect.metrics.get("servers", [])
        and overlaps(cause, effect)
    )


def _rogue_dns(cause: Symptom, effect: Symptom) -> bool:
    rogue = {cause.metrics.get("rogue_server"), *cause.metrics.get("rogue_dns", []), *cause.metrics.get("rogue_mac", [])}
    return bool({effect.metrics.get("suspect"), effect.metrics.get("claimed_resolver")} & rogue) and overlaps(cause, effect)


def _scan_refused(cause: Symptom, effect: Symptom) -> bool:
    return cause.metrics.get("scanner") in effect.metrics.get("clients", []) and overlaps(cause, effect)


def _starvation_blocks(cause: Symptom, effect: Symptom) -> bool:
    return overlaps(cause, effect, slack=120)


def _starvation_then_rogue(cause: Symptom, effect: Symptom) -> bool:
    senders = set(cause.metrics.get("sent_from", []))
    return bool(senders & set(effect.metrics.get("rogue_mac", []))) and overlaps(cause, effect, slack=120)


def _unreachable_server(cause: Symptom, effect: Symptom) -> bool:
    ip = cause.metrics.get("ip")
    return ip in (effect.metrics.get("server"), *effect.metrics.get("servers", [])) and overlaps(cause, effect, slack=30)


def _gateway_down_dhcp(cause: Symptom, effect: Symptom) -> bool:
    return bool(cause.metrics.get("is_gateway")) and overlaps(cause, effect, slack=30)


@dataclass(frozen=True)
class Rule:
    cause: str
    effect: str
    match: Callable[[Symptom, Symptom], bool]
    reason: str
    same_problem: bool = False  # effect is the same problem seen another way, not a consequence


RULES = [
    Rule("arp_spoofing", "arp_conflict", _spoof_same_device, "The address conflict is created by the forged ARP replies", True),
    Rule("arp_spoofing", "duplicate_ip", _spoof_same_device, "The 'duplicate' address is the attacker posing as another device", True),
    Rule("arp_spoofing", "tcp_retransmissions", _spoof_affects, "Traffic now detours through the attacker's device, which delays and drops packets"),
    Rule("arp_spoofing", "high_latency", _spoof_affects, "Traffic now detours through the attacker's device, adding delay"),
    Rule("arp_spoofing", "tcp_connection_aborted", _spoof_affects, "Connections break while the attacker sits in the middle"),
    Rule("rogue_dhcp", "dns_hijack", _rogue_dns, "Devices that took the rogue DHCP settings now ask the attacker for DNS"),
    Rule("port_scan", "tcp_connection_refused", _scan_refused, "The rejected connections are the scanner's probes"),
    Rule("duplicate_ip", "arp_conflict", _same_ip_conflict, "Both findings describe the same address being used twice", True),
    Rule("duplicate_ip", "tcp_connection_aborted", _dup_ip_affects, "Replies for one device are delivered to the other, which resets the connection"),
    Rule("duplicate_ip", "tcp_retransmissions", _dup_ip_affects, "Packets go to the wrong device half the time and must be re-sent"),
    Rule("mtu_blackhole", "tcp_retransmissions", _same_path, "The re-sent packets are the large ones the path keeps dropping"),
    Rule("mtu_blackhole", "tcp_connection_aborted", _mtu_aborts, "Connections give up after their large packets never get through"),
    Rule("mtu_mismatch", "tcp_retransmissions", _same_path, "Packets were too large for the path and had to be re-sent smaller"),
    Rule("dns_failure", "high_latency", _dns_slow, "DNS answers are slow because the DNS server is struggling"),
    Rule("dhcp_starvation", "dhcp_failure", _starvation_blocks, "The flood of fake requests used up the address pool, so real devices get nothing"),
    Rule("rogue_dhcp", "dhcp_starvation", _starvation_then_rogue, "Starving the real DHCP server first is how a rogue server makes sure its offers win"),
    Rule("host_unreachable", "dns_failure", _unreachable_server, "The DNS server cannot even be reached on the local network"),
    Rule("host_unreachable", "tcp_retransmissions", _unreachable_server, "Packets keep being re-sent to a device that has gone silent"),
    Rule("host_unreachable", "dhcp_failure", _gateway_down_dhcp, "The router that hands out addresses is the device that has gone silent"),
]


@dataclass
class Link:
    cause: int
    effect: int
    reason: str
    same_problem: bool


@dataclass
class Group:
    root: Symptom
    related: list[Symptom] = field(default_factory=list)  # same problem, other view
    consequences: list[tuple[Symptom, str]] = field(default_factory=list)


def correlate(symptoms: list[Symptom]) -> list[Group]:
    rules_by_pair: dict[tuple[str, str], list[Rule]] = {}
    for r in RULES:
        rules_by_pair.setdefault((r.cause, r.effect), []).append(r)

    # choose, for every symptom, the best parent (highest-ranked cause)
    parent: dict[int, Link] = {}
    for ei, effect in enumerate(symptoms):
        best: Link | None = None
        best_rank = -1
        for ci, cause in enumerate(symptoms):
            if ci == ei or RANK.get(cause.kind, 0) <= RANK.get(effect.kind, 0):
                continue
            for rule in rules_by_pair.get((cause.kind, effect.kind), []):
                if rule.match(cause, effect) and RANK.get(cause.kind, 0) > best_rank:
                    best, best_rank = Link(ci, ei, rule.reason, rule.same_problem), RANK.get(cause.kind, 0)
        if best is not None:
            parent[ei] = best

    def root_of(i: int) -> int:
        seen = set()
        while i in parent and i not in seen:
            seen.add(i)
            i = parent[i].cause
        return i

    groups: dict[int, Group] = {}
    for i, s in enumerate(symptoms):
        if i not in parent:
            groups[i] = Group(root=s)
    for i, s in enumerate(symptoms):
        if i in parent:
            link = parent[i]
            g = groups[root_of(i)]
            if link.same_problem and link.cause == root_of(i):
                g.related.append(s)
            else:
                g.consequences.append((s, link.reason))
    return sorted(groups.values(), key=lambda g: g.root.t_start)
