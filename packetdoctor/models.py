"""Data model shared by every stage of the pipeline.

Detectors only see ``PacketRecord`` (never raw Scapy packets), so the
detection logic is independent of the capture library. No payload bytes are
kept, only header fields.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

# --- Decoded packets --------------------------------------------------------


@dataclass(slots=True)
class DnsAnswer:
    name: str
    rtype: int
    data: str
    ttl: int


@dataclass(slots=True)
class DnsInfo:
    txid: int
    is_response: bool
    qname: str
    qtype: int
    rcode: int
    answers: list[DnsAnswer] = field(default_factory=list)


@dataclass(slots=True)
class ArpInfo:
    op: int  # 1 = request, 2 = reply
    hwsrc: str
    psrc: str
    hwdst: str
    pdst: str


@dataclass(slots=True)
class DhcpInfo:
    msg_type: int  # 1 discover, 2 offer, 3 request, 5 ack, 6 nak
    xid: int
    client_mac: str
    yiaddr: str
    server_id: str | None = None
    router: str | None = None
    dns_servers: list[str] = field(default_factory=list)
    requested_ip: str | None = None


@dataclass(slots=True)
class PacketRecord:
    idx: int  # 1-based, same numbering as Wireshark's "No." column
    ts: float
    length: int
    src_mac: str | None = None
    dst_mac: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    ip_version: int | None = None
    ip_proto: int | None = None
    ttl: int | None = None
    df: bool = False
    ip_id: int | None = None
    frag_offset: int = 0  # bytes
    more_fragments: bool = False
    frag_len: int | None = None  # payload bytes carried by this fragment
    sport: int | None = None
    dport: int | None = None
    # TCP
    tcp_flags: int | None = None
    seq: int | None = None
    ack: int | None = None
    payload_len: int = 0
    window: int | None = None
    mss: int | None = None
    # ICMP
    icmp_type: int | None = None
    icmp_code: int | None = None
    icmp_mtu: int | None = None  # next-hop MTU (frag needed / packet too big)
    icmp_inner: tuple | None = None  # (src, dst, proto, sport, dport) of quoted packet
    # Higher layers
    dns: DnsInfo | None = None
    arp: ArpInfo | None = None
    dhcp: DhcpInfo | None = None

    @property
    def is_tcp(self) -> bool:
        return self.tcp_flags is not None

    def has_flag(self, flag: int) -> bool:
        return self.tcp_flags is not None and bool(self.tcp_flags & flag)

    def summary(self) -> str:
        """One-line, Wireshark-like description used in evidence tables."""
        if self.arp:
            a = self.arp
            if a.op == 1:
                return f"ARP who-has {a.pdst}? tell {a.psrc} ({a.hwsrc})"
            return f"ARP reply {a.psrc} is-at {a.hwsrc}"
        if self.dhcp:
            names = {1: "Discover", 2: "Offer", 3: "Request", 4: "Decline", 5: "ACK", 6: "NAK", 7: "Release", 8: "Inform"}
            d = self.dhcp
            extra = f" offer={d.yiaddr} router={d.router} dns={','.join(d.dns_servers)}" if d.msg_type in (2, 5) else ""
            return f"DHCP {names.get(d.msg_type, d.msg_type)} xid=0x{d.xid:x}{extra}"
        if self.dns:
            d = self.dns
            if not d.is_response:
                return f"DNS query 0x{d.txid:04x} {d.qname}"
            rcode = RCODE_NAMES.get(d.rcode, str(d.rcode))
            ans = ", ".join(a.data for a in d.answers[:3])
            return f"DNS response 0x{d.txid:04x} {d.qname} {rcode} {ans}".rstrip()
        if self.frag_len is not None:
            return f"IP fragment id=0x{self.ip_id or 0:04x} offset={self.frag_offset} len={self.frag_len}{' MF' if self.more_fragments else ''}"
        if self.icmp_type is not None:
            base = f"ICMP type={self.icmp_type} code={self.icmp_code}"
            if self.icmp_mtu:
                base += f" (fragmentation needed, next-hop MTU {self.icmp_mtu})"
            return base
        if self.is_tcp:
            flags = tcp_flag_str(self.tcp_flags or 0)
            return f"TCP {self.sport} > {self.dport} [{flags}] seq={self.seq} ack={self.ack} len={self.payload_len}"
        if self.sport is not None:
            return f"UDP {self.sport} > {self.dport} len={self.payload_len}"
        return f"Frame length {self.length}"


TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK = 0x01, 0x02, 0x04, 0x08, 0x10
RCODE_NAMES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


def tcp_flag_str(flags: int) -> str:
    names = [(TCP_SYN, "SYN"), (TCP_ACK, "ACK"), (TCP_FIN, "FIN"), (TCP_RST, "RST"), (TCP_PSH, "PSH")]
    return ",".join(n for bit, n in names if flags & bit) or "none"


# --- Findings ---------------------------------------------------------------


class Category(str, Enum):
    FAULT = "fault"
    ATTACK = "attack"


class Verdict(str, Enum):
    FAULT = "FAULT"
    ATTACK = "ATTACK"
    UNCERTAIN = "UNCERTAIN"


@dataclass
class Evidence:
    """A reason that pushes a finding towards 'attack' or towards 'benign fault'."""

    text: str
    weight: float  # 0..1, how strong this indicator is


@dataclass
class Symptom:
    """Raw output of one detector: something specific observed in the capture."""

    kind: str  # e.g. "tcp_retransmissions", "arp_spoofing"
    category: Category  # what the detector is designed to find
    severity: int  # 1 (info) .. 5 (critical)
    title: str
    t_start: float
    t_end: float
    hosts: list[str] = field(default_factory=list)  # IPs/MACs involved
    packet_ids: list[int] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    attack_evidence: list[Evidence] = field(default_factory=list)
    benign_evidence: list[Evidence] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["category"] = self.category.value
        return d


@dataclass
class IngestStats:
    file_name: str = ""
    file_format: str = ""
    file_bytes: int = 0
    packets_read: int = 0
    packets_decoded: int = 0
    malformed: int = 0
    truncated: bool = False
    timed_out: bool = False
    packet_limit_hit: bool = False
    first_ts: float | None = None
    last_ts: float | None = None
    warnings: list[str] = field(default_factory=list)

    @property
    def duration(self) -> float:
        if self.first_ts is None or self.last_ts is None:
            return 0.0
        return max(0.0, self.last_ts - self.first_ts)
