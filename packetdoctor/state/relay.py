"""Detect packets that are seen twice on the wire, re-sent by a different MAC.

When a device sits in the middle of a conversation (ARP-spoofing MITM, or a
misbehaving bridge), every packet appears once on its way *to* that device
and again a moment later on its way *from* it, with identical IP/TCP headers
but a different source MAC. Those copies are not real retransmissions, so
they are filtered out of flow statistics and reported as relay evidence.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from ..models import PacketRecord
from .lru import LRUDict, add_capped

RELAY_WINDOW = 0.05  # seconds


@dataclass(slots=True)
class RelayStats:
    count: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    ids: list = field(default_factory=list)
    original_senders: Counter = field(default_factory=Counter)  # MACs whose packets were relayed
    conversations: Counter = field(default_factory=Counter)  # (src ip, dst ip)


class RelayTracker:
    def __init__(self, maxlen: int = 8192):
        self.recent: LRUDict[tuple, tuple] = LRUDict(maxlen)
        self.by_mac: dict[str, RelayStats] = {}

    @staticmethod
    def fingerprint(rec: PacketRecord) -> tuple | None:
        if rec.src_ip is None or rec.src_mac is None:
            return None
        if rec.is_tcp:
            extra = (rec.seq, rec.ack, rec.tcp_flags, rec.window)
        elif rec.dns:
            extra = ("dns", rec.dns.txid, rec.dns.is_response)
        elif rec.icmp_type is not None:
            extra = ("icmp", rec.icmp_type, rec.icmp_code)
        else:
            extra = ()
        return (rec.src_ip, rec.dst_ip, rec.ip_proto, rec.sport, rec.dport, rec.payload_len, rec.ttl is not None) + extra

    def check(self, rec: PacketRecord) -> bool:
        fp = self.fingerprint(rec)
        if fp is None:
            return False
        prev = self.recent.get(fp)
        self.recent.put(fp, (rec.ts, rec.src_mac))
        if prev is None:
            return False
        prev_ts, prev_mac = prev
        if prev_mac == rec.src_mac or rec.ts - prev_ts > RELAY_WINDOW:
            return False
        st = self.by_mac.get(rec.src_mac)
        if st is None:
            if len(self.by_mac) >= 256:
                return True
            st = self.by_mac[rec.src_mac] = RelayStats(first_ts=rec.ts)
        st.count += 1
        st.last_ts = rec.ts
        add_capped(st.ids, rec.idx, 50)
        st.original_senders[prev_mac] += 1
        if len(st.conversations) < 256:
            st.conversations[(rec.src_ip, rec.dst_ip)] += 1
        return True
