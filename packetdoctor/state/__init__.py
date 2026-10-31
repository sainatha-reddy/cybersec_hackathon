"""Shared network state, updated once per packet before detectors run."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from ..config import Settings
from ..models import PacketRecord
from .dns import DnsEvent, DnsTracker
from .flows import FlowTable, TcpEvent
from .hosts import ArpEvent, HostTable
from .relay import RelayTracker


@dataclass(slots=True)
class PacketContext:
    """What the state layer learned from one packet, handed to every detector."""

    relayed: bool = False
    tcp: TcpEvent | None = None
    dns: DnsEvent | None = None
    arp: ArpEvent | None = None


class NetworkState:
    def __init__(self, settings: Settings):
        lim = settings.limits
        self.settings = settings
        self.flows = FlowTable(lim.max_flows)
        self.dns = DnsTracker(lim.max_flows)
        self.hosts = HostTable(lim.max_hosts)
        self.relay = RelayTracker()
        self.first_ts: float | None = None
        self.last_ts: float | None = None
        self.packets = 0
        self.bytes = 0
        self.per_second: Counter = Counter()  # traffic volume for the timeline
        self.protocols: Counter = Counter()

    def update(self, rec: PacketRecord) -> PacketContext:
        self.packets += 1
        self.bytes += rec.length
        if self.first_ts is None or rec.ts < self.first_ts:
            self.first_ts = rec.ts
        if self.last_ts is None or rec.ts > self.last_ts:
            self.last_ts = rec.ts
        if len(self.per_second) < 200_000:
            self.per_second[int(rec.ts)] += 1
        self.protocols[_proto_name(rec)] += 1

        ctx = PacketContext()
        if rec.arp:
            ctx.arp = self.hosts.on_arp(rec)
            return ctx
        ctx.relayed = self.relay.check(rec)
        if ctx.relayed:
            return ctx
        if rec.src_ip:
            self.hosts.on_ip(rec)
        if rec.is_tcp and rec.src_ip and rec.dst_ip:
            ctx.tcp = self.flows.update(rec)
        if rec.dns:
            ctx.dns = self.dns.update(rec)
        return ctx

    @property
    def duration(self) -> float:
        if self.first_ts is None or self.last_ts is None:
            return 0.0
        return self.last_ts - self.first_ts


def _proto_name(rec: PacketRecord) -> str:
    if rec.arp:
        return "ARP"
    if rec.dhcp:
        return "DHCP"
    if rec.dns:
        return "DNS"
    if rec.icmp_type is not None:
        return "ICMP"
    if rec.is_tcp:
        return "TCP"
    if rec.sport is not None:
        return "UDP"
    return "Other"


__all__ = ["NetworkState", "PacketContext", "ArpEvent", "DnsEvent", "TcpEvent"]
