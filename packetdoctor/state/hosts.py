"""Who is who on the local network.

Tracks which MAC addresses use which IPs (from ARP and from IP traffic),
whether ARP replies were asked for, and infers the gateway and DNS servers.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from ..models import TCP_ACK, TCP_SYN, PacketRecord
from ..utils import is_private_ip, is_unicast_ipv4, subnet24
from .lru import LRUDict, add_capped

SOLICIT_WINDOW = 3.0  # seconds an ARP request stays "open"
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


@dataclass(slots=True)
class Usage:
    """How one MAC has used one IP."""

    first_ts: float
    last_ts: float
    ip_packets: int = 0
    originated: int = 0  # SYNs / DNS queries / ARP requests: acting like a normal host
    arp_requests: int = 0
    arp_replies: int = 0
    unsolicited_replies: int = 0
    gratuitous: int = 0
    ids: list = field(default_factory=list)


@dataclass(slots=True)
class ArpEvent:
    kind: str  # request | probe | gratuitous | reply | unsolicited_reply
    ip: str
    mac: str
    previous_macs: tuple = ()  # other MACs recently bound to this IP


class HostTable:
    def __init__(self, max_hosts: int):
        self.ip_macs: LRUDict[str, dict[str, Usage]] = LRUDict(max_hosts)
        self.mac_external_ips: LRUDict[str, set] = LRUDict(max_hosts)
        self.arp_target_counts: Counter = Counter()  # IP -> how many times asked for (by distinct askers)
        self._askers: dict[str, set] = {}
        self.pending: LRUDict[tuple, float] = LRUDict(50_000)  # (asker ip, target ip) -> ts
        self.local_nets: set[str] = set()
        self.dhcp_routers: Counter = Counter()

    # --- updates ---------------------------------------------------------------

    def _usage(self, ip: str, mac: str, ts: float) -> Usage:
        macs = self.ip_macs.get_or_create(ip, dict)
        u = macs.get(mac)
        if u is None:
            if len(macs) >= 16:
                return Usage(ts, ts)  # absurd number of MACs: stop recording, but don't crash
            u = macs[mac] = Usage(first_ts=ts, last_ts=ts)
        u.last_ts = ts
        return u

    def recent_macs(self, ip: str, exclude: str) -> tuple:
        return tuple(m for m in self.ip_macs.get(ip, {}) if m != exclude)

    def on_arp(self, rec: PacketRecord) -> ArpEvent | None:
        a = rec.arp
        if not a.hwsrc:
            return None
        if a.op == 1 and a.psrc == "0.0.0.0":
            # RFC 5227 probe: "is anyone using this address?"
            self.pending.put(("0.0.0.0", a.pdst), rec.ts)
            return ArpEvent(kind="probe", ip=a.pdst, mac=a.hwsrc, previous_macs=self.recent_macs(a.pdst, a.hwsrc))
        if not is_unicast_ipv4(a.psrc):
            return None
        self.local_nets.add(subnet24(a.psrc))
        previous = self.recent_macs(a.psrc, a.hwsrc)
        u = self._usage(a.psrc, a.hwsrc, rec.ts)
        add_capped(u.ids, rec.idx, 50)
        if a.op == 1:
            if a.psrc == a.pdst:
                u.gratuitous += 1
                return ArpEvent(kind="gratuitous", ip=a.psrc, mac=a.hwsrc, previous_macs=previous)
            u.arp_requests += 1
            u.originated += 1
            self.pending.put((a.psrc, a.pdst), rec.ts)
            askers = self._askers.setdefault(a.pdst, set())
            if len(askers) < 64:
                askers.add(a.psrc)
            self.arp_target_counts[a.pdst] = len(askers)
            return ArpEvent(kind="request", ip=a.psrc, mac=a.hwsrc, previous_macs=previous)
        # reply
        u.arp_replies += 1
        if a.psrc == a.pdst or rec.dst_mac == BROADCAST_MAC:
            u.gratuitous += 1
            return ArpEvent(kind="gratuitous", ip=a.psrc, mac=a.hwsrc, previous_macs=previous)
        asked = self.pending.get((a.pdst, a.psrc))
        probe = self.pending.get(("0.0.0.0", a.psrc))
        if (asked is not None and rec.ts - asked <= SOLICIT_WINDOW) or (probe is not None and rec.ts - probe <= SOLICIT_WINDOW):
            return ArpEvent(kind="reply", ip=a.psrc, mac=a.hwsrc, previous_macs=previous)
        u.unsolicited_replies += 1
        return ArpEvent(kind="unsolicited_reply", ip=a.psrc, mac=a.hwsrc, previous_macs=previous)

    def on_ip(self, rec: PacketRecord) -> None:
        if not rec.src_mac or not rec.src_ip or rec.ip_version != 4:
            return
        if self.is_local(rec.src_ip):
            u = self._usage(rec.src_ip, rec.src_mac, rec.ts)
            u.ip_packets += 1
            flags = rec.tcp_flags or 0
            if (flags & TCP_SYN and not flags & TCP_ACK) or (rec.dns and not rec.dns.is_response):
                u.originated += 1
                add_capped(u.ids, rec.idx, 50)
        elif is_unicast_ipv4(rec.src_ip) and not is_private_ip(rec.src_ip):
            ext = self.mac_external_ips.get_or_create(rec.src_mac, set)
            if len(ext) < 1000:
                ext.add(rec.src_ip)
        if rec.dhcp and rec.dhcp.router and rec.dhcp.msg_type == 5:
            self.dhcp_routers[rec.dhcp.router] += 1

    # --- queries ---------------------------------------------------------------

    def is_local(self, ip: str | None) -> bool:
        if not ip or not is_unicast_ipv4(ip):
            return False
        if self.local_nets:
            return subnet24(ip) in self.local_nets
        return is_private_ip(ip)

    def gateway(self) -> tuple[str | None, str | None]:
        """(gateway IP, gateway MAC). The gateway MAC is the one that delivers
        traffic from the most distinct internet addresses; its IP is the local
        address that MAC has used the longest."""
        gw_mac = None
        if self.mac_external_ips:
            gw_mac, ext = max(self.mac_external_ips.items(), key=lambda kv: len(kv[1]))
            if len(ext) < 2:
                gw_mac = None
        gw_ip = None
        if gw_mac:
            owned = [(ip, macs[gw_mac]) for ip, macs in self.ip_macs.items() if gw_mac in macs]
            if owned:
                gw_ip = min(owned, key=lambda kv: kv[1].first_ts)[0]
        if gw_ip is None and self.arp_target_counts:
            gw_ip = self.arp_target_counts.most_common(1)[0][0]
        if gw_ip is None and self.dhcp_routers:
            gw_ip = self.dhcp_routers.most_common(1)[0][0]
        return gw_ip, gw_mac

    def macs_for(self, ip: str) -> dict[str, Usage]:
        return dict(self.ip_macs.get(ip, {}))

    def ips_for_mac(self, mac: str) -> list[str]:
        return [ip for ip, macs in self.ip_macs.items() if mac in macs]

    def primary_mac(self, ip: str) -> str | None:
        """The MAC that used this IP first (the 'original owner')."""
        macs = self.ip_macs.get(ip)
        if not macs:
            return None
        return min(macs.items(), key=lambda kv: kv[1].first_ts)[0]
