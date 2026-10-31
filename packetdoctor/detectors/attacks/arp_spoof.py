from __future__ import annotations

import statistics
from collections import defaultdict

from ...models import Category, Evidence, Symptom
from ..base import Detector


class ArpSpoofDetector(Detector):
    """ARP spoofing / poisoning: a device sends ARP replies claiming an IP
    that belongs to someone else (usually the gateway) so that traffic is sent
    to it instead.

    Signals that separate it from an honest address change: replies nobody
    asked for, sent on a timer; one MAC claiming several IPs; the IP being the
    gateway; and, most tellingly, the claiming device relaying the victims'
    traffic onwards (packets seen twice with its MAC as the second sender)."""

    name = "arp_spoofing"

    def __init__(self, settings):
        super().__init__(settings)
        self.claims = defaultdict(lambda: defaultdict(lambda: {"unsolicited": 0, "solicited": 0, "gratuitous": 0, "ts": [], "ids": [], "victims": set()}))

    def on_packet(self, rec, ctx, state):
        ev = ctx.arp
        if ev is None or ev.kind not in ("reply", "unsolicited_reply", "gratuitous"):
            return
        c = self.claims[ev.mac][ev.ip]
        key = {"reply": "solicited", "unsolicited_reply": "unsolicited", "gratuitous": "gratuitous"}[ev.kind]
        c[key] += 1
        if len(c["ts"]) < 5000:
            c["ts"].append(rec.ts)
        if len(c["ids"]) < self.max_ids:
            c["ids"].append(rec.idx)
        if rec.arp.pdst and rec.arp.pdst != ev.ip and len(c["victims"]) < 64:
            c["victims"].add(rec.arp.pdst)

    def finalize(self, state):
        hosts = state.hosts
        gw_ip, gw_mac = hosts.gateway()
        out = []
        for mac, ips in self.claims.items():
            stolen = {}
            for ip, c in ips.items():
                owner = hosts.primary_mac(ip)
                if owner is not None and owner != mac:
                    stolen[ip] = (c, owner)
            if not stolen:
                continue
            relay = state.relay.by_mac.get(mac)
            unsolicited = sum(c["unsolicited"] for c, _ in stolen.values())
            if unsolicited < self.t.arp_unsolicited_min and not (relay and relay.count):
                continue  # a few honest replies (e.g. failover) are left to the conflict detectors

            all_ts = sorted(t for c, _ in stolen.values() for t in c["ts"])
            victims = sorted({v for c, _ in stolen.values() for v in c["victims"]})
            own_ips = [ip for ip in hosts.ips_for_mac(mac) if ip not in stolen and hosts.primary_mac(ip) == mac]
            claims_gateway = gw_ip in stolen
            sym = Symptom(
                kind=self.name,
                category=Category.ATTACK,
                severity=5 if claims_gateway and relay else 4,
                title=(
                    f"Device {mac} is impersonating the gateway {gw_ip}"
                    if claims_gateway
                    else f"Device {mac} is impersonating {', '.join(sorted(stolen))}"
                ),
                t_start=all_ts[0],
                t_end=all_ts[-1],
                hosts=[mac, *own_ips, *sorted(stolen), *victims],
                packet_ids=self.ids(*(c["ids"] for c, _ in stolen.values()), relay.ids[:10] if relay else []),
                metrics={
                    "attacker_mac": mac,
                    "attacker_ips": own_ips,
                    "impersonated": {ip: owner for ip, (_, owner) in stolen.items()},
                    "victims": victims,
                    "unsolicited_replies": unsolicited,
                    "relayed_packets": relay.count if relay else 0,
                    "gateway_targeted": claims_gateway,
                },
            )
            for ip, (c, owner) in stolen.items():
                sym.attack_evidence.append(Evidence(f"Claims {ip} belongs to it, but {ip} is really {owner}", 0.3))
            if unsolicited >= self.t.arp_unsolicited_min:
                sym.attack_evidence.append(Evidence(f"Sent {unsolicited} ARP replies that nobody asked for", 0.3))
            if len(all_ts) >= 4:
                gaps = [b - a for a, b in zip(all_ts, all_ts[1:]) if b - a > 0.05]
                if len(gaps) >= 3:
                    med = statistics.median(gaps)
                    spread = statistics.pstdev(gaps) / med if med else 1
                    if spread < 0.25:
                        sym.attack_evidence.append(Evidence(f"The forged replies repeat like clockwork every {med:.1f} s: the pattern of a poisoning tool", 0.2))
            if len(stolen) >= 2 or own_ips:
                sym.attack_evidence.append(Evidence(f"One device claims {len(stolen) + len(own_ips)} different IP addresses", 0.2))
            if claims_gateway:
                sym.attack_evidence.append(Evidence("The impersonated address is the gateway, so all internet traffic can be intercepted", 0.3))
            if relay and relay.count:
                sym.attack_evidence.append(
                    Evidence(f"It forwards other devices' traffic onwards ({relay.count} relayed packets): a man-in-the-middle", 0.5)
                )
            if not relay and unsolicited < 2 * self.t.arp_unsolicited_min and len(stolen) == 1:
                sym.benign_evidence.append(Evidence("Few replies and no traffic interception: could be a device replacement or router failover", 0.4))
            out.append(sym)
        return out
