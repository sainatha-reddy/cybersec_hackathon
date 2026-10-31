from __future__ import annotations

from collections import defaultdict

from ...models import Category, Evidence, Symptom
from ..base import Detector

OFFER, ACK = 2, 5


class RogueDhcpDetector(Detector):
    """More than one DHCP server handing out addresses.

    The 'real' server is the one that matches the gateway, was seen first, or
    has handed out the most leases. Any other server is examined: if it gives
    clients a different gateway or DNS server (especially itself), clients that
    accept its offer will send their traffic to it."""

    name = "rogue_dhcp"

    def __init__(self, settings):
        super().__init__(settings)
        self.servers = {}
        self.discover_ts = {}  # xid -> ts of DISCOVER
        self.offer_delay = defaultdict(list)

    def on_packet(self, rec, ctx, state):
        d = rec.dhcp
        if d is None:
            return
        if d.msg_type == 1:
            self.discover_ts[d.xid] = rec.ts
            if len(self.discover_ts) > 10_000:
                self.discover_ts.clear()
            return
        if d.msg_type not in (OFFER, ACK):
            return
        sid = d.server_id or rec.src_ip
        if not sid:
            return
        s = self.servers.get(sid)
        if s is None:
            if len(self.servers) >= 64:
                return
            s = self.servers[sid] = {
                "first_ts": rec.ts, "last_ts": rec.ts, "offers": 0, "acks": 0, "routers": set(), "dns": set(),
                "clients": set(), "acked_clients": set(), "ids": [], "macs": set(),
            }
        s["last_ts"] = rec.ts
        s["offers" if d.msg_type == OFFER else "acks"] += 1
        if d.router:
            s["routers"].add(d.router)
        s["dns"].update(d.dns_servers)
        s["clients"].add(d.client_mac)
        if d.msg_type == ACK:
            s["acked_clients"].add(d.client_mac)
        if rec.src_mac:
            s["macs"].add(rec.src_mac)
        if len(s["ids"]) < self.max_ids:
            s["ids"].append(rec.idx)
        if d.msg_type == OFFER and d.xid in self.discover_ts:
            self.offer_delay[sid].append(rec.ts - self.discover_ts[d.xid])

    def finalize(self, state):
        if len(self.servers) < 2:
            return []
        gw_ip, _ = state.hosts.gateway()

        def legit_score(item):
            sid, s = item
            return (
                2 * (sid == gw_ip) + 1 * (gw_ip in s["routers"]) + 0.5 * len(s["acked_clients"]) / 10,
                -s["first_ts"],
            )

        legit_id, legit = max(self.servers.items(), key=legit_score)
        out = []
        for sid, s in self.servers.items():
            if sid == legit_id:
                continue
            routers, dns = sorted(s["routers"]), sorted(s["dns"])
            sym = Symptom(
                kind=self.name,
                category=Category.ATTACK,
                severity=5 if s["acked_clients"] else 4,
                title=f"Unauthorised DHCP server {sid} is handing out network settings",
                t_start=s["first_ts"],
                t_end=s["last_ts"],
                hosts=[sid, *sorted(s["macs"]), *routers, *dns],
                packet_ids=self.ids(s["ids"]),
                metrics={
                    "rogue_server": sid,
                    "rogue_mac": sorted(s["macs"]),
                    "legit_server": legit_id,
                    "rogue_router": routers,
                    "rogue_dns": dns,
                    "legit_router": sorted(legit["routers"]),
                    "legit_dns": sorted(legit["dns"]),
                    "offers": s["offers"],
                    "clients_accepted": len(s["acked_clients"]),
                    "clients_targeted": len(s["clients"]),
                },
                attack_evidence=[Evidence(f"A second DHCP server ({sid}) answers besides the network's real one ({legit_id})", 0.3)],
            )
            if routers and set(routers) != set(legit["routers"]):
                sym.attack_evidence.append(Evidence(f"It tells devices to use {', '.join(routers)} as their gateway instead of {', '.join(sorted(legit['routers'])) or legit_id}", 0.35))
            if dns and set(dns) != set(legit["dns"]):
                sym.attack_evidence.append(Evidence(f"It tells devices to use {', '.join(dns)} for DNS, so it can redirect websites", 0.25))
            if sid in routers or sid in dns:
                sym.attack_evidence.append(Evidence("It points devices at itself, putting itself in the middle of their traffic", 0.2))
            mine, theirs = self.offer_delay.get(sid), self.offer_delay.get(legit_id)
            if mine and theirs and min(mine) < min(theirs):
                sym.attack_evidence.append(Evidence(f"It answers faster ({min(mine) * 1000:.0f} ms vs {min(theirs) * 1000:.0f} ms) so its offer wins", 0.1))
            if s["acked_clients"]:
                sym.attack_evidence.append(Evidence(f"{len(s['acked_clients'])} device(s) accepted its settings", 0.1))
            if set(routers) <= set(legit["routers"]) and set(dns) <= set(legit["dns"]):
                sym.benign_evidence.append(Evidence("It hands out the same gateway and DNS as the main server: probably a backup DHCP server or a home router plugged in by mistake", 0.6))
            out.append(sym)
        return out
