from __future__ import annotations

from collections import defaultdict

from ...models import Category, Evidence, Symptom
from ..base import Detector, track_span

# ICMP destination-unreachable codes grouped by what they mean for a user
NO_ROUTE = {0, 1, 5, 6, 7, 8, 11, 12}
PORT_CLOSED = {3}
BLOCKED = {9, 10, 13}
ICMP_GROUPS = {
    "no_route": ("has no route to", 3, 3),
    "blocked": ("is blocking traffic to", 3, 3),
    "port_closed": ("reports closed ports on", 2, 5),
    "ttl_expired": ("reports packets expiring (TTL exceeded) on the way to", 2, 10),
}
SWEEPER_TARGETS = 30


class UnreachableDetector(Detector):
    """Devices that cannot be reached.

    * host_unreachable: an address is asked for over ARP again and again and
      nobody ever answers: the device is off, unplugged or misconfigured.
      When that address is the gateway, nothing on the network can reach the
      internet.
    * icmp_unreachable: routers/hosts report that destinations cannot be
      reached (no route, blocked, closed port) or that packets expire in transit."""

    name = "unreachable"

    def __init__(self, settings):
        super().__init__(settings)
        self.asks = defaultdict(lambda: {"n": 0, "askers": set(), "ids": [], "t": [], "ts": []})
        self.asker_targets = defaultdict(set)
        self.icmp = defaultdict(lambda: {"n": 0, "dsts": set(), "ids": [], "t": [], "sources": set()})

    def on_packet(self, rec, ctx, state):
        a = rec.arp
        if a is not None and a.op == 1 and a.psrc != a.pdst:
            e = self.asks[a.pdst]
            e["n"] += 1
            if len(e["askers"]) < 32:
                e["askers"].add(a.psrc)
            if len(e["ts"]) < 5000:
                e["ts"].append((rec.ts, rec.idx))
            track_span(e["t"], rec.ts)
            targets = self.asker_targets[a.hwsrc]
            if len(targets) <= SWEEPER_TARGETS:
                targets.add(a.pdst)
            return
        if rec.icmp_type is None or rec.ip_version != 4:
            return
        group = None
        if rec.icmp_type == 3 and rec.icmp_code != 4:
            code = rec.icmp_code or 0
            group = "no_route" if code in NO_ROUTE else "port_closed" if code in PORT_CLOSED else "blocked" if code in BLOCKED else None
        elif rec.icmp_type == 11:
            group = "ttl_expired"
        if group is None:
            return
        dst = rec.icmp_inner[1] if rec.icmp_inner else "?"
        e = self.icmp[(rec.src_ip, group)]
        e["n"] += 1
        if len(e["dsts"]) < 64:
            e["dsts"].add(dst)
        if rec.icmp_inner and len(e["sources"]) < 64:
            e["sources"].add(rec.icmp_inner[0])
        if len(e["ids"]) < self.max_ids:
            e["ids"].append(rec.idx)
        track_span(e["t"], rec.ts)

    def finalize(self, state):
        out = []
        gw_ip, _ = state.hosts.gateway()
        sweepers = {mac for mac, t in self.asker_targets.items() if len(t) > SWEEPER_TARGETS}
        dns_servers = set(state.dns.server_responses) | {q.server for q in list(state.dns.queries.values())[:2000]}
        end = state.last_ts or 0
        for ip, e in self.asks.items():
            if e["n"] < self.t.unreachable_min_requests:
                continue
            # when did this device last say anything itself (ARP or IP traffic)?
            usage = state.hosts.macs_for(ip)
            last_seen = max((u.last_ts for u in usage.values()), default=None)
            silent = [
                (ts, idx) for ts, idx in e["ts"]
                if (last_seen is None or ts > last_seen + 3.0) and end - ts > 1.0
            ]
            if len(silent) < self.t.unreachable_min_requests:
                continue
            askers = {
                s for s in e["askers"]
                if not any(s in state.hosts.ips_for_mac(m) for m in sweepers)
            }
            if not askers:
                continue
            is_gw = ip == gw_ip
            role = "the gateway" if is_gw else "a DNS server" if ip in dns_servers else "a device"
            went_silent = last_seen is not None
            out.append(
                Symptom(
                    kind="host_unreachable",
                    category=Category.FAULT,
                    severity=5 if is_gw else 4 if ip in dns_servers else 2,
                    title=(
                        f"{ip} ({role}) stopped answering: {len(silent)} attempts to reach it failed"
                        if went_silent
                        else f"Nobody answers for {ip} ({role}): {len(silent)} attempts to reach it failed"
                    ),
                    t_start=silent[0][0],
                    t_end=silent[-1][0],
                    hosts=[ip, *sorted(askers)],
                    packet_ids=self.ids([i for _, i in silent]),
                    metrics={
                        "ip": ip,
                        "role": role,
                        "attempts": len(silent),
                        "askers": sorted(askers),
                        "is_gateway": is_gw,
                        "last_seen": round(last_seen, 3) if went_silent else None,
                    },
                    benign_evidence=[Evidence("Devices keep asking for this address and get silence: it is switched off, unplugged or has a different address", 0.6)],
                )
            )
        for (reporter, group), e in self.icmp.items():
            phrase, sev, minimum = ICMP_GROUPS[group]
            if e["n"] < minimum:
                continue
            dsts = sorted(e["dsts"])
            sym = Symptom(
                kind="icmp_unreachable",
                category=Category.FAULT,
                severity=sev,
                title=f"{reporter} {phrase} {', '.join(dsts[:3])}{'...' if len(dsts) > 3 else ''}",
                t_start=e["t"][0],
                t_end=e["t"][-1],
                hosts=[reporter, *dsts[:20], *sorted(e["sources"])[:10]],
                packet_ids=self.ids(e["ids"]),
                metrics={"reporter": reporter, "type": group, "messages": e["n"], "destinations": dsts, "affected_senders": sorted(e["sources"])},
                benign_evidence=[Evidence("A router or host itself reports the problem: a routing, firewall or service issue", 0.5)],
            )
            if group == "ttl_expired":
                sym.benign_evidence.append(Evidence("Could also be a traceroute tool, which triggers these messages on purpose", 0.2))
            out.append(sym)
        return out
