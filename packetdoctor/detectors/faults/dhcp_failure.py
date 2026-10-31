from __future__ import annotations

from collections import defaultdict

from ...models import Category, Evidence, Symptom
from ..base import Detector, track_span

DISCOVER, OFFER, REQUEST, ACK, NAK = 1, 2, 3, 5, 6
STARVATION_WINDOW = 60.0


class DhcpFailureDetector(Detector):
    """Devices that cannot get an IP address, and DHCP starvation.

    * dhcp_failure: clients keep sending DISCOVER/REQUEST and never get an
      ACK, or get NAKs: the DHCP server is down, unreachable or out of addresses.
    * dhcp_starvation: a burst of DISCOVERs from many different, never-seen
      MAC addresses, the attack that drains the address pool so that real
      devices get nothing (and a rogue server can take over)."""

    name = "dhcp_failure"

    def __init__(self, settings):
        super().__init__(settings)
        self.clients = defaultdict(lambda: {"asks": 0, "acks": 0, "naks": 0, "offers": 0, "ids": [], "t": [], "macs_src": set()})
        self.discovers = []  # (ts, client mac, frame src mac, idx)

    def on_packet(self, rec, ctx, state):
        d = rec.dhcp
        if d is None or not d.client_mac:
            return
        c = self.clients[d.client_mac]
        if d.msg_type in (DISCOVER, REQUEST):
            c["asks"] += 1
            if len(c["ids"]) < 20:
                c["ids"].append(rec.idx)
            track_span(c["t"], rec.ts)
            if rec.src_mac and len(c["macs_src"]) < 4:
                c["macs_src"].add(rec.src_mac)
            if d.msg_type == DISCOVER and len(self.discovers) < 100_000:
                self.discovers.append((rec.ts, d.client_mac, rec.src_mac, rec.idx))
        elif d.msg_type == OFFER:
            c["offers"] += 1
        elif d.msg_type == ACK:
            c["acks"] += 1
        elif d.msg_type == NAK:
            c["naks"] += 1
            if len(c["ids"]) < 20:
                c["ids"].append(rec.idx)

    def finalize(self, state):
        out = []
        starve = self._starvation()
        starving_macs = set(starve.metrics["fake_macs_sample"]) if starve else set()
        if starve:
            out.append(starve)
        failing = {
            mac: c for mac, c in self.clients.items()
            if mac not in starving_macs and c["acks"] == 0 and (c["asks"] >= self.t.dhcp_fail_min_requests or c["naks"] >= 2)
        }
        if failing:
            offers = sum(c["offers"] for c in failing.values())
            naks = sum(c["naks"] for c in failing.values())
            why = "the DHCP server refused (NAK)" if naks else "offers came but the address was never confirmed" if offers else "no DHCP server answered at all"
            out.append(
                Symptom(
                    kind="dhcp_failure",
                    category=Category.FAULT,
                    severity=4,
                    title=f"{len(failing)} device(s) cannot get an IP address: {why}",
                    t_start=min(c["t"][0] for c in failing.values()),
                    t_end=max(c["t"][-1] for c in failing.values()),
                    hosts=sorted(failing),
                    packet_ids=self.ids(*(c["ids"] for c in failing.values())),
                    metrics={
                        "clients": sorted(failing)[:20],
                        "requests": sum(c["asks"] for c in failing.values()),
                        "offers": offers,
                        "naks": naks,
                        "reason": why,
                    },
                    benign_evidence=[Evidence(f"Ordinary devices keep asking for an address and {why}: the DHCP server is down, unreachable or full", 0.6)],
                )
            )
        return out

    def _starvation(self):
        ds = self.discovers
        if len(ds) < self.t.dhcp_starvation_min_macs:
            return None
        best, lo = (0, 0, 0), 0
        seen = defaultdict(int)
        for hi, (ts, mac, *_rest) in enumerate(ds):
            seen[mac] += 1
            while ts - ds[lo][0] > STARVATION_WINDOW:
                seen[ds[lo][1]] -= 1
                if not seen[ds[lo][1]]:
                    del seen[ds[lo][1]]
                lo += 1
            if len(seen) > best[0]:
                best = (len(seen), lo, hi)
        n, lo, hi = best
        if n < self.t.dhcp_starvation_min_macs:
            return None
        burst = ds[lo : hi + 1]
        # a real client puts its own MAC in the DHCP request; starvation tools
        # invent one per request while the frames come from the attacker
        spoofed = list(dict.fromkeys(m for _, m, s, _ in burst if s and s != m))
        if len(spoofed) >= self.t.dhcp_starvation_min_macs:
            burst = [b for b in burst if b[2] and b[2] != b[1]]
            macs, n = spoofed, len(spoofed)
        else:
            macs = list(dict.fromkeys(m for _, m, _, _ in burst))
        frame_srcs = {s for _, _, s, _ in burst if s}
        acked = sum(1 for m in macs if self.clients[m]["acks"])
        sym = Symptom(
            kind="dhcp_starvation",
            category=Category.ATTACK,
            severity=4,
            title=f"{n} made-up devices asked for IP addresses within {STARVATION_WINDOW:.0f} s",
            t_start=burst[0][0],
            t_end=burst[-1][0],
            hosts=sorted(frame_srcs)[:5] + macs[:5],
            packet_ids=self.ids([b[3] for b in burst]),
            metrics={"fake_clients": n, "fake_macs_sample": macs[:200], "addresses_taken": acked, "sent_from": sorted(frame_srcs)[:10]},
            attack_evidence=[
                Evidence(f"{n} different devices asked for an address within one minute: far more than a small network has", 0.45),
                Evidence("Almost none of these devices ever send any other traffic: their identities are made up", 0.3),
            ],
        )
        if spoofed and len(spoofed) >= self.t.dhcp_starvation_min_macs:
            sym.attack_evidence.append(Evidence(f"The requests are sent by {len(frame_srcs)} device(s) but each claims a different hardware address inside: forged identities", 0.35))
        elif len(frame_srcs) < len(macs) / 4:
            sym.attack_evidence.append(Evidence(f"The requests physically come from only {len(frame_srcs)} network port(s) while claiming {len(macs)} identities", 0.3))
        return sym
