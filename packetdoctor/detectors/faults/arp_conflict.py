from __future__ import annotations

from collections import defaultdict

from ...models import Category, Evidence, Symptom
from ..base import Detector

RECENT = 300.0  # an IP->MAC binding counts as current for this long
REPLY_WINDOW = 1.0


class ArpConflictDetector(Detector):
    """ARP-level address conflicts:

    * a device announces an IP (gratuitous ARP) that another device is using;
    * an RFC 5227 address probe is answered, meaning the address is taken;
    * one ARP request gets answers from two different MACs."""

    name = "arp_conflict"

    def __init__(self, settings):
        super().__init__(settings)
        self.conflicts = defaultdict(lambda: {"events": [], "ids": [], "macs": set(), "t": []})
        self.probes = {}  # ip -> (mac, ts)
        self.requests = {}  # target ip -> (ts, request idx, {mac: idx})

    def _add(self, ip, what, macs, ids, ts):
        c = self.conflicts[ip]
        if len(c["events"]) < 100:
            c["events"].append(what)
        c["ids"].extend(ids)
        c["macs"].update(macs)
        c["t"].append(ts)

    def on_packet(self, rec, ctx, state):
        ev = ctx.arp
        if ev is None:
            return
        a = rec.arp
        if ev.kind == "probe":
            self.probes[ev.ip] = (ev.mac, rec.ts, rec.idx)
            return
        if ev.kind == "request":
            self.requests[a.pdst] = (rec.ts, rec.idx, {})
            if len(self.requests) > 50_000:
                self.requests.clear()
        current = []
        if ev.previous_macs:
            usage = state.hosts.macs_for(ev.ip)
            current = [m for m in ev.previous_macs if m in usage and rec.ts - usage[m].last_ts <= RECENT]
        if ev.kind == "gratuitous" and current:
            self._add(ev.ip, "announcement", {ev.mac, *current}, [rec.idx], rec.ts)
        if ev.kind in ("reply", "unsolicited_reply"):
            probe = self.probes.get(ev.ip)
            if probe and probe[0] != ev.mac and rec.ts - probe[1] <= 3.0:
                self._add(ev.ip, "probe_answered", {ev.mac, probe[0]}, [probe[2], rec.idx], rec.ts)
            req = self.requests.get(ev.ip)
            if req and rec.ts - req[0] <= REPLY_WINDOW:
                answers = req[2]
                if ev.mac not in answers:
                    answers[ev.mac] = rec.idx
                if len(answers) == 2:
                    self._add(ev.ip, "two_answers", set(answers), [req[1], *answers.values()], rec.ts)

    def finalize(self, state):
        out = []
        labels = {
            "announcement": "a device announced an address already in use",
            "probe_answered": "an address check found the address already taken",
            "two_answers": "two devices answered for the same address",
        }
        for ip, c in self.conflicts.items():
            kinds = sorted(set(c["events"]))
            out.append(
                Symptom(
                    kind=self.name,
                    category=Category.FAULT,
                    severity=3,
                    title=f"ARP address conflict on {ip}",
                    t_start=min(c["t"]),
                    t_end=max(c["t"]),
                    hosts=[ip, *sorted(c["macs"])],
                    packet_ids=self.ids(c["ids"]),
                    metrics={
                        "ip": ip,
                        "macs": sorted(c["macs"]),
                        "conflict_types": kinds,
                        "occurrences": len(c["events"]),
                        "descriptions": [labels[k] for k in kinds],
                    },
                    benign_evidence=[Evidence("Conflicts appear through normal ARP behaviour (announcements, two honest answers), not through a stream of forged replies", 0.4)],
                )
            )
        return out
