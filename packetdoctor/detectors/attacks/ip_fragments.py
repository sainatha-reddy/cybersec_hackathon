from __future__ import annotations

from collections import defaultdict

from ...models import Category, Evidence, Symptom
from ...state.lru import LRUDict
from ..base import Detector

TINY_FIRST_FRAGMENT = 24  # bytes: too small to even hold a full TCP header


class FragmentAttackDetector(Detector):
    """Malicious IP fragmentation.

    Normal fragments of one packet line up end to end. Overlapping
    fragments never occur legitimately; they are used to crash network
    stacks (teardrop) or to hide content from firewalls and IDSs that
    reassemble differently from the target. Tiny first fragments split the
    TCP header across fragments for the same evasion purpose."""

    name = "fragment_attack"

    def __init__(self, settings):
        super().__init__(settings)
        self.packets: LRUDict[tuple, list] = LRUDict(50_000)
        self.findings = defaultdict(lambda: {"overlap": 0, "tiny": 0, "ids": [], "t": [], "packets": set()})
        self.seen_at = LRUDict(min(settings.limits.max_flows, 50_000))
        self.last_end = LRUDict(min(settings.limits.max_flows, 50_000))
        self.packets.maxlen = min(settings.limits.max_flows, 50_000)

    def on_packet(self, rec, ctx, state):
        if rec.frag_len is None or rec.src_ip is None:
            return
        key = (rec.src_ip, rec.dst_ip, rec.ip_id, rec.ip_proto)
        previous = self.seen_at.get(key)
        if previous is not None and (rec.ts - previous > 30 or rec.ts < previous):
            self.packets.pop(key, None)
            self.last_end.pop(key, None)
        self.seen_at.put(key, rec.ts)
        frags = self.packets.get_or_create(key, list)
        start, end = rec.frag_offset, rec.frag_offset + rec.frag_len
        f = self.findings[(rec.src_ip, rec.dst_ip)]
        bad = False
        for s, e, idx in frags:
            if (s, e) == (start, end):
                continue  # an identical copy is a duplicate, not an overlap
            if start < e and s < end:
                f["overlap"] += 1
                bad = True
                if len(f["ids"]) < self.max_ids:
                    f["ids"].append(idx)
                break
        if start == 0 and rec.more_fragments and rec.frag_len < TINY_FIRST_FRAGMENT and rec.ip_proto == 6:
            f["tiny"] += 1
            bad = True
        if bad:
            if len(f["ids"]) < self.max_ids:
                f["ids"].append(rec.idx)
            f["t"].append(rec.ts)
            if len(f["packets"]) < 1000:
                f["packets"].add(rec.ip_id)
        if len(frags) < 64:
            frags.append((start, end, rec.idx))
        if not rec.more_fragments:
            self.last_end.put(key, end)
        target = self.last_end.get(key)
        covered = 0
        for lower, upper, _ in sorted(frags):
            if lower > covered:
                break
            covered = max(covered, upper)
        if target is not None and covered >= target:
            self.packets.pop(key, None)
            self.seen_at.pop(key, None)
            self.last_end.pop(key, None)

    def finalize(self, state):
        out = []
        for (src, dst), f in self.findings.items():
            if not f["t"]:
                continue
            sym = Symptom(
                kind=self.name,
                category=Category.ATTACK,
                severity=4,
                title=f"Malformed, overlapping IP fragments from {src} to {dst}",
                t_start=min(f["t"]),
                t_end=max(f["t"]),
                hosts=[src, dst],
                packet_ids=self.ids(f["ids"]),
                metrics={"src": src, "dst": dst, "overlaps": f["overlap"], "tiny_fragments": f["tiny"], "packets_affected": len(f["packets"])},
            )
            if f["overlap"]:
                sym.attack_evidence.append(Evidence("Pieces of the same packet overlap each other: this never happens in normal traffic and is used to crash devices (teardrop) or slip past firewalls", 0.6))
            if f["tiny"]:
                sym.attack_evidence.append(Evidence("The first piece is too small to hold a TCP header: a known trick to hide traffic from firewalls", 0.4))
            out.append(sym)
        return out
