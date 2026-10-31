from __future__ import annotations

from collections import defaultdict

from ...models import Category, Evidence, Symptom
from ..base import Detector

LARGE_SEGMENT = 1200  # bytes of payload; small packets fit through any sane path


class MtuDetector(Detector):
    """MTU problems:

    * explicit: a router reports 'fragmentation needed' (ICMP type 3 code 4)
      or 'packet too big' (ICMPv6), and we check whether the sender adapted;
    * black hole: full-size segments are re-sent again and again and never
      acknowledged, while small packets on the same connection get through.
      That is the signature of a path that silently drops big packets."""

    name = "mtu"

    def __init__(self, settings):
        super().__init__(settings)
        self.icmp = {}  # (src, dst) -> dict
        self.oversize_after = defaultdict(int)
        self.fitting_after = defaultdict(int)

    def on_packet(self, rec, ctx, state):
        if rec.icmp_mtu and rec.icmp_inner:
            key = (rec.icmp_inner[0], rec.icmp_inner[1])
            e = self.icmp.setdefault(key, {"mtu": rec.icmp_mtu, "ids": [], "t0": rec.ts, "t1": rec.ts, "router": rec.src_ip})
            e["mtu"] = min(e["mtu"], rec.icmp_mtu)
            e["t1"] = rec.ts
            if len(e["ids"]) < self.max_ids:
                e["ids"].append(rec.idx)
            return
        if rec.payload_len and rec.is_tcp and self.icmp:
            key = (rec.src_ip, rec.dst_ip)
            e = self.icmp.get(key)
            if e and rec.ts > e["t0"]:
                hdr = 40 if rec.ip_version == 4 else 60
                if rec.payload_len + hdr > e["mtu"]:
                    self.oversize_after[key] += 1
                else:
                    self.fitting_after[key] += 1

    def finalize(self, state):
        out = []
        for (src, dst), e in self.icmp.items():
            adapted = self.fitting_after[(src, dst)] > 0 and self.oversize_after[(src, dst)] == 0
            sym = Symptom(
                kind="mtu_mismatch",
                category=Category.FAULT,
                severity=2 if adapted else 3,
                title=f"Path from {src} to {dst} only carries packets up to {e['mtu']} bytes",
                t_start=e["t0"],
                t_end=e["t1"],
                hosts=[src, dst] + ([e["router"]] if e["router"] else []),
                packet_ids=self.ids(e["ids"]),
                metrics={"src": src, "dst": dst, "path_mtu": e["mtu"], "reported_by": e["router"], "sender_adapted": adapted},
                benign_evidence=[Evidence(f"A router ({e['router']}) reported a smaller MTU of {e['mtu']} bytes, typical of VPN or tunnel links", 0.6)],
            )
            out.append(sym)

        holes = defaultdict(lambda: {"flows": 0, "ids": [], "t": [], "retries": 0, "size": 0})
        for flow in state.flows.flows.values():
            for i, d in enumerate(flow.dirs):
                if d.acked <= 1:
                    continue  # nothing ever acknowledged: not the black-hole pattern
                stuck = [
                    (r, seg) for r, seg in d.segs.items()
                    if seg[0] >= 1 + self.t.mtu_blackhole_retries and seg[1] >= LARGE_SEGMENT and d.acked <= r
                ]
                if not stuck:
                    continue
                src = flow.client[0] if i == 0 else flow.server[0]
                dst = flow.server[0] if i == 0 else flow.client[0]
                h = holes[(src, dst)]
                h["flows"] += 1
                for r, seg in stuck:
                    h["ids"].append(seg[2])
                    h["retries"] += seg[0] - 1
                    h["size"] = max(h["size"], seg[1])
                h["ids"].extend(d.retrans_ids)
                h["t"].extend([flow.first_ts, flow.last_ts])
        for (src, dst), h in holes.items():
            out.append(
                Symptom(
                    kind="mtu_blackhole",
                    category=Category.FAULT,
                    severity=4,
                    title=f"Large packets from {src} to {dst} silently disappear (MTU black hole)",
                    t_start=min(h["t"]),
                    t_end=max(h["t"]),
                    hosts=[src, dst],
                    packet_ids=self.ids(h["ids"]),
                    metrics={"src": src, "dst": dst, "flows": h["flows"], "retries": h["retries"], "segment_size": h["size"]},
                    benign_evidence=[
                        Evidence("Small packets on the same connection are delivered and acknowledged, only full-size ones vanish", 0.6),
                        Evidence("No 'fragmentation needed' message came back: something on the path drops them silently", 0.3),
                    ],
                )
            )
        return out
