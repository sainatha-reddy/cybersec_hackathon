from __future__ import annotations

from collections import defaultdict

from ...models import Category, Evidence, Symptom
from ...utils import fmt_duration
from ..base import Detector

WINDOW = 10.0  # seconds


class ArpStormDetector(Detector):
    """One device sending ARP requests far faster than normal.

    Two very different causes look alike: a router resolving addresses for
    traffic sent to devices that do not exist (a fault, often triggered by
    scanning from the internet or a wrong route), and a computer sweeping the
    subnet to discover hosts (reconnaissance). The clues: who is asking (a
    router uses '.1'/'.254' style addresses, often several), and whether the
    targets are walked through in order."""

    name = "arp_storm"

    def __init__(self, settings):
        super().__init__(settings)
        self.by_mac = defaultdict(lambda: {"ts": [], "targets": [], "psrc": set(), "ids": []})

    def on_packet(self, rec, ctx, state):
        a = rec.arp
        if a is None or a.op != 1 or a.psrc == a.pdst or a.psrc == "0.0.0.0":
            return
        s = self.by_mac[a.hwsrc]
        if len(s["ts"]) < 50_000:
            s["ts"].append(rec.ts)
            s["targets"].append(a.pdst)
        if len(s["psrc"]) < 32:
            s["psrc"].add(a.psrc)
        if len(s["ids"]) < self.max_ids:
            s["ids"].append(rec.idx)

    def finalize(self, state):
        gw_ip, gw_mac = state.hosts.gateway()
        out = []
        for mac, s in self.by_mac.items():
            ts = s["ts"]
            if len(ts) < self.t.arp_storm_min_requests:
                continue
            peak, lo = 0, 0
            for hi in range(len(ts)):
                while ts[hi] - ts[lo] > WINDOW:
                    lo += 1
                peak = max(peak, hi - lo + 1)
            distinct = list(dict.fromkeys(s["targets"]))
            if peak < self.t.arp_storm_min_requests and len(distinct) < self.t.arp_sweep_min_targets:
                continue
            answered = sum(1 for t in distinct if state.hosts.macs_for(t))
            unanswered_share = 1 - answered / max(1, len(distinct))
            rate = peak / WINDOW
            sequential = _sequential_share(distinct)
            psrc = sorted(s["psrc"])
            router_like = mac == gw_mac or gw_ip in s["psrc"] or len(psrc) >= 2 or any(p.endswith((".1", ".254")) for p in psrc)
            sweep = not router_like and len(distinct) >= self.t.arp_sweep_min_targets

            sym = Symptom(
                kind="arp_sweep" if sweep else self.name,
                category=Category.FAULT,
                severity=3 if rate >= 10 else 2,
                title=(
                    f"{psrc[0] if psrc else mac} swept the network with ARP lookups for {len(distinct)} addresses"
                    if sweep
                    else f"{mac} flooded the network with {len(ts)} address lookups in {fmt_duration(ts[-1] - ts[0])}"
                ),
                t_start=ts[0],
                t_end=ts[-1],
                hosts=[mac, *psrc],
                packet_ids=self.ids(s["ids"]),
                metrics={
                    "mac": mac,
                    "sender_ips": psrc,
                    "requests": len(ts),
                    "distinct_targets": len(distinct),
                    "peak_per_second": round(rate, 1),
                    "unanswered_share": round(unanswered_share, 2),
                    "sequential_share": round(sequential, 2),
                    "router_like": router_like,
                },
            )
            if router_like:
                sym.benign_evidence.append(Evidence(f"The device asking is a router (it uses {', '.join(psrc[:3])}); routers look up every address that traffic is sent to", 0.5))
            if unanswered_share >= 0.7:
                sym.benign_evidence.append(Evidence(f"{unanswered_share:.0%} of the addresses never answer: traffic is being sent to devices that do not exist", 0.3))
            if sweep:
                sym.attack_evidence.append(Evidence("An ordinary device looked up dozens of other devices it never talked to: host discovery", 0.35))
            if sequential >= 0.6 and len(distinct) >= self.t.arp_sweep_min_targets:
                sym.attack_evidence.append(Evidence(f"The addresses were asked for in order ({sequential:.0%} consecutive): the pattern of a scanning tool", 0.35 if sweep else 0.2))
            out.append(sym)
        return out


def _sequential_share(targets: list[str]) -> float:
    """Share of consecutive lookups whose address is within 2 of the previous one."""
    nums = []
    for t in targets:
        try:
            a, b, c, d = (int(x) for x in t.split("."))
            nums.append((a << 24) | (b << 16) | (c << 8) | d)
        except ValueError:
            continue
    if len(nums) < 2:
        return 0.0
    close = sum(1 for x, y in zip(nums, nums[1:]) if 0 < abs(y - x) <= 2)
    return close / (len(nums) - 1)
