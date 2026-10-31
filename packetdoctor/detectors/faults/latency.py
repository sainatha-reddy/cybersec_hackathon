from __future__ import annotations

import statistics
from collections import defaultdict

from ...models import Category, Evidence, Symptom
from ..base import Detector

CLUSTER_GAP = 10.0  # seconds between slow samples that still belong to one episode


def _robust_threshold(values: list[float], k: float, min_abs: float) -> tuple[float, float]:
    """Return (baseline median, slow threshold) using median + k * MAD.

    The capture is its own baseline: 'slow' means slow compared with the rest
    of this network, with an absolute floor so tiny LAN times are not flagged."""
    med = statistics.median(values)
    mad = statistics.median(abs(v - med) for v in values) * 1.4826
    return med, max(med + k * mad, med * 3, min_abs)


class LatencyDetector(Detector):
    """Unusual delays: slow TCP connection setup or slow DNS answers, and
    receivers that stall (TCP zero window)."""

    name = "high_latency"

    def finalize(self, state):
        handshake = []  # (ts, rtt, server, ids)
        for flow in state.flows.flows.values():
            rtt = flow.handshake_rtt
            if rtt is not None:
                handshake.append((flow.syn_ts, rtt, flow.server[0], [flow.syn_idx]))
        dns = []
        for q in state.dns.all_queries():
            if q.first is not None:
                dns.append((q.ts, q.first.ts - q.ts, q.server, [q.idx, q.first.idx]))

        out = []
        for what, samples in (("connection setup (TCP handshake)", handshake), ("DNS replies", dns)):
            out.extend(self._episodes(what, samples))
        out.extend(self._zero_window(state))
        return out

    def _episodes(self, what, samples):
        if len(samples) < self.t.latency_min_samples * 2:
            return []
        values = [s[1] for s in samples]
        med, thr = _robust_threshold(values, self.t.latency_mad_k, self.t.latency_min_abs_s)
        slow = sorted((s for s in samples if s[1] > thr), key=lambda s: s[0])
        episodes, cur = [], []
        for s in slow:
            if cur and s[0] - cur[-1][0] > CLUSTER_GAP:
                episodes.append(cur)
                cur = []
            cur.append(s)
        if cur:
            episodes.append(cur)

        out = []
        for ep in episodes:
            if len(ep) < self.t.latency_min_samples:
                continue
            slow_vals = [s[1] for s in ep]
            slow_med = statistics.median(slow_vals)
            servers = sorted({s[2] for s in ep})
            factor = slow_med / med if med > 0 else float("inf")
            sev = 4 if slow_med > 1.0 else 3 if slow_med > 0.5 else 2
            out.append(
                Symptom(
                    kind=self.name,
                    category=Category.FAULT,
                    severity=sev,
                    title=f"Slow {what}: {slow_med * 1000:.0f} ms instead of the usual {med * 1000:.0f} ms",
                    t_start=ep[0][0],
                    t_end=ep[-1][0] + ep[-1][1],
                    hosts=servers,
                    packet_ids=self.ids(*(s[3] for s in ep)),
                    metrics={
                        "what": what,
                        "baseline_ms": round(med * 1000, 1),
                        "slow_median_ms": round(slow_med * 1000, 1),
                        "worst_ms": round(max(slow_vals) * 1000, 1),
                        "slowdown_factor": round(factor, 1) if factor != float("inf") else None,
                        "slow_samples": len(ep),
                        "total_samples": len(values),
                        "servers": servers,
                    },
                    benign_evidence=[Evidence(f"Delays affect {len(servers)} different destination(s) at the same time: a congested link or overloaded server", 0.5)],
                )
            )
        return out

    def _zero_window(self, state):
        per_host = defaultdict(lambda: {"count": 0, "ids": [], "flows": 0, "t": [], "peers": set()})
        for flow in state.flows.flows.values():
            for i, d in enumerate(flow.dirs):
                if d.zero_windows < self.t.zero_window_min:
                    continue
                host = flow.client[0] if i == 0 else flow.server[0]
                peer = flow.server[0] if i == 0 else flow.client[0]
                h = per_host[host]
                h["count"] += d.zero_windows
                h["ids"].extend(d.zero_window_ids)
                h["flows"] += 1
                h["t"].extend([flow.first_ts, flow.last_ts])
                h["peers"].add(peer)
        out = []
        for host, h in per_host.items():
            out.append(
                Symptom(
                    kind="tcp_zero_window",
                    category=Category.FAULT,
                    severity=2,
                    title=f"{host} is too busy to receive data (TCP zero window)",
                    t_start=min(h["t"]),
                    t_end=max(h["t"]),
                    hosts=[host, *sorted(h["peers"])],
                    packet_ids=self.ids(h["ids"]),
                    metrics={"receiver": host, "zero_window_packets": h["count"], "flows": h["flows"], "senders": sorted(h["peers"])},
                    benign_evidence=[Evidence("The receiving device itself asked the sender to pause: its application or disk cannot keep up", 0.6)],
                )
            )
        return out
