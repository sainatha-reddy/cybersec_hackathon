from __future__ import annotations

from collections import Counter, defaultdict

from ...models import Category, Evidence, Symptom
from ..base import Detector, severity_from_ratio


class TcpRetransmissionDetector(Detector):
    """Packet loss on a path shows up as TCP retransmissions. Retransmissions
    are aggregated per (client, server) pair and reported when both the count
    and the share of data segments are above threshold, so a single lost
    packet in a long capture is not reported."""

    name = "tcp_retransmissions"

    def finalize(self, state):
        groups: dict[tuple, dict] = defaultdict(
            lambda: {"retrans": 0, "data": 0, "kinds": Counter(), "ids": [], "flows": 0, "t0": None, "t1": None}
        )
        for flow in state.flows.all_flows():
            for d in flow.dirs:
                if d.data_segments == 0:
                    continue
                g = groups[(flow.client[0], flow.server[0])]
                g["data"] += d.data_segments
                if not d.retrans:
                    continue
                g["retrans"] += d.retrans
                g["kinds"].update(d.retrans_kinds)
                g["ids"].extend(d.retrans_ids)
                g["flows"] += 1
                g["t0"] = d.retrans_first if g["t0"] is None else min(g["t0"], d.retrans_first)
                g["t1"] = d.retrans_last if g["t1"] is None else max(g["t1"], d.retrans_last)

        out = []
        for (client, server), g in groups.items():
            if g["retrans"] < self.t.retrans_min_count:
                continue
            ratio = g["retrans"] / max(1, g["data"])
            if ratio < self.t.retrans_min_ratio:
                continue
            kinds = dict(g["kinds"])
            sym = Symptom(
                kind=self.name,
                category=Category.FAULT,
                severity=severity_from_ratio(ratio),
                title=f"Packets lost and re-sent between {client} and {server}",
                t_start=g["t0"],
                t_end=g["t1"],
                hosts=[client, server],
                packet_ids=self.ids(g["ids"]),
                metrics={
                    "client": client,
                    "server": server,
                    "retransmissions": g["retrans"],
                    "data_segments": g["data"],
                    "ratio": round(ratio, 4),
                    "kinds": kinds,
                    "flows_affected": g["flows"],
                },
                benign_evidence=[
                    Evidence(f"{ratio:.0%} of data packets on this path had to be sent again: typical of a congested or lossy link", 0.5)
                ],
            )
            if kinds.get("spurious", 0) > g["retrans"] / 2:
                sym.benign_evidence.append(Evidence("Most re-sent packets had already arrived (spurious retransmissions): the path is slow rather than lossy", 0.3))
            out.append(sym)
        return out
