from __future__ import annotations

from collections import defaultdict

from ...models import Category, Evidence, Symptom
from ..base import Detector


class TcpResetDetector(Detector):
    """Two different reset problems:

    * refused: the same service answers connection attempts with RST, i.e.
      the port is closed or the service is down;
    * aborted: established connections carrying data are torn down by the
      server side with RST instead of a normal FIN close.

    A client that gets refused on many *different* ports is scanning, not
    suffering a fault; those are left to the port-scan detector."""

    name = "tcp_resets"

    def finalize(self, state):
        refused = defaultdict(list)
        aborted = defaultdict(list)
        refused_ports_by_client = defaultdict(set)
        for flow in state.flows.all_flows():
            if flow.refused:
                refused[flow.server].append(flow)
                refused_ports_by_client[flow.client[0]].add(flow.server)
            elif flow.rst_by == 1 and flow.rst_after_data and not flow.fin_seen:
                # only resets sent by the server side: clients (browsers, apps)
                # routinely reset their own connections when they are done
                aborted[flow.server].append(flow)

        out = []
        for (srv_ip, srv_port), flows in refused.items():
            clients = {f.client[0] for f in flows}
            clients = {c for c in clients if len(refused_ports_by_client[c]) < self.t.scan_min_ports}
            flows = [f for f in flows if f.client[0] in clients]
            if len(flows) < self.t.reset_min_count:
                continue
            out.append(
                Symptom(
                    kind="tcp_connection_refused",
                    category=Category.FAULT,
                    severity=3,
                    title=f"Service on {srv_ip} port {srv_port} refuses connections",
                    t_start=min(f.first_ts for f in flows),
                    t_end=max(f.last_ts for f in flows),
                    hosts=[srv_ip, *sorted(clients)],
                    packet_ids=self.ids([f.syn_idx for f in flows if f.syn_idx], [f.rst_idx for f in flows]),
                    metrics={"server": srv_ip, "port": srv_port, "attempts": len(flows), "clients": sorted(clients)},
                    benign_evidence=[
                        Evidence(f"{len(flows)} attempts to the same port were all rejected: the service is not running or is blocked", 0.6),
                        Evidence("The clients only tried this one service (normal use, not scanning)", 0.3),
                    ],
                )
            )
        for (srv_ip, srv_port), flows in aborted.items():
            if len(flows) < self.t.reset_min_count:
                continue
            who = "the server"
            clients = sorted({f.client[0] for f in flows})
            out.append(
                Symptom(
                    kind="tcp_connection_aborted",
                    category=Category.FAULT,
                    severity=3,
                    title=f"Connections to {srv_ip}:{srv_port} are cut off mid-transfer",
                    t_start=min(f.rst_ts for f in flows),
                    t_end=max(f.rst_ts for f in flows),
                    hosts=[srv_ip, *clients],
                    packet_ids=self.ids([f.rst_idx for f in flows]),
                    metrics={
                        "server": srv_ip,
                        "port": srv_port,
                        "aborted": len(flows),
                        "reset_by": who,
                        "clients": clients,
                    },
                    benign_evidence=[Evidence(f"Resets come from {who} after real data was exchanged: an application or device dropping connections", 0.5)],
                )
            )
        return out
