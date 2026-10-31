from __future__ import annotations

from ...models import Category, Evidence, Symptom
from ..base import Detector


class DuplicateIpDetector(Detector):
    """Two devices actively using the same IP address.

    'Actively' means the MAC starts its own conversations with that IP (ARP
    requests, new TCP connections, DNS queries). An ARP spoofer that only
    *claims* an IP through forged replies does not count here; that pattern is
    handled by the ARP-spoofing detector. Relayed copies of packets (MITM) are
    filtered out before they reach the host table."""

    name = "duplicate_ip"

    def finalize(self, state):
        gw_ip, _ = state.hosts.gateway()
        out = []
        for ip, macs in state.hosts.ip_macs.items():
            if not state.hosts.is_local(ip):
                continue
            active = {
                mac: u
                for mac, u in macs.items()
                if u.originated >= 1 and (u.ip_packets + u.arp_requests) >= self.t.dup_ip_min_packets
            }
            if len(active) < 2:
                continue
            ordered = sorted(active.items(), key=lambda kv: kv[1].first_ts)
            original, newcomer = ordered[0], ordered[1]
            sym = Symptom(
                kind=self.name,
                category=Category.FAULT,
                severity=4,
                title=f"Two devices are using the same IP address {ip}",
                t_start=newcomer[1].first_ts,
                t_end=max(u.last_ts for _, u in ordered),
                hosts=[ip, *[m for m, _ in ordered]],
                packet_ids=self.ids(*(u.ids for _, u in ordered)),
                metrics={
                    "ip": ip,
                    "macs": [
                        {
                            "mac": m,
                            "first_seen": round(u.first_ts, 3),
                            "packets": u.ip_packets,
                            "connections_started": u.originated,
                            "gratuitous_arp": u.gratuitous,
                            "unsolicited_replies": u.unsolicited_replies,
                        }
                        for m, u in ordered
                    ],
                    "original_mac": original[0],
                    "new_mac": newcomer[0],
                },
                benign_evidence=[
                    Evidence("Both devices behave like ordinary computers: each starts its own connections with this address", 0.5),
                ],
            )
            if newcomer[1].gratuitous <= 2 and newcomer[1].unsolicited_replies == 0:
                sym.benign_evidence.append(
                    Evidence("The second device announced itself only when it was switched on, like a device given a fixed IP by mistake", 0.3)
                )
            if newcomer[1].unsolicited_replies >= self.t.arp_unsolicited_min:
                sym.attack_evidence.append(Evidence(f"The second device sent {newcomer[1].unsolicited_replies} unrequested ARP replies for this IP", 0.5))
            if ip == gw_ip:
                sym.attack_evidence.append(Evidence("The shared address is the gateway, the most valuable address to impersonate", 0.3))
            out.append(sym)
        return out
