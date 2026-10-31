from __future__ import annotations

from collections import Counter, defaultdict

from ...models import TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN, Category, Evidence, Symptom
from ...state.flows import FlowTable
from ...state.lru import LRUDict
from ..base import Detector

URG = 0x20
MAX_PROBES_PER_SOURCE = 50_000


def _max_distinct_in_window(items: list[tuple[float, object]], window: float) -> tuple[int, float, float]:
    """Largest number of distinct values seen within any ``window`` seconds.
    ``items`` is (ts, value) sorted by ts. Returns (count, start, end)."""
    counts: Counter = Counter()
    best = (0, 0.0, 0.0)
    lo = 0
    for hi, (ts, val) in enumerate(items):
        counts[val] += 1
        while ts - items[lo][0] > window:
            v = items[lo][1]
            counts[v] -= 1
            if not counts[v]:
                del counts[v]
            lo += 1
        if len(counts) > best[0]:
            best = (len(counts), items[lo][0], ts)
    return best


class PortScanDetector(Detector):
    """Reconnaissance: one source probing many ports on a host (vertical scan)
    or the same port on many hosts (horizontal sweep) in a short time.

    The key benign/attack separator is *completion*: a busy but normal client
    turns its connections into real conversations with data, whereas a scanner
    abandons almost every probe after the first reply."""

    name = "port_scan"

    def __init__(self, settings):
        super().__init__(settings)
        self.probes: LRUDict[str, list] = LRUDict(settings.limits.max_hosts)  # src -> [(ts, dst, dport, sport, idx, type)]
        self.open_ports: dict[tuple, set] = defaultdict(set)  # (scanner, target) -> ports that answered SYN-ACK

    def on_packet(self, rec, ctx, state):
        if not rec.is_tcp or ctx.relayed or not rec.src_ip:
            return
        f = rec.tcp_flags or 0
        probe_type = None
        if f & TCP_SYN and not f & TCP_ACK:
            probe_type = "SYN"
        elif not f & (TCP_ACK | TCP_RST | TCP_SYN):
            if f == 0:
                probe_type = "NULL"
            elif f & (TCP_FIN | TCP_PSH | URG) == (TCP_FIN | TCP_PSH | URG):
                probe_type = "XMAS"
            elif f == TCP_FIN:
                probe_type = "FIN"
        if probe_type:
            lst = self.probes.get_or_create(rec.src_ip, list)
            if len(lst) < MAX_PROBES_PER_SOURCE:
                lst.append((rec.ts, rec.dst_ip, rec.dport, rec.sport, rec.idx, probe_type))
        elif f & TCP_SYN and f & TCP_ACK:
            ports = self.open_ports[(rec.dst_ip, rec.src_ip)]
            if len(ports) < 1024:
                ports.add(rec.sport)

    def finalize(self, state):
        out = []
        window = self.t.scan_window_s
        for src, probes in self.probes.items():
            if len(probes) < min(self.t.scan_min_ports, self.t.scan_min_hosts):
                continue
            probes.sort()
            by_dst = defaultdict(list)
            by_port = defaultdict(list)
            for p in probes:
                by_dst[p[1]].append((p[0], p[2]))
                by_port[p[2]].append((p[0], p[1]))
            vertical = {dst: _max_distinct_in_window(items, window) for dst, items in by_dst.items()}
            horizontal = {port: _max_distinct_in_window(items, window) for port, items in by_port.items()}
            v_hits = {d: v for d, v in vertical.items() if v[0] >= self.t.scan_min_ports}
            h_hits = {p: v for p, v in horizontal.items() if v[0] >= self.t.scan_min_hosts}
            if not v_hits and not h_hits:
                continue

            involved = [p for p in probes if p[1] in v_hits or p[2] in h_hits]
            completed = dead = 0
            for ts, dst, dport, sport, idx, _ in involved:
                flow = state.flows.flows.get(FlowTable.key(_FakeRec(src, sport, dst, dport)))
                if flow is not None and flow.data_bytes > 0:
                    completed += 1
                elif flow is None or flow.synack_ts is None:
                    dead += 1  # refused (RST) or no answer at all: closed port / no such host
            completion = completed / max(1, len(involved))
            dead_share = dead / max(1, len(involved))
            types = Counter(p[5] for p in involved)
            if completion > 0.5 and set(types) == {"SYN"}:
                continue  # a busy client whose connections carry real data is not scanning
            t0 = min(p[0] for p in involved)
            t1 = max(p[0] for p in involved)
            duration = max(t1 - t0, 0.001)
            open_found = {dst: sorted(self.open_ports.get((src, dst), set())) for dst in {p[1] for p in involved}}
            open_found = {d: ports for d, ports in open_found.items() if ports}
            ports_probed = len({p[2] for p in involved})
            hosts_probed = len({p[1] for p in involved})

            sym = Symptom(
                kind=self.name,
                category=Category.ATTACK,
                severity=4 if open_found else 3,
                title=self._title(src, v_hits, h_hits),
                t_start=t0,
                t_end=t1,
                hosts=[src, *sorted(v_hits)[:20]],
                packet_ids=self.ids([p[4] for p in involved]),
                metrics={
                    "scanner": src,
                    "vertical_targets": {d: v[0] for d, v in v_hits.items()},
                    "horizontal_ports": {p: v[0] for p, v in h_hits.items()},
                    "probes": len(involved),
                    "ports_probed": ports_probed,
                    "hosts_probed": hosts_probed,
                    "probes_per_second": round(len(involved) / duration, 1),
                    "completion": round(completion, 3),
                    "dead_share": round(dead_share, 3),
                    "scan_types": dict(types),
                    "open_ports_found": open_found,
                },
            )
            if v_hits:
                worst = max(v_hits.items(), key=lambda kv: kv[1][0])
                n_ports = worst[1][0]
                weight = 0.55 if n_ports >= 100 else 0.45 if n_ports >= 40 else 0.4
                sym.attack_evidence.append(Evidence(f"{n_ports} different ports on {worst[0]} were tried within {window:.0f} seconds", weight))
            if h_hits:
                worst = max(h_hits.items(), key=lambda kv: kv[1][0])
                sym.attack_evidence.append(Evidence(f"Port {worst[0]} was tried on {worst[1][0]} different devices within {window:.0f} seconds", 0.35))
            if completion <= self.t.scan_max_completion:
                sym.attack_evidence.append(Evidence(f"Only {completion:.0%} of the attempts turned into real conversations: the source was only looking", 0.3))
            else:
                sym.benign_evidence.append(Evidence(f"{completion:.0%} of the connections carried real data, like a busy but normal application", 0.6))
            if dead_share >= 0.8:
                sym.attack_evidence.append(Evidence(f"{dead_share:.0%} of the attempts hit closed ports or devices that do not exist: the source did not know what was there", 0.2))
            if len(involved) / duration > 20:
                sym.attack_evidence.append(Evidence(f"{len(involved) / duration:.0f} attempts per second, far faster than a person or normal app", 0.2))
            stealth = {k: v for k, v in types.items() if k != "SYN"}
            if stealth:
                sym.attack_evidence.append(Evidence(f"Uses stealth probe types ({', '.join(stealth)}) that normal software never sends", 0.3))
            if open_found:
                listing = "; ".join(f"{d}: {', '.join(map(str, p[:10]))}" for d, p in open_found.items())
                sym.metrics["open_ports_text"] = listing
            out.append(sym)
        return out

    @staticmethod
    def _title(src, v_hits, h_hits):
        if v_hits and h_hits:
            return f"{src} scanned devices and ports on the network"
        if v_hits:
            targets = ", ".join(sorted(v_hits)[:3])
            return f"{src} scanned many ports on {targets}"
        ports = ", ".join(str(p) for p in sorted(h_hits)[:3])
        return f"{src} swept the network for port {ports}"


class _FakeRec:
    __slots__ = ("src_ip", "sport", "dst_ip", "dport")

    def __init__(self, src_ip, sport, dst_ip, dport):
        self.src_ip, self.sport, self.dst_ip, self.dport = src_ip, sport, dst_ip, dport
