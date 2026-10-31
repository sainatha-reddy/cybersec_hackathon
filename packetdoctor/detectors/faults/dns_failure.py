from __future__ import annotations

from collections import Counter, defaultdict

from ...models import Category, Evidence, Symptom
from ..base import Detector, severity_from_ratio

SERVFAIL, NXDOMAIN, REFUSED = 2, 3, 5
WINDOW = 30.0  # an outage is judged on its worst 30 seconds, not diluted by the rest of the capture


def _worst_window_ratio(events: list[tuple[float, bool]], window: float, min_failures: int) -> float:
    """Highest failure share over any window holding at least ``min_failures`` failures."""
    best, lo, fails = 0.0, 0, 0
    for hi, (ts, failed) in enumerate(events):
        fails += failed
        while ts - events[lo][0] > window:
            fails -= events[lo][1]
            lo += 1
        if fails >= min_failures:
            best = max(best, fails / (hi - lo + 1))
    return best


class DnsFailureDetector(Detector):
    """A DNS server that answers SERVFAIL/REFUSED or stops answering makes
    'the internet' look down. NXDOMAIN (name does not exist) is usually a
    typo, so it is counted but does not trigger a finding on its own."""

    name = "dns_failure"

    def finalize(self, state):
        end = state.last_ts or 0
        per_server = defaultdict(
            lambda: {"total": 0, "servfail": 0, "refused": 0, "timeout": 0, "nxdomain": 0, "ids": [], "names": Counter(), "clients": set(), "t": [], "events": []}
        )
        for q in state.dns.all_queries():
            s = per_server[q.server]
            first = q.first
            if first is None and end - q.ts < self.t.dns_timeout_s:
                continue  # capture ended before an answer could arrive
            failed = first is None or first.rcode in (SERVFAIL, REFUSED)
            s["events"].append((q.ts, failed))
            if first is None:
                s["total"] += 1
                s["timeout"] += 1
                s["ids"].append(q.idx)
            else:
                s["total"] += 1
                if first.rcode == SERVFAIL:
                    s["servfail"] += 1
                elif first.rcode == REFUSED:
                    s["refused"] += 1
                elif first.rcode == NXDOMAIN:
                    s["nxdomain"] += 1
                    continue
                else:
                    continue
                s["ids"].extend((q.idx, first.idx))
            s["names"][q.qname] += 1
            s["clients"].add(q.client)
            s["t"].append(q.ts)

        out = []
        for server, s in per_server.items():
            failures = s["servfail"] + s["refused"] + s["timeout"]
            if failures < self.t.dns_failure_min:
                continue
            ratio = _worst_window_ratio(sorted(s["events"]), WINDOW, self.t.dns_failure_min)
            if ratio < self.t.dns_failure_ratio:
                continue
            parts = []
            if s["servfail"]:
                parts.append(f"{s['servfail']} server errors")
            if s["refused"]:
                parts.append(f"{s['refused']} refusals")
            if s["timeout"]:
                parts.append(f"{s['timeout']} unanswered")
            out.append(
                Symptom(
                    kind=self.name,
                    category=Category.FAULT,
                    severity=severity_from_ratio(ratio, ((0.5, 4), (0.25, 3))),
                    title=f"DNS server {server} is failing to answer ({', '.join(parts)})",
                    t_start=min(s["t"]),
                    t_end=max(s["t"]),
                    hosts=[server, *sorted(s["clients"])],
                    packet_ids=self.ids(s["ids"]),
                    metrics={
                        "server": server,
                        "queries": s["total"],
                        "failures": failures,
                        "ratio": round(ratio, 3),
                        "servfail": s["servfail"],
                        "refused": s["refused"],
                        "timeouts": s["timeout"],
                        "nxdomain": s["nxdomain"],
                        "names": [n for n, _ in s["names"].most_common(5)],
                        "clients": sorted(s["clients"]),
                    },
                    benign_evidence=[
                        Evidence("Failures come from the network's normal DNS server and affect many different names: a server or upstream outage", 0.6)
                    ],
                )
            )
        return out
