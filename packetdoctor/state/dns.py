"""DNS query/response matching.

A query is identified by (client IP, client port, transaction id). Every
response is attached to its query, which lets detectors measure response
time, find unanswered queries, and spot *conflicting* responses to the same
query (a classic sign of forged DNS answers).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import PacketRecord
from .lru import LRUDict


@dataclass(slots=True)
class DnsResponse:
    ts: float
    idx: int
    src_ip: str
    src_mac: str | None
    rcode: int
    answers: tuple  # sorted A/AAAA/CNAME data
    min_ttl: int | None


@dataclass(slots=True)
class DnsQuery:
    ts: float
    idx: int
    client: str
    server: str
    qname: str
    qtype: int
    responses: list = field(default_factory=list)

    @property
    def answered(self) -> bool:
        return bool(self.responses)

    @property
    def first(self) -> DnsResponse | None:
        return self.responses[0] if self.responses else None


@dataclass(slots=True)
class DnsEvent:
    kind: str  # "query" | "response" | "unsolicited"
    query: DnsQuery | None = None
    response: DnsResponse | None = None
    rtt: float | None = None


class DnsTracker:
    def __init__(self, max_entries: int):
        self.queries: LRUDict[tuple, DnsQuery] = LRUDict(max_entries)
        self.unsolicited: list[DnsResponse] = []
        self.server_responses: dict[str, int] = {}
        self.pending: dict[tuple, tuple] = {}
        self.total_queries = 0

    def update(self, rec: PacketRecord) -> DnsEvent | None:
        dns = rec.dns
        if dns is None or not rec.src_ip or not rec.dst_ip:
            return None
        if not dns.is_response:
            base = (rec.src_ip, rec.sport, rec.dst_ip, rec.dport, rec.ip_proto, dns.txid, dns.qname, dns.qtype)
            previous = self.pending.get(base)
            old = self.queries.get(previous) if previous else None
            if old is not None and not old.answered and 0 <= rec.ts - old.ts <= 10:
                return DnsEvent(kind="query", query=old)
            key = (*base, rec.idx)
            q = DnsQuery(ts=rec.ts, idx=rec.idx, client=rec.src_ip, server=rec.dst_ip, qname=dns.qname, qtype=dns.qtype)
            self.queries.put(key, q)
            if len(self.pending) >= self.queries.maxlen:
                self.pending.pop(next(iter(self.pending)))
            self.pending[base] = key
            self.total_queries += 1
            return DnsEvent(kind="query", query=q)

        answers = tuple(sorted(a.data for a in dns.answers if a.rtype in (1, 5, 28)))
        ttls = [a.ttl for a in dns.answers if a.rtype in (1, 28)]
        resp = DnsResponse(
            ts=rec.ts,
            idx=rec.idx,
            src_ip=rec.src_ip,
            src_mac=rec.src_mac,
            rcode=dns.rcode,
            answers=answers,
            min_ttl=min(ttls) if ttls else None,
        )
        self.server_responses[rec.src_ip] = self.server_responses.get(rec.src_ip, 0) + 1
        base = (rec.dst_ip, rec.dport, rec.src_ip, rec.sport, rec.ip_proto, dns.txid, dns.qname, dns.qtype)
        key = self.pending.get(base)
        q = self.queries.get(key) if key else None
        if q is not None and not 0 <= rec.ts - q.ts <= 10:
            q = None
        if q is None:
            if len(self.unsolicited) < 1000:
                self.unsolicited.append(resp)
            return DnsEvent(kind="unsolicited", response=resp)
        if len(q.responses) < 8:
            q.responses.append(resp)
        return DnsEvent(kind="response", query=q, response=resp, rtt=rec.ts - q.ts)

    def all_queries(self) -> list[DnsQuery]:
        return list(self.queries.values())
