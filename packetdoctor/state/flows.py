"""Bidirectional TCP flow tracking.

Sequence numbers are made relative to each side's initial sequence number,
so comparisons are simple integers. For every data segment we decide
whether it is new data or a retransmission, and if so which kind:

* ``fast``     the receiver had already sent 3+ duplicate ACKs asking for it
* ``spurious`` the receiver had already acknowledged that data
* ``timeout``  anything else (the sender's retransmission timer fired)
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from ..models import TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN, PacketRecord
from .lru import LRUDict, add_capped

MASK = 0xFFFFFFFF
HALF = 0x7FFFFFFF
MAX_SEG_TRACK = 4096
MAX_HOLES = 256
REORDER_WINDOW = 0.02  # a gap filled faster than this is reordering, not loss


def rel(seq: int, base: int) -> int:
    return (seq - base) & MASK


@dataclass(slots=True)
class Direction:
    base: int | None = None
    next_rel: int = 0  # end of the highest data seen
    acked: int = 0  # highest cumulative ACK from the peer, relative to our base
    mss: int | None = None
    packets: int = 0
    bytes: int = 0
    data_segments: int = 0
    retrans: int = 0
    retrans_kinds: Counter = field(default_factory=Counter)
    retrans_ids: list = field(default_factory=list)
    retrans_first: float | None = None
    retrans_last: float | None = None
    dupacks: dict = field(default_factory=dict)  # our rel seq -> duplicate ACKs the peer sent for it
    segs: dict = field(default_factory=dict)  # rel seq -> [tx count, size, first idx, last ts, acked?]
    zero_windows: int = 0
    zero_window_ids: list = field(default_factory=list)
    last_ack_sent: int | None = None
    holes: list = field(default_factory=list)  # (start, end, ts) gaps in the data seen so far
    reordered: int = 0


@dataclass(slots=True)
class Flow:
    client: tuple
    server: tuple
    first_ts: float
    last_ts: float
    first_idx: int
    syn_ts: float | None = None
    syn_idx: int | None = None
    synack_ts: float | None = None
    ack_ts: float | None = None
    syn_count: int = 0
    established: bool = False
    fin_seen: bool = False
    rst_by: int | None = None  # 0 = client, 1 = server
    rst_ts: float | None = None
    rst_idx: int | None = None
    rst_after_data: bool = False
    src_macs: set = field(default_factory=set)
    dirs: tuple = field(default_factory=lambda: (Direction(), Direction()))

    @property
    def handshake_rtt(self) -> float | None:
        if self.syn_ts is not None and self.synack_ts is not None and 0 <= self.synack_ts - self.syn_ts < 60:
            return self.synack_ts - self.syn_ts
        return None

    @property
    def data_bytes(self) -> int:
        return self.dirs[0].bytes + self.dirs[1].bytes

    @property
    def refused(self) -> bool:
        """Server answered the SYN with a reset (port closed / service down)."""
        return self.rst_by == 1 and self.synack_ts is None and self.syn_ts is not None


@dataclass(slots=True)
class TcpEvent:
    flow: Flow
    direction: int
    retrans: str | None = None  # "fast" / "spurious" / "timeout"
    new_flow: bool = False


class FlowTable:
    def __init__(self, max_flows: int):
        self.flows: LRUDict[tuple, Flow] = LRUDict(max_flows)
        self.total_flows = 0
        self.retired: list[Flow] = []
        self.retired_dropped = 0
        self.flows.on_evict = lambda key, flow: self._archive(flow)

    def _archive(self, flow):
        relevant = flow.rst_by is not None or flow.handshake_rtt is not None or any(direction.retrans or direction.zero_windows for direction in flow.dirs)
        if not relevant:
            return
        if len(self.retired) >= min(self.flows.maxlen, 20_000):
            self.retired_dropped += 1
            return
        for direction in flow.dirs:
            direction.segs = {sequence: segment for sequence, segment in direction.segs.items() if segment[0] >= 3 and segment[1] >= 1200}
            direction.holes.clear()
            direction.dupacks.clear()
        self.retired.append(flow)

    def all_flows(self):
        yield from self.retired
        yield from self.flows.values()

    @staticmethod
    def key(rec: PacketRecord) -> tuple:
        a = (rec.src_ip, rec.sport)
        b = (rec.dst_ip, rec.dport)
        return (a, b) if a <= b else (b, a)

    def update(self, rec: PacketRecord) -> TcpEvent:
        flags = rec.tcp_flags or 0
        key = self.key(rec)
        flow = self.flows.get(key)
        if flow is not None and flags & TCP_SYN and not flags & TCP_ACK:
            reused = flow.rst_by is not None or flow.fin_seen or rec.ts - flow.last_ts > 120
            if reused:
                self._archive(flow)
                self.flows.pop(key)
                flow = None
        new = flow is None
        if new:
            src, dst = (rec.src_ip, rec.sport), (rec.dst_ip, rec.dport)
            if flags & TCP_SYN and flags & TCP_ACK:
                client, server = dst, src  # we only saw the SYN-ACK
            elif flags & TCP_SYN:
                client, server = src, dst
            else:  # picked up mid-stream: the side with the ephemeral port is the client
                client, server = (src, dst) if (rec.sport or 0) >= (rec.dport or 0) else (dst, src)
            flow = Flow(client=client, server=server, first_ts=rec.ts, last_ts=rec.ts, first_idx=rec.idx)
            self.flows.put(key, flow)
            self.total_flows += 1
        else:
            self.flows.move_to_end(key)
        flow.last_ts = max(flow.last_ts, rec.ts)
        if rec.src_mac and len(flow.src_macs) < 8:
            flow.src_macs.add(rec.src_mac)

        d = 0 if (rec.src_ip, rec.sport) == flow.client else 1
        me, peer = flow.dirs[d], flow.dirs[1 - d]
        me.packets += 1
        event = TcpEvent(flow=flow, direction=d, new_flow=new)
        seq = rec.seq or 0

        if flags & TCP_SYN:
            me.base = seq
            me.next_rel = max(me.next_rel, 1)  # the SYN uses one sequence number
            if rec.mss:
                me.mss = rec.mss
            if flags & TCP_ACK:
                if flow.synack_ts is None:
                    flow.synack_ts = rec.ts
            else:
                flow.syn_count += 1
                if flow.syn_ts is None:
                    flow.syn_ts, flow.syn_idx = rec.ts, rec.idx
        elif me.base is None:
            me.base = (seq - 1) & MASK  # mid-stream: pretend the ISN was just before
            me.next_rel = 1

        # Acknowledgements (what the peer's data has reached)
        if flags & TCP_ACK and peer.base is not None and not flags & TCP_RST:
            ack_rel = rel(rec.ack or 0, peer.base)
            if ack_rel < HALF:
                if ack_rel > peer.acked:
                    peer.acked = ack_rel
                elif (
                    ack_rel == peer.acked
                    and rec.payload_len == 0
                    and not flags & (TCP_SYN | TCP_FIN)
                    and me.last_ack_sent == ack_rel
                    and rec.window != 0
                ):
                    if len(peer.dupacks) > MAX_SEG_TRACK:
                        peer.dupacks.clear()
                    peer.dupacks[ack_rel] = peer.dupacks.get(ack_rel, 0) + 1
                me.last_ack_sent = ack_rel
            if d == 0 and not flags & TCP_SYN and flow.synack_ts is not None and flow.ack_ts is None:
                flow.ack_ts = rec.ts
                flow.established = True

        # Data
        if rec.payload_len > 0 and me.base is not None:
            flow.established = flow.established or flow.synack_ts is not None or flow.syn_ts is None
            r = rel(seq, me.base)
            end = r + rec.payload_len
            me.data_segments += 1
            me.bytes += rec.payload_len
            kind = None
            if r < me.next_rel and end <= me.next_rel and r < HALF:
                hole = _take_hole(me, r, end) if r not in me.segs else None
                if hole is not None:
                    # data we never saw before, filling a gap: it was lost
                    # *before* the capture point and re-sent (or just reordered)
                    if rec.ts - hole[2] > REORDER_WINDOW:
                        kind = "lost_before_capture"
                    else:
                        me.reordered += 1
                elif peer_acked_beyond(me, end):
                    kind = "spurious"
                elif me.dupacks.get(r, 0) >= 3:
                    kind = "fast"
                else:
                    kind = "timeout"
            elif r > me.next_rel and me.next_rel > 0 and r < HALF and len(me.holes) < MAX_HOLES:
                me.holes.append((me.next_rel, r, rec.ts))
            if kind is not None:
                me.retrans += 1
                me.retrans_kinds[kind] += 1
                add_capped(me.retrans_ids, rec.idx, 200)
                if me.retrans_first is None:
                    me.retrans_first = rec.ts
                me.retrans_last = rec.ts
                event.retrans = kind
            if end > me.next_rel and r < HALF:
                me.next_rel = end
            seg = me.segs.get(r)
            if seg is None:
                if len(me.segs) >= MAX_SEG_TRACK:
                    me.segs.pop(next(iter(me.segs)))
                me.segs[r] = [1, rec.payload_len, rec.idx, rec.ts]
            else:
                seg[0] += 1
                seg[3] = rec.ts

        if flags & TCP_FIN:
            flow.fin_seen = True
        if flags & TCP_RST and flow.rst_by is None:
            flow.rst_by, flow.rst_ts, flow.rst_idx = d, rec.ts, rec.idx
            flow.rst_after_data = (flow.dirs[0].bytes + flow.dirs[1].bytes) > 0

        if (
            flags & TCP_ACK
            and rec.window == 0
            and not flags & (TCP_RST | TCP_SYN | TCP_FIN)
        ):
            me.zero_windows += 1
            add_capped(me.zero_window_ids, rec.idx, 50)
        return event


def peer_acked_beyond(direction: Direction, end: int) -> bool:
    return direction.acked >= end


def _take_hole(direction: Direction, start: int, end: int):
    """Find (and shrink or remove) the sequence gap that [start, end) fills."""
    for i, (h0, h1, ts) in enumerate(direction.holes):
        if h0 <= start < h1:
            del direction.holes[i]
            if h0 < start:
                direction.holes.append((h0, start, ts))
            if end < h1:
                direction.holes.append((end, h1, ts))
            return (h0, h1, ts)
    return None
