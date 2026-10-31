"""Generate the synthetic sample captures in this folder.

Everything here is built in memory with Scapy and written straight to .pcap
files: no packet is ever sent on a real network. The captures model a small
office LAN (192.168.1.0/24) behind a router that is also the DNS forwarder
and DHCP server.

    python samples/generate.py            # writes samples/*.pcap
    python samples/generate.py --out DIR  # somewhere else

Generation is deterministic (fixed random seed), so the files are stable.
"""

from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from packetdoctor._scapy import (  # noqa: E402
    ARP,
    BOOTP,
    DHCP,
    DNS,
    DNSQR,
    DNSRR,
    ICMP,
    IP,
    TCP,
    UDP,
    Ether,
    wrpcap,
)
from scapy.packet import Raw  # noqa: E402
from scapy.utils import wrpcapng  # noqa: E402

BASE_TS = 1793563200.0  # 2026-11-01 00:00 UTC, the hackathon day

# --- the simulated office ----------------------------------------------------
GW_IP, GW_MAC = "192.168.1.1", "00:1a:2b:3c:00:01"
LAPTOP, DESKTOP, PRINTER, PHONE = "192.168.1.10", "192.168.1.20", "192.168.1.30", "192.168.1.40"
ATTACKER_IP, ATTACKER_MAC = "192.168.1.66", "de:ad:be:ef:00:66"
NEW_DEVICE_MAC = "3c:22:fb:00:00:99"  # misconfigured device in the duplicate-IP case
GUEST_MAC = "3c:22:fb:00:00:77"  # laptop joining in the rogue-DHCP case
BROADCAST = "ff:ff:ff:ff:ff:ff"

MACS = {
    GW_IP: GW_MAC,
    LAPTOP: "3c:22:fb:00:00:10",
    DESKTOP: "3c:22:fb:00:00:20",
    PRINTER: "3c:22:fb:00:00:30",
    PHONE: "3c:22:fb:00:00:40",
    ATTACKER_IP: ATTACKER_MAC,
}
CLIENTS = [LAPTOP, DESKTOP, PHONE]

SITES = {
    "example.com": "93.184.216.34",
    "news.example.org": "151.101.1.69",
    "api.example.net": "140.82.112.3",
    "files.example.com": "203.0.113.50",
    "video.example.com": "198.51.100.20",
    "mail.example.com": "203.0.113.25",
    "mybank.example.com": "203.0.113.80",
}


def is_local(ip: str) -> bool:
    return ip.startswith("192.168.1.")


def mac_of(ip: str) -> str:
    return MACS.get(ip, GW_MAC) if is_local(ip) else GW_MAC


class Capture:
    """Collects packets with relative timestamps, then writes them in time order."""

    def __init__(self, seed: int):
        self.pkts: list = []
        self.rng = random.Random(seed)
        self.dns_ids = 0x1000

    def add(self, t: float, pkt) -> None:
        pkt.time = BASE_TS + t
        self.pkts.append(pkt)

    def next_txid(self) -> int:
        self.dns_ids += self.rng.randint(1, 97)
        return self.dns_ids & 0xFFFF

    def write(self, path: Path, ng: bool = False) -> int:
        self.pkts.sort(key=lambda p: float(p.time))
        (wrpcapng if ng else wrpcap)(str(path), self.pkts)
        return len(self.pkts)


# --- packet builders -----------------------------------------------------------


def eth(src_ip: str, dst_ip: str, src_mac: str | None = None, dst_mac: str | None = None):
    return Ether(src=src_mac or mac_of(src_ip), dst=dst_mac or mac_of(dst_ip))


def ip(src: str, dst: str, df: bool = True):
    ttl = 64 if is_local(src) else 54
    return IP(src=src, dst=dst, ttl=ttl, flags="DF" if df else 0)


def tcp_pkt(src, dst, sport, dport, flags, seq, ack, plen=0, window=64240, mss=None, df=True, src_mac=None, dst_mac=None):
    opts = [("MSS", mss)] if mss else []
    p = eth(src, dst, src_mac, dst_mac) / ip(src, dst, df) / TCP(
        sport=sport, dport=dport, flags=flags, seq=seq & 0xFFFFFFFF, ack=ack & 0xFFFFFFFF, window=window, options=opts
    )
    if plen:
        p = p / Raw(b"\x00" * plen)
    return p


def arp_exchange(cap: Capture, t: float, asker: str, target: str, answer_mac: str | None = None) -> None:
    cap.add(t, Ether(src=mac_of(asker), dst=BROADCAST) / ARP(op=1, hwsrc=mac_of(asker), psrc=asker, pdst=target))
    reply_mac = answer_mac or mac_of(target)
    cap.add(
        t + 0.0004,
        Ether(src=reply_mac, dst=mac_of(asker))
        / ARP(op=2, hwsrc=reply_mac, psrc=target, hwdst=mac_of(asker), pdst=asker),
    )


def dns_lookup(
    cap: Capture,
    t: float,
    client: str,
    name: str,
    *,
    answers: list[str] | None = None,
    rcode: int = 0,
    rtt: float = 0.012,
    server: str = GW_IP,
    respond: bool = True,
    ttl: int = 300,
) -> float:
    txid = cap.next_txid()
    sport = cap.rng.randint(49152, 65000)
    cap.add(t, eth(client, server) / ip(client, server, df=False) / UDP(sport=sport, dport=53) / DNS(id=txid, rd=1, qd=DNSQR(qname=name)))
    if not respond:
        return t
    if answers is None:
        answers = [SITES[name]] if (rcode == 0 and name in SITES) else []
    an = [DNSRR(rrname=name, rdata=a, ttl=ttl) for a in answers]
    cap.add(
        t + rtt,
        eth(server, client) / ip(server, client, df=False) / UDP(sport=53, dport=sport)
        / DNS(id=txid, qr=1, rd=1, ra=1, rcode=rcode, qd=DNSQR(qname=name), an=an),
    )
    return t + rtt


def tcp_session(
    cap: Capture,
    t: float,
    cli: str,
    srv: str,
    dport: int = 443,
    *,
    nseg: int = 6,
    seg: int = 1200,
    rtt: float = 0.02,
    upload: bool = False,
    lost: set[int] | None = None,
    rto: float = 0.3,
    close: str = "fin",
    mss: int = 1460,
    request: int = 320,
    rst_after: int | None = None,
    zero_window_stalls: int = 0,
) -> float:
    """Model one TCP connection as seen from a capture point near the client.

    ``lost`` holds the indexes of data segments whose first copy is lost and
    retransmitted after ``rto``; ``close`` is "fin", "rst" (server aborts) or
    "none" (connection left open at capture end).
    """
    rng = cap.rng
    lost = lost or set()
    sport = rng.randint(49152, 65000)
    c_isn, s_isn = rng.randint(1, 2**31), rng.randint(1, 2**31)
    half = rtt / 2
    cap.add(t, tcp_pkt(cli, srv, sport, dport, "S", c_isn, 0, mss=mss))
    cap.add(t + half, tcp_pkt(srv, cli, dport, sport, "SA", s_isn, c_isn + 1, mss=mss))
    cap.add(t + rtt, tcp_pkt(cli, srv, sport, dport, "A", c_isn + 1, s_isn + 1))
    cseq, sseq = c_isn + 1, s_isn + 1
    tt = t + rtt + 0.001
    cap.add(tt, tcp_pkt(cli, srv, sport, dport, "PA", cseq, sseq, plen=request))
    cseq += request
    tt += half if not upload else 0.001
    if not upload:
        cap.add(tt, tcp_pkt(srv, cli, dport, sport, "A", sseq, cseq))

    # bulk data in one direction
    if upload:
        snd, rcv, sp, dp = cli, srv, sport, dport
        seq0, ack_other = cseq, sseq
    else:
        snd, rcv, sp, dp = srv, cli, dport, sport
        seq0, ack_other = sseq, cseq
    deliveries = []  # (time, index)
    seq = seq0
    for i in range(nseg):
        if rst_after is not None and i == rst_after:
            cap.add(tt, tcp_pkt(srv, cli, dport, sport, "RA", sseq if not upload else sseq, cseq if not upload else seq))
            return tt
        cap.add(tt, tcp_pkt(snd, rcv, sp, dp, "PA", seq, ack_other, plen=seg))
        if i in lost:
            cap.add(tt + rto, tcp_pkt(snd, rcv, sp, dp, "PA", seq, ack_other, plen=seg))
            deliveries.append((tt + rto + half, i))
        else:
            deliveries.append((tt + half, i))
        seq += seg
        tt += 0.002
    received: set[int] = set()
    next_needed = 0
    stalls_left = zero_window_stalls
    last_t = tt
    for when, i in sorted(deliveries):
        received.add(i)
        while next_needed in received:
            next_needed += 1
        win = 64240
        if stalls_left and next_needed > 2:
            win = 0
            stalls_left -= 1
        cap.add(when, tcp_pkt(rcv, snd, dp, sp, "A", ack_other, seq0 + next_needed * seg, window=win))
        if win == 0:  # receiver application stalled, then window update later
            when += 1.5
            cap.add(when, tcp_pkt(rcv, snd, dp, sp, "A", ack_other, seq0 + next_needed * seg, window=64240))
        last_t = max(last_t, when)
    if upload:
        cseq = seq
    else:
        sseq = seq
    tt = last_t + 0.001
    if close == "fin":
        cap.add(tt, tcp_pkt(cli, srv, sport, dport, "FA", cseq, sseq))
        cap.add(tt + half, tcp_pkt(srv, cli, dport, sport, "FA", sseq, cseq + 1))
        cap.add(tt + rtt, tcp_pkt(cli, srv, sport, dport, "A", cseq + 1, sseq + 1))
        tt += rtt
    elif close == "rst":
        cap.add(tt + half, tcp_pkt(srv, cli, dport, sport, "RA", sseq, cseq))
        tt += half
    return tt


def browse(cap: Capture, t: float, client: str, site: str, rtt: float = 0.02, dns_rtt: float = 0.012, **kw) -> float:
    t2 = dns_lookup(cap, t, client, site, rtt=dns_rtt)
    return tcp_session(cap, t2 + 0.002, client, SITES[site], rtt=rtt, **kw)


def baseline(cap: Capture, t0: float, t1: float, clients=CLIENTS, *, avoid=(), rtt=0.02, step=(1.5, 3.5)) -> None:
    """Normal office chatter: ARP for the gateway, DNS lookups and short HTTPS sessions."""
    for i, c in enumerate(clients):
        arp_exchange(cap, t0 + 0.05 * i, c, GW_IP)
    names = [n for n in SITES if n not in avoid and n != "mybank.example.com"]
    t = t0 + 0.5
    while t < t1:
        client = cap.rng.choice(clients)
        browse(cap, t, client, cap.rng.choice(names), rtt=rtt * cap.rng.uniform(0.8, 1.3), nseg=cap.rng.randint(3, 8))
        t += cap.rng.uniform(*step)
    # periodic ARP cache refresh from the router
    t = t0 + 10
    while t < t1:
        arp_exchange(cap, t, GW_IP, cap.rng.choice(clients))
        t += 12


# --- scenarios ---------------------------------------------------------------


def scenario_clean(cap: Capture) -> None:
    """Healthy network. Includes harmless noise that must NOT raise alarms:
    a mistyped domain (NXDOMAIN) and a single isolated retransmission."""
    baseline(cap, 0, 60)
    dns_lookup(cap, 14.2, LAPTOP, "exmaple.com", rcode=3)
    dns_lookup(cap, 37.9, PHONE, "wpad.lan", rcode=3)
    browse(cap, 22.0, DESKTOP, "files.example.com", nseg=20, lost={7})


def scenario_retransmissions(cap: Capture) -> None:
    """A lossy path to one file server: many retransmissions, slow downloads."""
    baseline(cap, 0, 60)
    for k, t in enumerate((8.0, 21.0, 34.0, 47.0)):
        lost = set(cap.rng.sample(range(40), 9))
        browse(cap, t, LAPTOP, "files.example.com", nseg=40, lost=lost, rto=0.4 + 0.1 * k, rtt=0.035)


def scenario_resets(cap: Capture) -> None:
    """Printer service down (RST to every connection attempt) and a web API
    that aborts transfers half-way."""
    baseline(cap, 0, 60)
    for t in (5.0, 11.0, 17.0, 23.0, 29.0, 35.0):
        sport = cap.rng.randint(49152, 65000)
        isn = cap.rng.randint(1, 2**31)
        cap.add(t, tcp_pkt(DESKTOP, PRINTER, sport, 9100, "S", isn, 0, mss=1460))
        cap.add(t + 0.0007, tcp_pkt(PRINTER, DESKTOP, 9100, sport, "RA", 0, isn + 1))
    for t in (12.0, 26.0, 40.0, 52.0):
        browse(cap, t, PHONE, "api.example.net", nseg=10, rst_after=4)


def scenario_dns_failure(cap: Capture) -> None:
    """The DNS forwarder breaks between t=20s and t=45s: SERVFAIL and timeouts."""
    baseline(cap, 0, 20)
    t = 20.0
    while t < 45:
        client = cap.rng.choice(CLIENTS)
        name = cap.rng.choice(list(SITES)[:5])
        if cap.rng.random() < 0.6:
            dns_lookup(cap, t, client, name, rcode=2, rtt=0.9)
        else:
            dns_lookup(cap, t, client, name, respond=False)
            dns_lookup(cap, t + 2.0, client, name, respond=False)  # client retry
        t += cap.rng.uniform(0.8, 1.6)
    baseline(cap, 45, 60)


def scenario_duplicate_ip(cap: Capture) -> None:
    """A newly installed device is manually configured with the desktop's IP."""
    baseline(cap, 0, 60)
    new = NEW_DEVICE_MAC
    # boots at t=25, announces itself (gratuitous ARP), no conflict probe
    cap.add(25.0, Ether(src=new, dst=BROADCAST) / ARP(op=1, hwsrc=new, psrc=DESKTOP, hwdst="00:00:00:00:00:00", pdst=DESKTOP))
    # it then behaves like a normal host: asks for the gateway and browses
    cap.add(25.5, Ether(src=new, dst=BROADCAST) / ARP(op=1, hwsrc=new, psrc=DESKTOP, pdst=GW_IP))
    cap.add(25.5004, Ether(src=GW_MAC, dst=new) / ARP(op=2, hwsrc=GW_MAC, psrc=GW_IP, hwdst=new, pdst=DESKTOP))
    t = 26.0
    while t < 58:
        # traffic from the new device, using the same IP as the desktop
        sport = cap.rng.randint(49152, 65000)
        txid = cap.next_txid()
        cap.add(t, Ether(src=new, dst=GW_MAC) / ip(DESKTOP, GW_IP, False) / UDP(sport=sport, dport=53) / DNS(id=txid, rd=1, qd=DNSQR(qname="example.com")))
        cap.add(
            t + 0.012,
            Ether(src=GW_MAC, dst=new) / ip(GW_IP, DESKTOP, False) / UDP(sport=53, dport=sport)
            / DNS(id=txid, qr=1, rd=1, ra=1, qd=DNSQR(qname="example.com"), an=[DNSRR(rrname="example.com", rdata=SITES["example.com"], ttl=300)]),
        )
        isn = cap.rng.randint(1, 2**31)
        cap.add(t + 0.03, Ether(src=new, dst=GW_MAC) / ip(DESKTOP, "93.184.216.34") / TCP(sport=sport + 1, dport=443, flags="S", seq=isn))
        t += cap.rng.uniform(3, 5)
    # the router keeps asking who has .20 and gets two different answers
    for t in (30.0, 42.0, 54.0):
        cap.add(t, Ether(src=GW_MAC, dst=BROADCAST) / ARP(op=1, hwsrc=GW_MAC, psrc=GW_IP, pdst=DESKTOP))
        cap.add(t + 0.0004, Ether(src=MACS[DESKTOP], dst=GW_MAC) / ARP(op=2, hwsrc=MACS[DESKTOP], psrc=DESKTOP, hwdst=GW_MAC, pdst=GW_IP))
        cap.add(t + 0.0009, Ether(src=new, dst=GW_MAC) / ARP(op=2, hwsrc=new, psrc=DESKTOP, hwdst=GW_MAC, pdst=GW_IP))
    # the desktop's own connections break as replies go to the wrong device
    for t in (31.0, 43.0, 55.0):
        browse(cap, t, DESKTOP, "news.example.org", nseg=8, rst_after=3)


def scenario_mtu(cap: Capture) -> None:
    """Two MTU problems: (1) a router reports 'fragmentation needed' and the
    sender adapts; (2) a PMTU black hole where large segments silently vanish."""
    baseline(cap, 0, 60)
    srv = SITES["files.example.com"]
    t = 10.0
    sport, isn, sisn = 50123, 1000, 9000
    cap.add(t, tcp_pkt(LAPTOP, srv, sport, 443, "S", isn, 0, mss=1460))
    cap.add(t + 0.015, tcp_pkt(srv, LAPTOP, 443, sport, "SA", sisn, isn + 1, mss=1460))
    cap.add(t + 0.03, tcp_pkt(LAPTOP, srv, sport, 443, "A", isn + 1, sisn + 1))
    seq = isn + 1
    cap.add(t + 0.031, tcp_pkt(LAPTOP, srv, sport, 443, "PA", seq, sisn + 1, plen=1460))
    cap.add(
        t + 0.033,
        eth(GW_IP, LAPTOP) / IP(src=GW_IP, dst=LAPTOP) / ICMP(type=3, code=4, nexthopmtu=1400)
        / IP(src=LAPTOP, dst=srv, flags="DF", len=1500) / TCP(sport=sport, dport=443, seq=seq),
    )
    for k in range(6):  # sender adapts to 1360-byte segments
        cap.add(t + 0.04 + 0.002 * k, tcp_pkt(LAPTOP, srv, sport, 443, "PA", seq, sisn + 1, plen=1360))
        seq += 1360
        cap.add(t + 0.055 + 0.002 * k, tcp_pkt(srv, LAPTOP, 443, sport, "A", sisn + 1, seq))
    # black hole towards the video server
    vsrv = SITES["video.example.com"]
    for t in (20.0, 38.0):
        sport = cap.rng.randint(49152, 65000)
        isn, sisn = cap.rng.randint(1, 2**31), cap.rng.randint(1, 2**31)
        cap.add(t, tcp_pkt(LAPTOP, vsrv, sport, 443, "S", isn, 0, mss=1460))
        cap.add(t + 0.02, tcp_pkt(vsrv, LAPTOP, 443, sport, "SA", sisn, isn + 1, mss=1460))
        cap.add(t + 0.04, tcp_pkt(LAPTOP, vsrv, sport, 443, "A", isn + 1, sisn + 1))
        cap.add(t + 0.041, tcp_pkt(LAPTOP, vsrv, sport, 443, "PA", isn + 1, sisn + 1, plen=200))
        cap.add(t + 0.061, tcp_pkt(vsrv, LAPTOP, 443, sport, "A", sisn + 1, isn + 201))
        seq = isn + 201
        rto = 0.3
        tt = t + 0.07
        for _ in range(5):  # full-size segment never acknowledged
            cap.add(tt, tcp_pkt(LAPTOP, vsrv, sport, 443, "PA", seq, sisn + 1, plen=1460))
            tt += rto
            rto *= 2
        cap.add(tt, tcp_pkt(LAPTOP, vsrv, sport, 443, "RA", seq, sisn + 1))


def scenario_latency(cap: Capture) -> None:
    """Internet link congested from t=30s to t=50s: slow handshakes and DNS,
    plus a receiver whose application stalls (TCP zero window)."""
    baseline(cap, 0, 30, step=(1.0, 2.0))
    t = 30.0
    while t < 50:
        client = cap.rng.choice(CLIENTS)
        site = cap.rng.choice(list(SITES)[:5])
        browse(cap, t, client, site, rtt=cap.rng.uniform(0.9, 1.6), dns_rtt=cap.rng.uniform(0.8, 1.4), nseg=4)
        t += cap.rng.uniform(1.0, 2.0)
    baseline(cap, 50, 70, step=(1.0, 2.0))
    browse(cap, 12.0, PRINTER, "files.example.com", nseg=12, zero_window_stalls=3)


def scenario_port_scan(cap: Capture) -> None:
    """A device on the LAN scans the desktop (vertical) and then sweeps the subnet for SSH."""
    baseline(cap, 0, 60)
    open_ports = {22, 80, 445}
    ports = list(range(1, 1025))
    cap.rng.shuffle(ports)
    t = 15.0
    target = DESKTOP
    for port in ports[:300] + [22, 80, 445]:
        sport = 40000 + (port % 2000)
        isn = cap.rng.randint(1, 2**31)
        cap.add(t, tcp_pkt(ATTACKER_IP, target, sport, port, "S", isn, 0, window=1024, mss=1460))
        if port in open_ports:
            cap.add(t + 0.0005, tcp_pkt(target, ATTACKER_IP, port, sport, "SA", 777, isn + 1, mss=1460))
            cap.add(t + 0.0008, tcp_pkt(ATTACKER_IP, target, sport, port, "R", isn + 1, 0))
        else:
            cap.add(t + 0.0005, tcp_pkt(target, ATTACKER_IP, port, sport, "RA", 0, isn + 1))
        t += 0.008
    t = 35.0
    for host in range(2, 80):
        dst = f"192.168.1.{host}"
        if dst == ATTACKER_IP:
            continue
        cap.add(t, tcp_pkt(ATTACKER_IP, dst, 41000 + host, 22, "S", cap.rng.randint(1, 2**31), 0, window=1024, mss=1460, dst_mac=mac_of(dst)))
        t += 0.02


def _arp_poison(cap: Capture, start: float, end: float, victim: str, interval: float = 2.0) -> None:
    """Attacker repeatedly tells the victim 'the gateway is at my MAC' and
    tells the gateway 'the victim is at my MAC'."""
    t = start
    while t < end:
        cap.add(t, Ether(src=ATTACKER_MAC, dst=mac_of(victim)) / ARP(op=2, hwsrc=ATTACKER_MAC, psrc=GW_IP, hwdst=mac_of(victim), pdst=victim))
        cap.add(t + 0.001, Ether(src=ATTACKER_MAC, dst=GW_MAC) / ARP(op=2, hwsrc=ATTACKER_MAC, psrc=victim, hwdst=GW_MAC, pdst=GW_IP))
        t += interval


def _mitm_relay(cap: Capture, victim: str, start: float) -> None:
    """After poisoning, the victim's internet traffic physically flows through
    the attacker: each packet is seen twice on the mirrored switch port."""
    out = []
    for p in cap.pkts:
        t = float(p.time) - BASE_TS
        if t >= start and p.haslayer(IP) and victim in (p[IP].src, p[IP].dst):
            other = p[IP].dst if p[IP].src == victim else p[IP].src
            if is_local(other):
                out.append(p)
                continue
            first, second = p.copy(), p.copy()
            if p[IP].src == victim:
                first[Ether].dst = ATTACKER_MAC
                second[Ether].src, second[Ether].dst = ATTACKER_MAC, GW_MAC
            else:
                first[Ether].dst = ATTACKER_MAC
                second[Ether].src, second[Ether].dst = ATTACKER_MAC, mac_of(victim)
            first.time = p.time
            second.time = p.time + 0.0006
            out.extend([first, second])
        else:
            out.append(p)
    cap.pkts = out


def scenario_arp_spoof(cap: Capture) -> None:
    """Man-in-the-middle: 192.168.1.66 poisons the laptop and the router."""
    baseline(cap, 0, 70)
    arp_exchange(cap, 3.0, ATTACKER_IP, GW_IP)
    browse(cap, 5.0, ATTACKER_IP, "example.com")
    _arp_poison(cap, 20.0, 70.0, LAPTOP)
    for t in (24.0, 36.0, 48.0, 60.0):
        browse(cap, t, LAPTOP, cap.rng.choice(["mail.example.com", "news.example.org"]), nseg=6)
    _mitm_relay(cap, LAPTOP, 20.5)


def scenario_dns_hijack(cap: Capture) -> None:
    """A device races the real DNS server with forged answers that send the
    laptop to 192.168.1.66 for the bank and mail sites."""
    baseline(cap, 0, 60, avoid=("mail.example.com",))
    for t, name in ((15.0, "mybank.example.com"), (28.0, "mail.example.com"), (41.0, "mybank.example.com"), (52.0, "mail.example.com")):
        txid = cap.next_txid()
        sport = cap.rng.randint(49152, 65000)
        q = DNSQR(qname=name)
        cap.add(t, eth(LAPTOP, GW_IP) / ip(LAPTOP, GW_IP, False) / UDP(sport=sport, dport=53) / DNS(id=txid, rd=1, qd=q))
        # forged answer: spoofed source IP of the real resolver, but sent from the attacker's MAC
        cap.add(
            t + 0.0015,
            Ether(src=ATTACKER_MAC, dst=mac_of(LAPTOP)) / ip(GW_IP, LAPTOP, False) / UDP(sport=53, dport=sport)
            / DNS(id=txid, qr=1, aa=1, rd=1, ra=1, qd=q, an=[DNSRR(rrname=name, rdata=ATTACKER_IP, ttl=10)]),
        )
        # the real answer arrives later and is ignored by the victim
        cap.add(
            t + 0.024,
            eth(GW_IP, LAPTOP) / ip(GW_IP, LAPTOP, False) / UDP(sport=53, dport=sport)
            / DNS(id=txid, qr=1, rd=1, ra=1, qd=q, an=[DNSRR(rrname=name, rdata=SITES[name], ttl=300)]),
        )
        tcp_session(cap, t + 0.03, LAPTOP, ATTACKER_IP, 443, rtt=0.001, nseg=4)


def scenario_rogue_dhcp(cap: Capture) -> None:
    """A guest laptop joins; a rogue DHCP server answers first and hands out
    itself as gateway and DNS server."""
    baseline(cap, 0, 60)
    # a normal lease renewal with the real server, before the rogue appears
    _dhcp(cap, 4.0, MACS[PHONE], 0xA1, [(GW_IP, GW_IP, GW_IP, PHONE, 0.003)], renew=True)
    _dhcp(cap, 20.0, GUEST_MAC, 0xB2, [(ATTACKER_IP, ATTACKER_IP, ATTACKER_IP, "192.168.1.150", 0.002), (GW_IP, GW_IP, GW_IP, "192.168.1.101", 0.040)])
    guest_ip = "192.168.1.150"
    MACS[guest_ip] = GUEST_MAC
    try:
        cap.add(20.2, Ether(src=GUEST_MAC, dst=BROADCAST) / ARP(op=1, hwsrc=GUEST_MAC, psrc=guest_ip, pdst=ATTACKER_IP))
        cap.add(20.2004, Ether(src=ATTACKER_MAC, dst=GUEST_MAC) / ARP(op=2, hwsrc=ATTACKER_MAC, psrc=ATTACKER_IP, hwdst=GUEST_MAC, pdst=guest_ip))
        t = 21.0
        while t < 58:
            name = cap.rng.choice(["example.com", "mybank.example.com", "mail.example.com"])
            dns_lookup(cap, t, guest_ip, name, server=ATTACKER_IP, answers=[ATTACKER_IP], ttl=30)
            t += cap.rng.uniform(2, 4)
    finally:
        del MACS[guest_ip]
    # second DHCP exchange: the rogue answers again
    _dhcp(cap, 45.0, "3c:22:fb:00:00:55", 0xC3, [(ATTACKER_IP, ATTACKER_IP, ATTACKER_IP, "192.168.1.151", 0.002), (GW_IP, GW_IP, GW_IP, "192.168.1.102", 0.035)])


def _dhcp(cap: Capture, t: float, client_mac: str, xid: int, offers, renew: bool = False) -> None:
    """offers: list of (server_ip, router, dns, offered_ip, delay). The client
    accepts the first offer to arrive."""
    chaddr = bytes.fromhex(client_mac.replace(":", "")) + b"\x00" * 10
    def bootp(op, yiaddr="0.0.0.0"):
        return BOOTP(op=op, xid=xid, chaddr=chaddr, yiaddr=yiaddr)
    def frm(src_mac, src_ip, dst_mac, dst_ip):
        return Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip, ttl=64) / UDP(
            sport=68 if src_ip in ("0.0.0.0",) or src_mac == client_mac else 67,
            dport=67 if src_mac == client_mac else 68,
        )
    first = min(offers, key=lambda o: o[4])
    if not renew:
        cap.add(t, frm(client_mac, "0.0.0.0", BROADCAST, "255.255.255.255") / bootp(1) / DHCP(options=[("message-type", "discover"), "end"]))
        for server, router, dns, offered, delay in offers:
            cap.add(
                t + delay,
                frm(mac_of(server), server, BROADCAST, "255.255.255.255") / bootp(2, offered)
                / DHCP(options=[("message-type", "offer"), ("server_id", server), ("router", router), ("name_server", dns), ("lease_time", 3600), "end"]),
            )
        t += max(o[4] for o in offers) + 0.01
    server, router, dns, offered, _ = first
    cap.add(t, frm(client_mac, "0.0.0.0", BROADCAST, "255.255.255.255") / bootp(1) / DHCP(options=[("message-type", "request"), ("server_id", server), ("requested_addr", offered), "end"]))
    cap.add(
        t + 0.002,
        frm(mac_of(server), server, BROADCAST, "255.255.255.255") / bootp(2, offered)
        / DHCP(options=[("message-type", "ack"), ("server_id", server), ("router", router), ("name_server", dns), ("lease_time", 3600), "end"]),
    )


def scenario_mixed(cap: Capture) -> None:
    """The showcase: a fault and attacks hidden in the same 90 seconds.

    * t=10-13  port scan from 192.168.1.66 (attack)
    * t=30-45  DNS forwarder outage, SERVFAIL/timeouts (fault)
    * t=55-90  ARP spoofing MITM of the laptop; the attacker's relay is slow
               and drops packets, so the laptop sees retransmissions (attack,
               with retransmissions as a consequence)
    """
    baseline(cap, 0, 30)
    baseline(cap, 45, 55)
    # port scan
    t = 10.0
    for port in list(range(20, 140)) + [443, 3389, 8080]:
        isn = cap.rng.randint(1, 2**31)
        cap.add(t, tcp_pkt(ATTACKER_IP, DESKTOP, 45000, port, "S", isn, 0, window=1024, mss=1460))
        if port in (22, 80, 443):
            cap.add(t + 0.0005, tcp_pkt(DESKTOP, ATTACKER_IP, port, 45000, "SA", 1, isn + 1, mss=1460))
            cap.add(t + 0.0009, tcp_pkt(ATTACKER_IP, DESKTOP, 45000, port, "R", isn + 1, 0))
        else:
            cap.add(t + 0.0005, tcp_pkt(DESKTOP, ATTACKER_IP, port, 45000, "RA", 0, isn + 1))
        t += 0.02
    # DNS outage
    t = 30.0
    while t < 45:
        client = cap.rng.choice(CLIENTS)
        name = cap.rng.choice(list(SITES)[:5])
        if cap.rng.random() < 0.6:
            dns_lookup(cap, t, client, name, rcode=2, rtt=0.8)
        else:
            dns_lookup(cap, t, client, name, respond=False)
        t += cap.rng.uniform(0.7, 1.4)
    # ARP spoofing MITM with packet loss in the attacker's relay
    _arp_poison(cap, 55.0, 90.0, LAPTOP)
    baseline(cap, 55, 90, clients=[DESKTOP, PHONE])
    for t in (58.0, 66.0, 74.0, 82.0):
        browse(cap, t, LAPTOP, "files.example.com", nseg=30, lost=set(cap.rng.sample(range(30), 7)), rto=0.35)
    _mitm_relay(cap, LAPTOP, 55.5)


def scenario_gateway_down(cap: Capture) -> None:
    """The router crashes at t=30s: ARP for it goes unanswered, DNS (served by
    the router) times out, and a device renewing its lease gets no answer."""
    baseline(cap, 0, 30)
    t = 30.0
    while t < 60:
        for i, c in enumerate(CLIENTS):
            cap.add(t + 0.1 * i, Ether(src=mac_of(c), dst=BROADCAST) / ARP(op=1, hwsrc=mac_of(c), psrc=c, pdst=GW_IP))
        client = cap.rng.choice(CLIENTS)
        dns_lookup(cap, t + 0.5, client, cap.rng.choice(list(SITES)[:5]), respond=False)
        t += cap.rng.uniform(1.5, 3.0)
    chaddr = bytes.fromhex(MACS[PHONE].replace(":", "")) + b"\x00" * 10
    for k in range(5):
        cap.add(
            35.0 + 4 * k,
            Ether(src=MACS[PHONE], dst=BROADCAST) / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67)
            / BOOTP(op=1, xid=0xD1, chaddr=chaddr) / DHCP(options=[("message-type", "discover"), "end"]),
        )


def scenario_dhcp_starvation(cap: Capture) -> None:
    """A device floods the DHCP server with requests from 150 invented MAC
    addresses and empties the pool; a real visitor then cannot join."""
    baseline(cap, 0, 60)
    t = 15.0
    for k in range(150):
        fake = "02:%02x:%02x:%02x:%02x:%02x" % tuple(cap.rng.randrange(256) for _ in range(5))
        chaddr = bytes.fromhex(fake.replace(":", "")) + b"\x00" * 10
        xid = 0x5000 + k
        disc = Ether(src=ATTACKER_MAC, dst=BROADCAST) / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / BOOTP(op=1, xid=xid, chaddr=chaddr) / DHCP(options=[("message-type", "discover"), "end"])
        cap.add(t, disc)
        if k < 40:  # pool has 40 free addresses
            offered = f"192.168.1.{100 + k}"
            cap.add(t + 0.003, Ether(src=GW_MAC, dst=BROADCAST) / IP(src=GW_IP, dst="255.255.255.255") / UDP(sport=67, dport=68) / BOOTP(op=2, xid=xid, chaddr=chaddr, yiaddr=offered) / DHCP(options=[("message-type", "offer"), ("server_id", GW_IP), ("router", GW_IP), ("name_server", GW_IP), "end"]))
            cap.add(t + 0.005, Ether(src=ATTACKER_MAC, dst=BROADCAST) / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / BOOTP(op=1, xid=xid, chaddr=chaddr) / DHCP(options=[("message-type", "request"), ("server_id", GW_IP), ("requested_addr", offered), "end"]))
            cap.add(t + 0.007, Ether(src=GW_MAC, dst=BROADCAST) / IP(src=GW_IP, dst="255.255.255.255") / UDP(sport=67, dport=68) / BOOTP(op=2, xid=xid, chaddr=chaddr, yiaddr=offered) / DHCP(options=[("message-type", "ack"), ("server_id", GW_IP), ("router", GW_IP), ("name_server", GW_IP), "end"]))
        t += 0.04
    chaddr = bytes.fromhex(GUEST_MAC.replace(":", "")) + b"\x00" * 10
    for k in range(5):  # the real visitor's laptop retries and gives up
        cap.add(30.0 + 3 * k, Ether(src=GUEST_MAC, dst=BROADCAST) / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / BOOTP(op=1, xid=0xE1, chaddr=chaddr) / DHCP(options=[("message-type", "discover"), "end"]))


def scenario_arp_sweep(cap: Capture) -> None:
    """A laptop walks through every address of the subnet with ARP (host
    discovery, as done by network scanners), slowly enough to look quiet."""
    baseline(cap, 0, 70)
    t = 10.0
    for host in range(2, 255):
        dst = f"192.168.1.{host}"
        if dst == ATTACKER_IP:
            continue
        cap.add(t, Ether(src=ATTACKER_MAC, dst=BROADCAST) / ARP(op=1, hwsrc=ATTACKER_MAC, psrc=ATTACKER_IP, pdst=dst))
        if dst in MACS:
            cap.add(t + 0.0004, Ether(src=MACS[dst], dst=ATTACKER_MAC) / ARP(op=2, hwsrc=MACS[dst], psrc=dst, hwdst=ATTACKER_MAC, pdst=ATTACKER_IP))
        t += 0.2


def scenario_fragment_attack(cap: Capture) -> None:
    """Teardrop-style overlapping fragments and tiny TCP fragments aimed at the desktop."""
    baseline(cap, 0, 40)
    t = 12.0
    for k in range(8):
        pid = 0x4000 + k
        first = eth(ATTACKER_IP, DESKTOP) / IP(src=ATTACKER_IP, dst=DESKTOP, id=pid, flags="MF", proto=17) / Raw(b"\x00" * 36)
        overlap = eth(ATTACKER_IP, DESKTOP) / IP(src=ATTACKER_IP, dst=DESKTOP, id=pid, frag=3, proto=17) / Raw(b"\x00" * 4)
        cap.add(t, first)
        cap.add(t + 0.0005, overlap)
        t += 1.5
    for k in range(4):
        pid = 0x4100 + k
        tiny = eth(ATTACKER_IP, DESKTOP) / IP(src=ATTACKER_IP, dst=DESKTOP, id=pid, flags="MF", proto=6) / Raw(b"\x00" * 8)
        rest = eth(ATTACKER_IP, DESKTOP) / IP(src=ATTACKER_IP, dst=DESKTOP, id=pid, frag=1, proto=6) / Raw(b"\x00" * 32)
        cap.add(t, tiny)
        cap.add(t + 0.0005, rest)
        t += 1.0
    # legitimate fragmentation (a large UDP datagram) must not be flagged
    for k in range(3):
        pid = 0x4200 + k
        cap.add(t, eth(LAPTOP, GW_IP) / IP(src=LAPTOP, dst="203.0.113.50", id=pid, flags="MF", proto=17) / Raw(b"\x00" * 1480))
        cap.add(t + 0.0003, eth(LAPTOP, GW_IP) / IP(src=LAPTOP, dst="203.0.113.50", id=pid, frag=185, proto=17) / Raw(b"\x00" * 600))
        t += 0.5


SCENARIOS = {
    "clean": scenario_clean,
    "tcp_retransmissions": scenario_retransmissions,
    "tcp_resets": scenario_resets,
    "dns_failure": scenario_dns_failure,
    "duplicate_ip": scenario_duplicate_ip,
    "mtu_problems": scenario_mtu,
    "high_latency": scenario_latency,
    "port_scan": scenario_port_scan,
    "arp_spoofing": scenario_arp_spoof,
    "dns_hijack": scenario_dns_hijack,
    "rogue_dhcp": scenario_rogue_dhcp,
    "mixed_fault_and_attack": scenario_mixed,
    "gateway_down": scenario_gateway_down,
    "dhcp_starvation": scenario_dhcp_starvation,
    "arp_sweep": scenario_arp_sweep,
    "ip_fragment_attack": scenario_fragment_attack,
}


def generate(out_dir: Path) -> dict[str, int]:
    out_dir.mkdir(parents=True, exist_ok=True)
    counts = {}
    for i, (name, fn) in enumerate(SCENARIOS.items()):
        cap = Capture(seed=1000 + i)
        fn(cap)
        counts[name] = cap.write(out_dir / f"{name}.pcap")
    # the same healthy capture in pcapng format, to exercise that reader
    cap = Capture(seed=1000)
    scenario_clean(cap)
    counts["clean (pcapng)"] = cap.write(out_dir / "clean.pcapng", ng=True)
    return counts


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    for name, n in generate(args.out).items():
        print(f"{name:28s} {n:6d} packets")
