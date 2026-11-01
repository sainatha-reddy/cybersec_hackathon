"""Accuracy benchmark on randomised, labelled synthetic captures.

Every case is a fresh 120-second capture: background office traffic at a
random rate, plus 0-2 *problems* (each with randomised parameters: loss rate,
scan speed, poisoning interval, outage length, ...) and 0-3 *hard negatives*,
benign situations chosen because they resemble problems (a busy client, a
backup DHCP server, a router failover, split-horizon DNS, CDN answer rotation,
legitimate fragmentation, browsers resetting connections, ...).

For each problem we check that it was found and given the right verdict; for
cases without problems we check that nothing was reported as an attack.

    python benchmark/run.py                 # 300 cases, writes docs/EVALUATION.md
    python benchmark/run.py --cases 50 --seed 7 --no-write
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import tempfile
import time
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scapy.layers.dhcp import BOOTP, DHCP  # noqa: E402
from scapy.layers.dns import DNS, DNSQR, DNSRR  # noqa: E402
from scapy.layers.inet import IP, UDP  # noqa: E402
from scapy.layers.l2 import ARP, Ether  # noqa: E402
from scapy.packet import Raw  # noqa: E402

from packetdoctor.engine import analyze  # noqa: E402
from samples import generate as g  # noqa: E402

DURATION = 120.0
SLOTS = [(8.0, 52.0), (62.0, 110.0)]  # problems are placed in separate time slots
NAMES = list(g.SITES)[:6]


# --- problems: each returns the (verdict, kind) it should produce -------------------


def p_retrans(cap, t0, t1, rng):
    t = t0
    while t < t1 - 8:
        n = rng.randint(25, 45)
        lost = set(rng.sample(range(n), max(3, int(n * rng.uniform(0.1, 0.3)))))
        g.browse(cap, t, rng.choice(g.CLIENTS), "files.example.com", nseg=n, lost=lost, rto=rng.uniform(0.2, 0.6), rtt=rng.uniform(0.02, 0.06))
        t += rng.uniform(5, 12)
    return ("FAULT", "tcp_retransmissions")


def p_refused(cap, t0, t1, rng):
    port = rng.choice([9100, 515, 631, 445, 8080])
    client = rng.choice(g.CLIENTS)
    for k in range(rng.randint(4, 9)):
        t = t0 + k * rng.uniform(1, 4)
        isn = rng.randint(1, 2**31)
        sport = rng.randint(49152, 65000)
        cap.add(t, g.tcp_pkt(client, g.PRINTER, sport, port, "S", isn, 0, mss=1460))
        cap.add(t + 0.0008, g.tcp_pkt(g.PRINTER, client, port, sport, "RA", 0, isn + 1))
    return ("FAULT", "tcp_connection_refused")


def p_aborted(cap, t0, t1, rng):
    for k in range(rng.randint(3, 6)):
        g.browse(cap, t0 + k * rng.uniform(2, 6), rng.choice(g.CLIENTS), "api.example.net", nseg=10, rst_after=rng.randint(1, 6))
    return ("FAULT", "tcp_connection_aborted")


def p_dns_outage(cap, t0, t1, rng):
    end = t0 + rng.uniform(10, min(30, t1 - t0))
    share = rng.uniform(0.3, 0.9)
    t = t0
    while t < end:
        client, name = rng.choice(g.CLIENTS), rng.choice(NAMES)
        if rng.random() < share:
            g.dns_lookup(cap, t, client, name, rcode=rng.choice([2, 2, 5]), rtt=rng.uniform(0.05, 1.0))
        else:
            g.dns_lookup(cap, t, client, name, respond=False)
        t += rng.uniform(0.5, 1.8)
    return ("FAULT", "dns_failure")


def p_duplicate_ip(cap, t0, t1, rng):
    new = "3c:22:fb:00:%02x:%02x" % (rng.randrange(256), rng.randrange(256))
    victim = rng.choice([g.DESKTOP, g.PHONE])
    cap.add(t0, Ether(src=new, dst=g.BROADCAST) / ARP(op=1, hwsrc=new, psrc=victim, hwdst="00:00:00:00:00:00", pdst=victim))
    t = t0 + 0.5
    while t < t1:
        sport, txid = rng.randint(49152, 65000), cap.next_txid()
        cap.add(t, Ether(src=new, dst=g.GW_MAC) / g.ip(victim, g.GW_IP, False) / UDP(sport=sport, dport=53) / DNS(id=txid, rd=1, qd=DNSQR(qname="example.com")))
        cap.add(t + 0.01, Ether(src=g.GW_MAC, dst=new) / g.ip(g.GW_IP, victim, False) / UDP(sport=53, dport=sport) / DNS(id=txid, qr=1, qd=DNSQR(qname="example.com"), an=[DNSRR(rrname="example.com", rdata="93.184.216.34")]))
        t += rng.uniform(2, 6)
    return ("FAULT", "duplicate_ip")


def p_mtu_blackhole(cap, t0, t1, rng):
    srv = g.SITES["video.example.com"]
    for k in range(rng.randint(1, 3)):
        t = t0 + k * 12
        sport, isn, sisn = rng.randint(49152, 65000), rng.randint(1, 2**31), rng.randint(1, 2**31)
        c = g.LAPTOP
        cap.add(t, g.tcp_pkt(c, srv, sport, 443, "S", isn, 0, mss=1460))
        cap.add(t + 0.02, g.tcp_pkt(srv, c, 443, sport, "SA", sisn, isn + 1, mss=1460))
        cap.add(t + 0.04, g.tcp_pkt(c, srv, sport, 443, "A", isn + 1, sisn + 1))
        cap.add(t + 0.041, g.tcp_pkt(c, srv, sport, 443, "PA", isn + 1, sisn + 1, plen=rng.randint(100, 500)))
        cap.add(t + 0.061, g.tcp_pkt(srv, c, 443, sport, "A", sisn + 1, isn + 501))
        rto, tt = rng.uniform(0.2, 0.5), t + 0.07
        for _ in range(rng.randint(4, 6)):
            cap.add(tt, g.tcp_pkt(c, srv, sport, 443, "PA", isn + 501, sisn + 1, plen=rng.choice([1360, 1400, 1460])))
            tt += rto
            rto *= 2
    return ("FAULT", "mtu_blackhole")


def p_latency(cap, t0, t1, rng):
    t, end = t0, min(t1, t0 + rng.uniform(15, 35))
    while t < end:
        g.browse(cap, t, rng.choice(g.CLIENTS), rng.choice(NAMES[:5]), rtt=rng.uniform(0.6, 2.0), dns_rtt=rng.uniform(0.5, 1.5), nseg=3)
        t += rng.uniform(1.0, 2.5)
    return ("FAULT", "high_latency")


def p_port_scan(cap, t0, t1, rng):
    target = rng.choice([g.DESKTOP, g.PRINTER, g.LAPTOP])
    gap = rng.uniform(0.002, 0.08)
    if rng.random() < 0.6:
        n = min(rng.randint(20, 400), int((t1 - t0 - 2) / gap))
        ports = rng.sample(range(1, 2000), n)
        open_ports = set(rng.sample(ports, min(3, n)))
        t = t0
        for port in ports:
            isn = rng.randint(1, 2**31)
            cap.add(t, g.tcp_pkt(g.ATTACKER_IP, target, 40000 + port % 999, port, "S", isn, 0, window=1024, mss=1460))
            flags = "SA" if port in open_ports else "RA"
            cap.add(t + 0.0005, g.tcp_pkt(target, g.ATTACKER_IP, port, 40000 + port % 999, flags, 7, isn + 1))
            t += gap
    else:
        port = rng.choice([22, 445, 3389, 23])
        t = t0
        for host in rng.sample(range(2, 254), rng.randint(15, 120)):
            dst = f"192.168.1.{host}"
            if dst == g.ATTACKER_IP:
                continue
            cap.add(t, g.tcp_pkt(g.ATTACKER_IP, dst, 41000 + host, port, "S", rng.randint(1, 2**31), 0, window=1024, mss=1460, dst_mac=g.mac_of(dst)))
            t += gap
    return ("ATTACK", "port_scan")


def p_arp_spoof(cap, t0, t1, rng, post):
    victim = rng.choice(g.CLIENTS)
    g._arp_poison(cap, t0, t1, victim, interval=rng.uniform(1.0, 8.0))
    if rng.random() < 0.5:
        post.append(lambda c: g._mitm_relay(c, victim, t0 + 0.5))
    return ("ATTACK", "arp_spoofing")


def p_dns_hijack(cap, t0, t1, rng):
    victim = rng.choice(g.CLIENTS)
    forged = f"192.168.1.{rng.randint(150, 250)}"
    for k in range(rng.randint(1, 4)):
        t = t0 + k * rng.uniform(3, 9)
        name = rng.choice(["mybank.example.com", "mail.example.com", "example.com"])
        txid, sport = cap.next_txid(), rng.randint(49152, 65000)
        q = DNSQR(qname=name)
        cap.add(t, g.eth(victim, g.GW_IP) / g.ip(victim, g.GW_IP, False) / UDP(sport=sport, dport=53) / DNS(id=txid, rd=1, qd=q))
        cap.add(t + rng.uniform(0.0005, 0.005), Ether(src=g.ATTACKER_MAC, dst=g.mac_of(victim)) / g.ip(g.GW_IP, victim, False) / UDP(sport=53, dport=sport) / DNS(id=txid, qr=1, aa=1, qd=q, an=[DNSRR(rrname=name, rdata=forged, ttl=rng.randint(5, 60))]))
        cap.add(t + rng.uniform(0.01, 0.05), g.eth(g.GW_IP, victim) / g.ip(g.GW_IP, victim, False) / UDP(sport=53, dport=sport) / DNS(id=txid, qr=1, qd=q, an=[DNSRR(rrname=name, rdata=g.SITES[name], ttl=300)]))
    return ("ATTACK", "dns_hijack")


def p_rogue_dhcp(cap, t0, t1, rng):
    for k in range(rng.randint(1, 3)):
        mac = "3c:22:fb:01:%02x:%02x" % (rng.randrange(256), rng.randrange(256))
        g._dhcp(cap, t0 + k * 7, mac, 0x7000 + k, [(g.ATTACKER_IP, g.ATTACKER_IP, g.ATTACKER_IP, f"192.168.1.{160 + k}", rng.uniform(0.001, 0.01)), (g.GW_IP, g.GW_IP, g.GW_IP, f"192.168.1.{110 + k}", rng.uniform(0.02, 0.08))])
    return ("ATTACK", "rogue_dhcp")


def p_starvation(cap, t0, t1, rng):
    n = rng.randint(25, 200)
    gap = min(0.2, (t1 - t0 - 5) / n)
    t = t0
    for k in range(n):
        fake = "02:%02x:%02x:%02x:%02x:%02x" % tuple(rng.randrange(256) for _ in range(5))
        chaddr = bytes.fromhex(fake.replace(":", "")) + b"\x00" * 10
        cap.add(t, Ether(src=g.ATTACKER_MAC, dst=g.BROADCAST) / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / BOOTP(op=1, xid=0x9000 + k, chaddr=chaddr) / DHCP(options=[("message-type", "discover"), "end"]))
        t += gap
    return ("ATTACK", "dhcp_starvation")


def p_fragments(cap, t0, t1, rng):
    t = t0
    for k in range(rng.randint(1, 6)):
        pid = rng.randrange(65536)
        first_len = rng.choice([24, 36, 48])
        cap.add(t, g.eth(g.ATTACKER_IP, g.DESKTOP) / IP(src=g.ATTACKER_IP, dst=g.DESKTOP, id=pid, flags="MF", proto=17) / Raw(b"\x00" * first_len))
        cap.add(t + 0.0005, g.eth(g.ATTACKER_IP, g.DESKTOP) / IP(src=g.ATTACKER_IP, dst=g.DESKTOP, id=pid, frag=rng.randint(1, first_len // 8 - 1), proto=17) / Raw(b"\x00" * 16))
        t += rng.uniform(0.5, 4)
    return ("ATTACK", "fragment_attack")


PROBLEMS = {
    "tcp_retransmissions": p_retrans,
    "tcp_connection_refused": p_refused,
    "tcp_connection_aborted": p_aborted,
    "dns_failure": p_dns_outage,
    "duplicate_ip": p_duplicate_ip,
    "mtu_blackhole": p_mtu_blackhole,
    "high_latency": p_latency,
    "port_scan": p_port_scan,
    "arp_spoofing": p_arp_spoof,
    "dns_hijack": p_dns_hijack,
    "rogue_dhcp": p_rogue_dhcp,
    "dhcp_starvation": p_starvation,
    "fragment_attack": p_fragments,
}


def gateway_down(cap, t0, rng):
    t = t0
    while t < DURATION - 2:
        for i, c in enumerate(g.CLIENTS):
            if rng.random() < 0.7:
                cap.add(t + 0.1 * i, Ether(src=g.mac_of(c), dst=g.BROADCAST) / ARP(op=1, hwsrc=g.mac_of(c), psrc=c, pdst=g.GW_IP))
        if rng.random() < 0.5:
            g.dns_lookup(cap, t + 0.3, rng.choice(g.CLIENTS), rng.choice(NAMES), respond=False)
        t += rng.uniform(1.0, 3.0)
    return ("FAULT", "host_unreachable")


# --- hard negatives: benign look-alikes that must NOT become attacks ---------------------


def n_busy_client(cap, rng):
    t = rng.uniform(5, 100)
    for i in range(rng.randint(12, 30)):
        g.tcp_session(cap, t + 0.15 * i, rng.choice(g.CLIENTS), f"151.101.{rng.randrange(256)}.{rng.randint(1, 254)}", 443, nseg=rng.randint(2, 6))


def n_backup_dhcp(cap, rng):
    g.MACS["192.168.1.2"] = "00:1a:2b:3c:00:02"
    g._dhcp(cap, rng.uniform(5, 100), "3c:22:fb:02:00:%02x" % rng.randrange(256), rng.randrange(1 << 16), [("192.168.1.2", g.GW_IP, g.GW_IP, "192.168.1.130", 0.004)])


def n_failover(cap, rng):
    new = "00:1a:2b:3c:00:99"
    cap.add(rng.uniform(5, 100), Ether(src=new, dst=g.BROADCAST) / ARP(op=2, hwsrc=new, psrc=g.GW_IP, hwdst=g.BROADCAST, pdst=g.GW_IP))


def n_split_horizon(cap, rng):
    for _ in range(rng.randint(2, 6)):
        g.dns_lookup(cap, rng.uniform(2, 115), rng.choice(g.CLIENTS), rng.choice(["intranet.office.lan", "nas.office.lan"]), answers=[f"192.168.1.{rng.randint(2, 9)}"])


def n_typos(cap, rng):
    for _ in range(rng.randint(1, 3)):
        g.dns_lookup(cap, rng.uniform(2, 115), rng.choice(g.CLIENTS), rng.choice(["exmaple.com", "gogle.com", "wpad.lan"]), rcode=3)


def n_single_loss(cap, rng):
    g.browse(cap, rng.uniform(5, 100), rng.choice(g.CLIENTS), "news.example.org", nseg=30, lost={rng.randrange(30)})


def n_duplicate_answer(cap, rng):
    t, client = rng.uniform(5, 110), rng.choice(g.CLIENTS)
    txid, sport = cap.next_txid(), rng.randint(49152, 65000)
    q = DNSQR(qname="example.com")
    cap.add(t, g.eth(client, g.GW_IP) / g.ip(client, g.GW_IP, False) / UDP(sport=sport, dport=53) / DNS(id=txid, qd=q))
    for d in (0.01, 0.4):  # resolver retransmits the identical answer
        cap.add(t + d, g.eth(g.GW_IP, client) / g.ip(g.GW_IP, client, False) / UDP(sport=53, dport=sport) / DNS(id=txid, qr=1, qd=q, an=[DNSRR(rrname="example.com", rdata="93.184.216.34")]))


def n_cdn_rotation(cap, rng):
    for _ in range(rng.randint(3, 6)):
        g.dns_lookup(cap, rng.uniform(2, 115), rng.choice(g.CLIENTS), "news.example.org", answers=[f"151.101.{rng.randrange(256)}.69"], ttl=30)


def n_legit_fragments(cap, rng):
    t = rng.uniform(5, 110)
    for k in range(rng.randint(1, 4)):
        pid = rng.randrange(65536)
        cap.add(t, g.eth(g.LAPTOP, g.GW_IP) / IP(src=g.LAPTOP, dst="203.0.113.50", id=pid, flags="MF", proto=17) / Raw(b"\x00" * 1480))
        cap.add(t + 0.0003, g.eth(g.LAPTOP, g.GW_IP) / IP(src=g.LAPTOP, dst="203.0.113.50", id=pid, frag=185, proto=17) / Raw(b"\x00" * rng.randint(100, 1400)))
        t += 0.3


def n_client_resets(cap, rng):
    srv = "151.101.1.69"
    for k in range(rng.randint(3, 8)):
        t, c = rng.uniform(3, 115), rng.choice(g.CLIENTS)
        sport, isn, sisn = rng.randint(49152, 65000), rng.randint(1, 2**31), rng.randint(1, 2**31)
        cap.add(t, g.tcp_pkt(c, srv, sport, 443, "S", isn, 0, mss=1460))
        cap.add(t + 0.01, g.tcp_pkt(srv, c, 443, sport, "SA", sisn, isn + 1, mss=1460))
        cap.add(t + 0.02, g.tcp_pkt(c, srv, sport, 443, "PA", isn + 1, sisn + 1, plen=200))
        cap.add(t + 0.03, g.tcp_pkt(srv, c, 443, sport, "PA", sisn + 1, isn + 201, plen=1000))
        cap.add(t + 0.04, g.tcp_pkt(c, srv, sport, 443, "RA", isn + 201, sisn + 1001))


NEGATIVES = {
    "busy_client": n_busy_client,
    "backup_dhcp": n_backup_dhcp,
    "router_failover": n_failover,
    "split_horizon_dns": n_split_horizon,
    "dns_typos": n_typos,
    "single_lost_packet": n_single_loss,
    "duplicate_dns_answer": n_duplicate_answer,
    "cdn_answer_rotation": n_cdn_rotation,
    "legit_fragmentation": n_legit_fragments,
    "client_resets": n_client_resets,
}


# --- running ------------------------------------------------------------------------------


def build_case(seed: int, out: Path) -> dict:
    rng = random.Random(seed)
    cap = g.Capture(seed=seed)
    saved_macs = dict(g.MACS)
    post: list = []
    try:
        kinds = []
        planted = []
        r = rng.random()
        n_problems = 0 if r < 0.25 else 1 if r < 0.7 else 2
        if n_problems and rng.random() < 0.06:
            g.baseline(cap, 0, 60, step=(rng.uniform(0.8, 2), rng.uniform(2.5, 5)))
            before = len(cap.pkts)
            kinds.append(gateway_down(cap, 62.0, rng))
            planted.append((kinds[-1], cap.pkts[before:]))
            negs = []
        else:
            g.baseline(cap, 0, DURATION, step=(rng.uniform(0.8, 2), rng.uniform(2.5, 5)))
            for slot, name in zip(SLOTS, rng.sample(list(PROBLEMS), n_problems)):
                fn = PROBLEMS[name]
                before = len(cap.pkts)
                kinds.append(fn(cap, *slot, rng, post) if name == "arp_spoofing" else fn(cap, *slot, rng))
                planted.append((kinds[-1], cap.pkts[before:]))
            negs = rng.sample(list(NEGATIVES), rng.randint(0, 3))
            for name in negs:
                NEGATIVES[name](cap, rng)
        for fn in post:
            fn(cap)
        path = out / f"case{seed}.pcap"
        cap.write(path)
        positions = {id(packet): index for index, packet in enumerate(cap.pkts, 1)}
        instances = [{"verdict": verdict, "kind": kind, "packet_ids": [positions[id(packet)] for packet in packets if id(packet) in positions],
                      "t_start": min(float(packet.time) for packet in packets), "t_end": max(float(packet.time) for packet in packets)}
                     for (verdict, kind), packets in planted if packets]
        return {"seed": seed, "path": path, "expected": instances, "negatives": negs}
    finally:
        g.MACS.clear()
        g.MACS.update(saved_macs)


def score_case(case: dict) -> dict:
    report = analyze(case["path"])
    found = []
    for incident in report["incidents"]:
        found.append({**incident, "placement": "root"})
        for sub in incident["related"] + incident["consequences"]:
            found.append({**sub, "verdict": sub.get("verdict", incident["verdict"]), "placement": "linked"})
    matched = set()
    outcomes = []
    linked_correct = 0
    for expected in case["expected"]:
        if not isinstance(expected, dict):
            expected = {"verdict": expected[0], "kind": expected[1]}
        verdict, kind = expected["verdict"], expected["kind"]
        candidates = [(index, finding) for index, finding in enumerate(found)
                      if index not in matched and finding["kind"] == kind
                      and (not expected.get("packet_ids") or set(expected["packet_ids"]) & set(finding.get("packet_ids", [])))]
        if not candidates:
            outcomes.append((kind, "missed"))
        else:
            index, finding = max(candidates, key=lambda candidate: len(set(expected.get("packet_ids", [])) & set(candidate[1].get("packet_ids", []))))
            matched.add(index)
            correct = finding["verdict"] == verdict
            outcomes.append((kind, "correct" if correct else f"wrong verdict ({finding['verdict']})"))
            linked_correct += int(correct and finding["placement"] == "linked")
    unexpected = [(finding["kind"], finding["verdict"]) for index, finding in enumerate(found) if index not in matched]
    return {"outcomes": outcomes, "unexpected": unexpected, "negatives": case["negatives"], "n_expected": len(case["expected"]), "correctly_linked": linked_correct}


def run(cases: int, seed: int) -> dict:
    results = []
    started = time.time()
    with tempfile.TemporaryDirectory(prefix="pd-bench-") as tmp:
        for i in range(cases):
            case = build_case(seed + i, Path(tmp))
            res = score_case(case)
            res["seed"] = seed + i
            results.append(res)
            case["path"].unlink()
            if (i + 1) % 25 == 0:
                print(f"  {i + 1}/{cases} cases ({time.time() - started:.0f}s)", flush=True)
    summary = summarise(results, time.time() - started)
    summary["case_results"] = results
    return summary


def _false_attack(result):
    return any(verdict == "ATTACK" for _, verdict in result["unexpected"]) or any(outcome == "wrong verdict (ATTACK)" for _, outcome in result["outcomes"])


def summarise(results: list[dict], elapsed: float) -> dict:
    per_kind = defaultdict(Counter)
    for r in results:
        for kind, outcome in r["outcomes"]:
            per_kind[kind][outcome] += 1
    total = sum(sum(c.values()) for c in per_kind.values())
    correct = sum(c["correct"] for c in per_kind.values())
    detected = sum(sum(v for k, v in c.items() if k != "missed") for c in per_kind.values())
    false_attacks = [result for result in results if _false_attack(result)]
    unexpected = Counter(f"{k} ({v})" for r in results for k, v in r["unexpected"])
    # which hard negatives were present when each extra finding appeared
    appears_with = defaultdict(Counter)
    for r in results:
        for k, v in r["unexpected"]:
            for n in r["negatives"] or ["(none)"]:
                appears_with[f"{k} ({v})"][n] += 1
    no_problem = [r for r in results if r["n_expected"] == 0]
    neg_trouble = Counter()
    for r in results:
        if _false_attack(r):
            for n in r["negatives"]:
                neg_trouble[n] += 1
    return {
        "cases": len(results),
        "elapsed": elapsed,
        "problems": total,
        "detected": detected,
        "correct": correct,
        "per_kind": {k: dict(v) for k, v in sorted(per_kind.items())},
        "false_attack_cases": len(false_attacks),
        "false_attack_seeds": [r["seed"] for r in false_attacks][:20],
        "no_problem_cases": len(no_problem),
        "no_problem_clean": sum(1 for r in no_problem if not r["unexpected"]),
        "no_problem_false_attack": sum(1 for result in no_problem if _false_attack(result)),
        "unexpected": dict(unexpected.most_common()),
        "appears_with": {k: dict(c.most_common(2)) for k, c in appears_with.items()},
        "negatives_in_false_attacks": dict(neg_trouble),
        "missed_seeds": [r["seed"] for r in results if any(o != "correct" for _, o in r["outcomes"])][:20],
    }


def markdown(s: dict, seed: int) -> str:
    lines = [
        "# Evaluation",
        "",
        f"Generated by `python benchmark/run.py --cases {s['cases']} --seed {seed}` "
        f"({s['cases']} randomised captures, {s['elapsed']:.0f} s).",
        "",
        "Each case is a fresh 120-second synthetic capture: office background traffic at a random rate, "
        "0–2 problems with randomised parameters (loss rate, scan speed and size, poisoning interval, "
        "outage length, number of forged answers, flood size, ...) placed in separate time slots, and 0–3 "
        "*hard negatives*: benign situations that resemble problems. A problem counts as **correct** when it "
        "is matched one-to-one to planted packet evidence and has the correct independent verdict. "
        "Linked findings receive no automatic credit. Unmatched root and linked findings are counted separately.",
        "",
        "## Headline numbers",
        "",
        "| Metric | Result |",
        "|---|---|",
        f"| Problems detected | **{s['detected']}/{s['problems']} ({s['detected'] / max(1, s['problems']):.1%})** |",
        f"| Problems detected with the correct verdict | **{s['correct']}/{s['problems']} ({s['correct'] / max(1, s['problems']):.1%})** |",
        f"| Cases with a false ATTACK verdict | **{s['false_attack_cases']}/{s['cases']} ({s['false_attack_cases'] / max(1, s['cases']):.1%})** |",
        f"| Problem-free cases reported completely clean | {s['no_problem_clean']}/{s['no_problem_cases']} |",
        f"| Problem-free cases with a false ATTACK | {s['no_problem_false_attack']}/{s['no_problem_cases']} |",
        "",
        "## Per problem type",
        "",
        "| Problem | Cases | Correct | Wrong verdict | Missed |",
        "|---|---|---|---|---|",
    ]
    for kind, c in s["per_kind"].items():
        n = sum(c.values())
        wrong = sum(v for k, v in c.items() if k.startswith("wrong"))
        lines.append(f"| `{kind}` | {n} | {c.get('correct', 0)} ({c.get('correct', 0) / n:.0%}) | {wrong} | {c.get('missed', 0)} |")
    lines += ["", "## Extra findings not planted by the generator", ""]
    if s["unexpected"]:
        lines += ["| Finding (verdict) | Times | Most often present in the same capture |", "|---|---|---|"]
        for k, v in s["unexpected"].items():
            with_ = ", ".join(f"`{n}` ({c})" for n, c in s["appears_with"].get(k, {}).items())
            lines.append(f"| {k} | {v} | {with_} |")
        lines += [
            "",
            "An `arp_conflict` next to `router_failover` is expected: in that hard negative a standby router announces the gateway "
            "address while the original keeps working, which is a genuine address conflict. It is reported as a FAULT, never as an attack.",
        ]
    else:
        lines.append("None.")
    lines += [
        "",
        "## Hard negatives used",
        "",
        ", ".join(f"`{n}`" for n in NEGATIVES),
        "",
        "## What the benchmark caught during development",
        "",
        "The first 60-case trial scored 94% correct verdicts and exposed three weaknesses, which were then fixed:",
        "",
        "* **Slow port scans** (about 12 probes/s) landed just below the attack threshold and were marked UNCERTAIN. Fix: the "
        "'ports tried' clue now scales with the number of ports, and a new clue counts probes that hit closed ports or missing hosts.",
        "* **Short DNS outages** were diluted by healthy traffic in the rest of the capture (failure ratio 23% overall). Fix: the "
        "failure ratio is measured over the worst 30-second window.",
        "* **Busy clients** (many servers, all carrying data) produced a needless 'many connection attempts' incident. Fix: such "
        "sources are no longer reported unless they use stealth probe types.",
        "",
        "## Honest caveats",
        "",
        "* The captures are synthetic and written with the same packet primitives as the bundled samples, so this measures robustness to "
        "parameter changes, timing, background noise and combinations, not every quirk of real networks.",
        "* Four named public Wireshark captures are independently reproducible using `python benchmark/real_captures.py --fetch`. "
        "Source URLs and SHA-256 hashes are pinned in `benchmark/public-captures.json`; observed results are in `docs/public-capture-results.json`. "
        "The capture files are not redistributed. This small check does not establish production-network accuracy.",
        "",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cases", type=int, default=300)
    ap.add_argument("--seed", type=int, default=2026)
    ap.add_argument("--no-write", action="store_true", help="print results only, do not update docs/EVALUATION.md")
    args = ap.parse_args()
    summary = run(args.cases, args.seed)
    md = markdown(summary, args.seed)
    print(md)
    print("missed/wrong seeds:", summary["missed_seeds"])
    print("false-attack seeds:", summary["false_attack_seeds"])
    if not args.no_write:
        (ROOT / "docs").mkdir(exist_ok=True)
        (ROOT / "docs" / "EVALUATION.md").write_text(md, encoding="utf-8")
        (ROOT / "docs" / "evaluation-results.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
