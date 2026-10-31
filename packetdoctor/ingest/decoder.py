"""Turn a dissected Scapy packet into a header-only ``PacketRecord``.

Only header fields are copied; payload bytes are never stored. Strings taken
from the capture (DNS names, record data) go through ``safe_text``.
"""

from __future__ import annotations

from .._scapy import (
    ARP,
    BOOTP,
    DHCP,
    DNS,
    ICMP,
    IP,
    TCP,
    UDP,
    Ether,
    ICMPv6PacketTooBig,
    IPerror,
    IPerror6,
    IPv6,
    TCPerror,
    UDPerror,
)
from ..models import ArpInfo, DhcpInfo, DnsAnswer, DnsInfo, PacketRecord
from ..utils import normalize_dns_name, safe_text

DNS_PORTS = {53}
DHCP_PORTS = {67, 68}


def _mac(value: object) -> str | None:
    if value is None:
        return None
    text = safe_text(value, 32).lower()
    return text or None


def decode(idx: int, pkt) -> PacketRecord:
    rec = PacketRecord(idx=idx, ts=float(pkt.time), length=int(getattr(pkt, "wirelen", None) or len(pkt)))

    if pkt.haslayer(Ether):
        eth = pkt[Ether]
        rec.src_mac = _mac(eth.src)
        rec.dst_mac = _mac(eth.dst)

    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        if arp.ptype == 0x0800 and arp.op in (1, 2):
            rec.arp = ArpInfo(
                op=int(arp.op),
                hwsrc=_mac(arp.hwsrc) or "",
                psrc=safe_text(arp.psrc, 45),
                hwdst=_mac(arp.hwdst) or "",
                pdst=safe_text(arp.pdst, 45),
            )
        return rec

    ip_hdr_len = None
    ip_total = None
    if pkt.haslayer(IP):
        ip = pkt[IP]
        rec.ip_version = 4
        rec.src_ip = safe_text(ip.src, 45)
        rec.dst_ip = safe_text(ip.dst, 45)
        rec.ip_proto = int(ip.proto)
        rec.ttl = int(ip.ttl)
        rec.df = bool(int(ip.flags) & 0x2)
        ip_hdr_len = int(ip.ihl or 5) * 4
        ip_total = int(ip.len) if ip.len is not None else None
    elif pkt.haslayer(IPv6):
        ip6 = pkt[IPv6]
        rec.ip_version = 6
        rec.src_ip = safe_text(ip6.src, 45)
        rec.dst_ip = safe_text(ip6.dst, 45)
        rec.ip_proto = int(ip6.nh)
        rec.ttl = int(ip6.hlim)
        ip_hdr_len = 40
        ip_total = int(ip6.plen) + 40 if ip6.plen is not None else None

    # ICMP errors quote the original packet; the quoted TCP/UDP header must not
    # be mistaken for real traffic, so handle them first and stop.
    if pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        rec.icmp_type = int(icmp.type)
        rec.icmp_code = int(icmp.code)
        if rec.icmp_type == 3 and rec.icmp_code == 4:
            rec.icmp_mtu = int(icmp.nexthopmtu or 0) or None
        if pkt.haslayer(IPerror):
            rec.icmp_inner = _quoted(pkt, IPerror)
        return rec
    if pkt.haslayer(ICMPv6PacketTooBig):
        rec.icmp_type = 2
        rec.icmp_code = 0
        rec.icmp_mtu = int(pkt[ICMPv6PacketTooBig].mtu)
        if pkt.haslayer(IPerror6):
            rec.icmp_inner = _quoted(pkt, IPerror6)
        return rec

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        rec.sport, rec.dport = int(tcp.sport), int(tcp.dport)
        rec.tcp_flags = int(tcp.flags)
        rec.seq, rec.ack = int(tcp.seq), int(tcp.ack)
        rec.window = int(tcp.window)
        tcp_hdr = int(tcp.dataofs or 5) * 4
        if ip_total is not None and ip_hdr_len is not None:
            rec.payload_len = max(0, ip_total - ip_hdr_len - tcp_hdr)
        else:
            rec.payload_len = len(bytes(tcp.payload))
        for opt in tcp.options or []:
            if isinstance(opt, tuple) and opt and opt[0] == "MSS":
                rec.mss = int(opt[1])
        if rec.sport in DNS_PORTS or rec.dport in DNS_PORTS:
            rec.dns = _dns(pkt)
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        rec.sport, rec.dport = int(udp.sport), int(udp.dport)
        rec.payload_len = max(0, int(udp.len or 8) - 8)
        if rec.sport in DNS_PORTS or rec.dport in DNS_PORTS:
            rec.dns = _dns(pkt)
        elif rec.sport in DHCP_PORTS and rec.dport in DHCP_PORTS:
            rec.dhcp = _dhcp(pkt)
    return rec


def _quoted(pkt, err_layer) -> tuple:
    inner = pkt[err_layer]
    sport = dport = None
    proto = int(getattr(inner, "proto", getattr(inner, "nh", 0)) or 0)
    if pkt.haslayer(TCPerror):
        sport, dport = int(pkt[TCPerror].sport), int(pkt[TCPerror].dport)
    elif pkt.haslayer(UDPerror):
        sport, dport = int(pkt[UDPerror].sport), int(pkt[UDPerror].dport)
    return (safe_text(inner.src, 45), safe_text(inner.dst, 45), proto, sport, dport)


def _dns(pkt) -> DnsInfo | None:
    if not pkt.haslayer(DNS):
        return None
    dns = pkt[DNS]
    qname, qtype = "", 0
    qd = dns.qd
    if qd:
        first = qd[0] if isinstance(qd, list) or hasattr(qd, "__getitem__") else qd
        qname = normalize_dns_name(getattr(first, "qname", ""))
        qtype = int(getattr(first, "qtype", 0) or 0)
    answers: list[DnsAnswer] = []
    for rr in list(dns.an or [])[:32]:
        data = rr.rdata
        if isinstance(data, (list, tuple)):  # TXT records
            data = b" ".join(x if isinstance(x, bytes) else str(x).encode() for x in data)
        rtype = int(getattr(rr, "type", 0) or 0)
        text = normalize_dns_name(data) if rtype in (2, 5, 12) else safe_text(data, 255)
        answers.append(
            DnsAnswer(
                name=normalize_dns_name(getattr(rr, "rrname", "")),
                rtype=rtype,
                data=text,
                ttl=int(getattr(rr, "ttl", 0) or 0),
            )
        )
    return DnsInfo(
        txid=int(dns.id),
        is_response=bool(dns.qr),
        qname=qname,
        qtype=qtype,
        rcode=int(dns.rcode),
        answers=answers,
    )


def _dhcp(pkt) -> DhcpInfo | None:
    if not (pkt.haslayer(BOOTP) and pkt.haslayer(DHCP)):
        return None
    bootp = pkt[BOOTP]
    chaddr = bytes(bootp.chaddr or b"")[:6]
    info = DhcpInfo(
        msg_type=0,
        xid=int(bootp.xid),
        client_mac=":".join(f"{b:02x}" for b in chaddr),
        yiaddr=safe_text(bootp.yiaddr, 45),
    )
    for opt in pkt[DHCP].options or []:
        if not isinstance(opt, tuple) or len(opt) < 2:
            continue
        key, values = opt[0], opt[1:]
        if key == "message-type":
            info.msg_type = int(values[0])
        elif key == "server_id":
            info.server_id = safe_text(values[0], 45)
        elif key == "router":
            info.router = safe_text(values[0], 45)
        elif key == "name_server":
            info.dns_servers = [safe_text(v, 45) for v in values[:8]]
        elif key == "requested_addr":
            info.requested_ip = safe_text(values[0], 45)
    return info
