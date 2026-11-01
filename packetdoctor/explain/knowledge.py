"""Plain-language knowledge base.

For every kind of finding: what happened (for a beginner), why it matters,
the likely cause, and concrete steps to fix it, filled in with the actual
addresses and numbers from the capture. Written by us; no external service
or language model is involved, so the output is deterministic and offline.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Symptom
from ..utils import fmt_duration, is_private_ip


@dataclass
class Explanation:
    what: str
    why: str
    cause: str
    fixes: list[str] = field(default_factory=list)
    technical: str = ""

    def to_dict(self) -> dict:
        return {"what": self.what, "why": self.why, "cause": self.cause, "fixes": self.fixes, "technical": self.technical}


class Namer:
    """Turns addresses into friendly descriptions ('your gateway (192.168.1.1)')."""

    def __init__(self, gateway_ip: str | None, gateway_mac: str | None, dns_servers: set[str] | None = None):
        self.gw_ip, self.gw_mac = gateway_ip, gateway_mac
        self.dns = dns_servers or set()

    def ip(self, ip: str | None) -> str:
        if not ip:
            return "an unknown device"
        if ip == self.gw_ip:
            return f"your router/gateway ({ip})"
        if ip in self.dns:
            return f"the DNS server {ip}"
        if is_private_ip(ip):
            return f"the device at {ip}"
        return f"the internet server {ip}"

    def mac(self, mac: str | None) -> str:
        if not mac:
            return "an unknown device"
        if mac == self.gw_mac:
            return f"your router (hardware address {mac})"
        return f"the device with hardware address {mac}"


def explain(s: Symptom, n: Namer) -> Explanation:
    fn = _KB.get(s.kind)
    if fn is None:
        return Explanation(what=s.title, why="", cause="", fixes=[])
    return fn(s, s.metrics, n)


def as_consequence(s: Symptom) -> str:
    """Short sentence used when a finding is listed as a side-effect of another."""
    return s.title


# --- fault explanations ---------------------------------------------------------------


def _retrans(s, m, n):
    kinds = m.get("kinds", {})
    return Explanation(
        what=(
            f"Data between {n.ip(m['client'])} and {n.ip(m['server'])} keeps getting lost on the way, so it has to be sent again. "
            f"{m['retransmissions']} of {m['data_segments']} data packets ({m['ratio']:.0%}) were re-sent."
        ),
        why="Every lost packet makes the sender wait before trying again, so downloads, video calls and websites on this path feel slow or freeze.",
        cause="Packet loss on the path: a congested internet link, a bad cable or Wi-Fi signal, an overloaded router, or a problem at the remote server's network.",
        fixes=[
            "Check whether other devices talking to the same server are also slow; if only one device is affected, test its cable or Wi-Fi signal.",
            "Look at the router/switch port for errors (CRC or collision counters) and replace suspicious cables.",
            "If the link is saturated, schedule large transfers off-peak or enable QoS on the router.",
            f"If only {m['server']} is affected, the problem is likely on its side; contact that service or your ISP.",
        ],
        technical=f"TCP retransmissions: {kinds}. Flows affected: {m['flows_affected']}.",
    )


def _refused(s, m, n):
    return Explanation(
        what=f"Devices tried {m['attempts']} times to use the service on port {m['port']} of {n.ip(m['server'])}, and every attempt was immediately rejected.",
        why="The program that needs this service (printing, file sharing, an app, ...) will fail with 'connection refused' errors.",
        cause="The service is not running on that device, it listens on another port, or a firewall on the device rejects the connections.",
        fixes=[
            f"Check that the device {m['server']} is on and that the service for port {m['port']} is running (restart it if needed).",
            f"Check the device's firewall rules for port {m['port']}.",
            "Make sure the clients are configured with the right address and port.",
        ],
        technical=f"TCP SYN answered with RST/ACK from {m['server']}:{m['port']} ({m['attempts']} times).",
    )


def _aborted(s, m, n):
    return Explanation(
        what=f"{m['aborted']} connections to {n.ip(m['server'])} (port {m['port']}) were cut off in the middle of a transfer by {m['reset_by']}.",
        why="Downloads stop half-way and apps show errors like 'connection reset'.",
        cause="An application crashing or timing out, a firewall or load balancer dropping long connections, or packets for this connection reaching the wrong device.",
        fixes=[
            "Check the server or application logs at the time shown in the timeline.",
            "Check firewall/NAT idle timeouts on the router.",
            "If several findings mention the same device, fix that underlying problem first.",
        ],
        technical=f"RST on established connections after data; reset by {m['reset_by']}.",
    )


def _dns_failure(s, m, n):
    duration = fmt_duration(s.t_end - s.t_start)
    names = ", ".join(m.get("names", [])[:3])
    return Explanation(
        what=(
            f"The DNS server {m['server']}, which turns website names into addresses, failed {m['failures']} of {m['queries']} lookups "
            f"over about {duration} ({m['servfail']} errors, {m['timeouts']} unanswered). Affected names include {names}."
        ),
        why="When DNS fails, every website and app looks 'down' even though the internet connection itself may be working.",
        cause="The DNS server (often the router) is overloaded or crashed, or it cannot reach its upstream DNS provider. This looks like a plain outage, not tampering.",
        fixes=[
            f"Restart the DNS service or the router at {m['server']}.",
            "Check whether the router can reach its upstream DNS (try another provider such as your ISP's DNS).",
            "As a temporary workaround, configure a second DNS server on the devices.",
        ],
        technical=f"SERVFAIL={m['servfail']}, REFUSED={m['refused']}, timeouts={m['timeouts']}, NXDOMAIN={m['nxdomain']} (typos, ignored).",
    )


def _latency(s, m, n):
    return Explanation(
        what=(
            f"For about {fmt_duration(s.t_end - s.t_start)}, {m['what']} took {m['slow_median_ms']:.0f} ms instead of the usual "
            f"{m['baseline_ms']:.0f} ms (worst {m['worst_ms']:.0f} ms)."
        ),
        why="Everything that needs a quick answer from the network (websites, calls, logins) feels sluggish.",
        cause="A congested internet link (someone downloading or uploading heavily), an overloaded router or server, or Wi-Fi interference.",
        fixes=[
            "Check if a large download, backup or video stream ran at that time and limit it (QoS / bandwidth limits).",
            "Check the router's CPU load and the internet line's usage graph.",
            "If only one server is slow, the problem is on that server's side.",
        ],
        technical=f"{m['slow_samples']} of {m['total_samples']} samples above the robust threshold (median + 6xMAD). Servers: {', '.join(m['servers'][:5])}.",
    )


def _zero_window(s, m, n):
    return Explanation(
        what=f"{n.ip(m['receiver'])} repeatedly told the sender to pause because it could not keep up ({m['zero_window_packets']} 'window full' messages).",
        why="Transfers to this device stall in bursts even though the network itself is fine.",
        cause="The receiving device is overloaded: slow disk, busy CPU, or an application that reads data too slowly (common on printers and small devices).",
        fixes=["Check the CPU, memory and disk of the receiving device.", "Update or restart the application receiving the data."],
        technical="TCP zero-window advertisements from the receiver.",
    )


def _duplicate_ip(s, m, n):
    macs = m.get("macs", [])
    return Explanation(
        what=(
            f"Two different devices are both using the address {m['ip']}: the original one ({m['original_mac']}) and a newer one "
            f"({m['new_mac']}) that appeared later. Traffic for {m['ip']} is delivered to one or the other at random."
        ),
        why="Both devices lose connections intermittently: pages half-load, file copies fail, printers 'disappear'.",
        cause="Someone gave the new device a fixed (static) IP that is also handed out by DHCP, or two devices were manually configured with the same address.",
        fixes=[
            f"Find the device with hardware address {m['new_mac']} (check the router's client list or the switch MAC table).",
            "Set it to obtain an address automatically (DHCP), or give it a fixed address outside the DHCP range.",
            "Reserve addresses for printers/servers in the DHCP server instead of configuring them by hand.",
        ],
        technical=f"{len(macs)} MACs actively originate traffic with source {m['ip']}.",
    )


def _arp_conflict(s, m, n):
    return Explanation(
        what=f"Devices disagree about who owns {m['ip']}: {'; '.join(m.get('descriptions', []))}.",
        why="Other devices keep switching which hardware they send traffic for this address to, causing intermittent drop-outs.",
        cause="An IP address conflict: usually a statically configured device clashing with DHCP, or a device that was replaced.",
        fixes=["Identify the devices by the hardware addresses listed in the evidence and give one of them a different IP address."],
        technical=f"ARP conflict types: {', '.join(m.get('conflict_types', []))}; MACs: {', '.join(m.get('macs', []))}.",
    )


def _mtu_mismatch(s, m, n):
    adapted = m.get("sender_adapted")
    return Explanation(
        what=(
            f"Somewhere between {n.ip(m['src'])} and {n.ip(m['dst'])} the path can only carry packets up to {m['path_mtu']} bytes, "
            f"smaller than the standard 1500. {n.ip(m['reported_by'])} reported this."
            + (" The sender adjusted and continued normally." if adapted else " The sender did NOT adjust.")
        ),
        why="Oversized packets have to be re-sent smaller, which costs time; if adjustment fails, some websites or VPN connections hang.",
        cause="A VPN, tunnel (PPPoE, GRE, IPsec) or misconfigured link with a smaller MTU on the path.",
        fixes=[
            f"Set the MTU of the tunnel/WAN interface consistently (e.g. {m['path_mtu']}) or enable MSS clamping on the router.",
            "Make sure firewalls do not block ICMP 'fragmentation needed' messages.",
        ],
        technical=f"ICMP fragmentation-needed / packet-too-big, next-hop MTU {m['path_mtu']}; sender adapted: {adapted}.",
    )


def _mtu_blackhole(s, m, n):
    return Explanation(
        what=(
            f"Large packets from {n.ip(m['src'])} to {n.ip(m['dst'])} vanish without a trace: full-size packets ({m['segment_size']} bytes) were re-sent "
            f"{m['retries']} times and never arrived, while small packets on the same connections got through."
        ),
        why="Connections open fine but hang as soon as real data flows: pages load half-way, uploads freeze, VPNs connect but nothing works.",
        cause="A link with a smaller MTU on the path (VPN, tunnel, PPPoE) combined with a firewall that blocks the ICMP messages that would tell the sender to use smaller packets.",
        fixes=[
            "Enable TCP MSS clamping on the router (e.g. MSS 1360 for VPN links).",
            "Allow ICMP type 3 code 4 ('fragmentation needed') through firewalls.",
            "Lower the MTU on the affected interface as a quick test (e.g. 1400) and see if the problem disappears.",
        ],
        technical=f"PMTUD black hole: large DF segments retransmitted with no ACK and no ICMP, {m['flows']} flow(s).",
    )


# --- attack explanations -----------------------------------------------------------------


def _port_scan(s, m, n):
    open_ports = m.get("open_ports_text")
    return Explanation(
        what=(
            f"The device at {m['scanner']} systematically knocked on {m['ports_probed']} different ports across {m['hosts_probed']} device(s) "
            f"in {fmt_duration(max(s.t_end - s.t_start, 0.001))} ({m['probes_per_second']} attempts per second), without actually using any of them."
            + (f" It found open services: {open_ports}." if open_ports else "")
        ),
        why="Scanning is how an attacker maps a network before breaking in: it finds which devices exist and which services can be attacked.",
        cause="Malware on that device, an intruder, or an unauthorised security tool. (Approved vulnerability scanners do this too: check whether a scan was scheduled.)",
        fixes=[
            f"Identify the device at {m['scanner']} and find out who owns it; disconnect it if the scan was not authorised.",
            "Scan that device for malware and change passwords used on it.",
            "Close or firewall the open services that were discovered if they are not needed.",
        ],
        technical=f"Scan types {m.get('scan_types')}, completion {m['completion']:.0%}, vertical {m.get('vertical_targets')}, horizontal {m.get('horizontal_ports')}.",
    )


def _arp_spoof(s, m, n):
    victims = ", ".join(v for v in m.get("victims", []) if v != n.gw_ip) or "other devices"
    imp = " and ".join(n.ip(ip) for ip in m.get("impersonated", {}))
    attacker = f"{m['attacker_mac']}" + (f" (using IP {', '.join(m['attacker_ips'])})" if m.get("attacker_ips") else "")
    return Explanation(
        what=(
            f"The device {attacker} is lying to other devices, pretending to be {imp}. "
            + ("Because it impersonates the gateway, internet traffic from " if m.get("gateway_targeted") else "Traffic from ")
            + f"{victims} is now flowing through it"
            + (f": we saw it relaying {m['relayed_packets']} packets." if m.get("relayed_packets") else ".")
        ),
        why="This is a 'man-in-the-middle' attack: the attacker can read, change or block the victim's traffic, steal passwords and redirect websites.",
        cause="ARP spoofing/poisoning, usually done with tools such as arpspoof, Ettercap or Bettercap by someone on the local network, or by malware on that device.",
        fixes=[
            f"Find the device with hardware address {m['attacker_mac']} (switch MAC table / router client list) and disconnect it.",
            "On the victims, clear the ARP cache (Windows: 'arp -d *', Linux: 'ip neigh flush all') and reconnect.",
            "Enable Dynamic ARP Inspection (DAI) and DHCP snooping on managed switches; add a static ARP entry for the gateway on critical machines.",
            "Assume passwords typed by the victims during the attack window may be compromised; change them.",
        ],
        technical=f"{m['unsolicited_replies']} unsolicited ARP replies, impersonated {m.get('impersonated')}, relayed packets {m['relayed_packets']}.",
    )


def _dns_hijack(s, m, n):
    names = ", ".join(m.get("names", [])[:4])
    forged = ", ".join(m.get("forged_addresses", []))
    real = {k: v for k, v in m.get("real_addresses", {}).items() if v}
    real_txt = "; ".join(f"{k} is really {', '.join(v)}" for k, v in real.items())
    return Explanation(
        what=(
            f"Someone is giving false answers to name lookups: {names} were pointed to {forged} for {', '.join(m.get('victims', []))}."
            + (f" ({real_txt}.)" if real_txt else "")
        ),
        why="Victims who type a correct website name are silently sent to the attacker's machine, which can show fake login pages and steal passwords.",
        cause="DNS spoofing by a device on the local network (often combined with ARP spoofing or a rogue DHCP server), or a compromised router.",
        fixes=[
            f"Find and disconnect the device behind {m['suspect']}.",
            "Flush the DNS cache on the victims (Windows: 'ipconfig /flushdns') and check their DNS settings.",
            "Use DNS over HTTPS/TLS on clients, and only allow the official DNS server through the firewall.",
            "Treat logins made to the affected sites during this time as compromised and reset those passwords.",
        ],
        technical=f"Suspect {m['suspect']} answering as {m['claimed_resolver']}.",
    )


def _rogue_dhcp(s, m, n):
    return Explanation(
        what=(
            f"An unauthorised DHCP server at {m['rogue_server']} is handing out network settings to devices that join, "
            f"telling them to use {', '.join(m['rogue_router']) or '?'} as their gateway and {', '.join(m['rogue_dns']) or '?'} for DNS "
            f"(the real server {m['legit_server']} says {', '.join(m['legit_router']) or '?'} / {', '.join(m['legit_dns']) or '?'}). "
            f"{m['clients_accepted']} device(s) accepted its settings."
        ),
        why="Devices that accept these settings send all their traffic and name lookups to that machine, which can watch or redirect everything.",
        cause="Either an attacker running a fake DHCP server, or someone plugging a home router/hotspot into the office network (that case is accidental but has the same effect).",
        fixes=[
            f"Locate the device {', '.join(m.get('rogue_mac', [])) or m['rogue_server']} on the switch and disconnect it.",
            "Enable DHCP snooping on the switches so only the real DHCP server's port can hand out addresses.",
            "On affected devices, renew the address (Windows: 'ipconfig /release' then '/renew') after the rogue server is gone.",
        ],
        technical=f"{m['offers']} offers; legit server {m['legit_server']}.",
    )


def _arp_storm(s, m, n):
    sweep = not m["router_like"] and m["distinct_targets"] >= 30
    return Explanation(
        what=(
            f"The device {m['mac']} ({', '.join(m['sender_ips'][:3])}) sent {m['requests']} 'who has this address?' broadcasts for "
            f"{m['distinct_targets']} different addresses, up to {m['peak_per_second']} per second. "
            f"{m['unanswered_share']:.0%} of them never got an answer."
        ),
        why="Every ARP request is a broadcast that every device on the network must process; a storm slows everything down, and a sweep is often the first step of an attack.",
        cause=(
            "A device discovering which addresses are in use (network scanner, malware, or an inventory tool)."
            if sweep
            else "A router trying to deliver traffic to addresses where no device exists, often because of scanning from the internet, a wrong route, or a subnet configured too large."
        ),
        fixes=[
            f"Identify the device {m['mac']} and check what is generating the lookups.",
            "If it is the router: check its routes and subnet mask, and block unsolicited inbound traffic to unused addresses.",
            "If it is a computer: check whether a network scan was authorised; scan it for malware if not.",
            "Enable broadcast storm control on managed switches.",
        ],
        technical=f"Peak {m['peak_per_second']}/s over 10 s; sequential share {m['sequential_share']:.0%}; router-like: {m['router_like']}.",
    )


def _host_unreachable(s, m, n):
    gw = m.get("is_gateway")
    return Explanation(
        what=(
            f"Devices ({', '.join(m['askers'][:4])}) tried {m['attempts']} times to find {m['ip']} ({m['role']}) on the local network and nobody answered."
            + (" Without the gateway, nothing can reach the internet." if gw else "")
        ),
        why="Anything that depends on this device (internet access, printing, file shares, DNS) fails completely.",
        cause="The device is switched off, crashed, unplugged, on a different VLAN, or its IP address was changed.",
        fixes=[
            f"Check that the device with address {m['ip']} is powered on and its cable/Wi-Fi link is up.",
            "Check that it still has the expected IP address (it may have taken a different one from DHCP).",
            "Check the switch port and VLAN configuration between the devices.",
        ]
        + (["Restart the router; if it stays silent, check its LAN port and its power supply."] if gw else []),
        technical=f"{m['attempts']} ARP requests for {m['ip']} without a single reply.",
    )


def _icmp_unreachable(s, m, n):
    meaning = {
        "no_route": ("there is no route to these destinations", "A missing or wrong route on a router, a WAN link that is down, or a mistyped address."),
        "blocked": ("traffic to these destinations is administratively blocked", "A firewall rule or access list is rejecting the traffic."),
        "port_closed": ("nothing is listening on the requested ports", "The service is not running, or the clients use the wrong port."),
        "ttl_expired": ("packets expire before they arrive", "A routing loop between routers (or a traceroute, which does this on purpose)."),
    }[m["type"]]
    return Explanation(
        what=f"{n.ip(m['reporter'])} sent {m['messages']} error messages saying {meaning[0]}: {', '.join(m['destinations'][:5])}.",
        why="Connections to these destinations fail immediately or time out.",
        cause=meaning[1],
        fixes=[
            f"Check the routing table / firewall rules on {m['reporter']} for these destinations.",
            "Verify the destination addresses and ports the clients are using.",
            "For TTL-expired messages repeating for the same destination, look for two routers pointing at each other (a routing loop).",
        ],
        technical=f"ICMP {m['type']} x{m['messages']} from {m['reporter']}.",
    )


def _dhcp_failure(s, m, n):
    return Explanation(
        what=f"{len(m['clients'])} device(s) asked for an IP address {m['requests']} times, and {m['reason']}.",
        why="Without an address a device cannot use the network at all; users see 'no internet' or 'limited connectivity'.",
        cause="The DHCP server (often the router) is down or unreachable, its address pool is full, or a DHCP relay is misconfigured.",
        fixes=[
            "Check that the DHCP server/router is running and reachable on this network segment or VLAN.",
            "Look at the DHCP server's lease table: if the pool is full, shorten lease times or enlarge the range.",
            "If DHCP is relayed across VLANs, check the relay (ip helper-address) configuration.",
        ],
        technical=f"offers={m['offers']}, NAKs={m['naks']}, clients={', '.join(m['clients'][:5])}.",
    )


def _dhcp_starvation(s, m, n):
    return Explanation(
        what=(
            f"{m['fake_clients']} different 'devices' asked for an IP address within one minute, physically coming from "
            f"{len(m['sent_from']) or 'a few'} network port(s). They took {m['addresses_taken']} addresses."
        ),
        why="The real DHCP server runs out of addresses, so genuine devices cannot join the network; attackers often follow up with a rogue DHCP server.",
        cause="A DHCP starvation attack (tools such as Yersinia or dhcpstarv) run from a device on the local network.",
        fixes=[
            f"Disconnect the port(s) the requests come from ({', '.join(m['sent_from'][:3])}).",
            "Enable DHCP snooping with a per-port rate limit and port security (limit MAC addresses per port).",
            "Clear the fake leases on the DHCP server.",
        ],
        technical=f"{m['fake_clients']} client MACs in 60 s; sent from {m['sent_from']}.",
    )


def _fragments(s, m, n):
    return Explanation(
        what=f"{m['src']} sent {m['packets_affected']} packet(s) to {n.ip(m['dst'])} broken into pieces that overlap or are impossibly small ({m['overlaps']} overlaps, {m['tiny_fragments']} tiny fragments).",
        why="Malformed fragments are used to crash vulnerable systems (the 'teardrop' attack) or to sneak traffic past firewalls and intrusion detection.",
        cause="A deliberate attack or evasion tool; normal operating systems never produce overlapping fragments.",
        fixes=[
            f"Block or investigate traffic from {m['src']}.",
            "Make sure the target's operating system is patched.",
            "Configure the firewall to drop overlapping and tiny fragments (most do this with 'fragment reassembly' or 'virtual reassembly').",
        ],
        technical=f"overlaps={m['overlaps']}, tiny={m['tiny_fragments']}.",
    )


_KB = {
    "tcp_retransmissions": _retrans,
    "tcp_connection_refused": _refused,
    "tcp_connection_aborted": _aborted,
    "dns_failure": _dns_failure,
    "high_latency": _latency,
    "tcp_zero_window": _zero_window,
    "duplicate_ip": _duplicate_ip,
    "arp_conflict": _arp_conflict,
    "mtu_mismatch": _mtu_mismatch,
    "mtu_blackhole": _mtu_blackhole,
    "port_scan": _port_scan,
    "arp_spoofing": _arp_spoof,
    "dns_hijack": _dns_hijack,
    "rogue_dhcp": _rogue_dhcp,
    "arp_storm": _arp_storm,
    "arp_sweep": _arp_storm,
    "host_unreachable": _host_unreachable,
    "icmp_unreachable": _icmp_unreachable,
    "dhcp_failure": _dhcp_failure,
    "dhcp_starvation": _dhcp_starvation,
    "fragment_attack": _fragments,
}

# Used when an attack-type detector fired but the evidence says "harmless":
# the label must not shout "attack" next to a FAULT verdict.
BENIGN_KIND = {
    "port_scan": "Many connection attempts",
    "arp_spoofing": "IP address takeover",
    "dns_hijack": "Inconsistent DNS answers",
    "rogue_dhcp": "Extra DHCP server",
    "dhcp_starvation": "Many DHCP requests",
    "fragment_attack": "Unusual IP fragments",
}


def benign_title(s: Symptom) -> str:
    m = s.metrics
    if s.kind == "rogue_dhcp":
        return f"A second DHCP server ({m['rogue_server']}) is also handing out addresses"
    if s.kind == "port_scan":
        return f"{m['scanner']} opened connections to many ports or devices"
    if s.kind == "arp_spoofing":
        return f"Device {m['attacker_mac']} took over {', '.join(m.get('impersonated', {}))}"
    if s.kind == "dns_hijack":
        return "Inconsistent DNS answers require investigation"
    if s.kind == "fragment_attack":
        return "Unusual IP fragments require investigation"
    if s.kind == "dhcp_starvation":
        return "Many DHCP requests require investigation"
    return s.title

FRIENDLY_KIND = {
    "tcp_retransmissions": "Packet loss",
    "tcp_connection_refused": "Service unreachable",
    "tcp_connection_aborted": "Connections dropped",
    "dns_failure": "DNS outage",
    "high_latency": "Slow network",
    "tcp_zero_window": "Overloaded receiver",
    "duplicate_ip": "Duplicate IP address",
    "arp_conflict": "Address conflict",
    "mtu_mismatch": "MTU mismatch",
    "mtu_blackhole": "MTU black hole",
    "port_scan": "Port scan",
    "arp_spoofing": "ARP spoofing (man-in-the-middle)",
    "dns_hijack": "DNS hijacking",
    "rogue_dhcp": "Rogue DHCP server",
    "arp_storm": "ARP storm",
    "arp_sweep": "ARP sweep (host discovery)",
    "host_unreachable": "Device unreachable",
    "icmp_unreachable": "Destination unreachable",
    "dhcp_failure": "No IP address (DHCP failure)",
    "dhcp_starvation": "DHCP starvation",
    "fragment_attack": "Fragmentation attack",
}
