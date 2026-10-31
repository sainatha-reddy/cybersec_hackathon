"""Single place where Scapy is imported.

Scapy prints warnings about missing libpcap / interfaces on import. We never
sniff or send packets (offline analysis only), so those warnings are noise.
Only the dissector layers we need are imported, not ``scapy.all``.
"""

import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

from scapy.config import conf  # noqa: E402

conf.verb = 0

from scapy.layers.l2 import ARP, Ether, CookedLinux  # noqa: E402,F401
from scapy.layers.inet import ICMP, IP, TCP, UDP, IPerror, TCPerror, UDPerror  # noqa: E402,F401
from scapy.layers.inet6 import IPv6, ICMPv6PacketTooBig, IPerror6  # noqa: E402,F401
from scapy.layers.dns import DNS, DNSQR, DNSRR  # noqa: E402,F401
from scapy.layers.dhcp import BOOTP, DHCP  # noqa: E402,F401
from scapy.utils import PcapReader, PcapNgReader, wrpcap  # noqa: E402,F401
