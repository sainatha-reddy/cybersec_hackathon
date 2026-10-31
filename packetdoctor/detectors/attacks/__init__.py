from .arp_spoof import ArpSpoofDetector
from .dns_hijack import DnsHijackDetector
from .port_scan import PortScanDetector
from .rogue_dhcp import RogueDhcpDetector

ATTACK_DETECTORS = [PortScanDetector, ArpSpoofDetector, DnsHijackDetector, RogueDhcpDetector]
