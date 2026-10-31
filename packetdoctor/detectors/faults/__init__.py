from .arp_conflict import ArpConflictDetector
from .dns_failure import DnsFailureDetector
from .duplicate_ip import DuplicateIpDetector
from .latency import LatencyDetector
from .mtu import MtuDetector
from .tcp_reset import TcpResetDetector
from .tcp_retrans import TcpRetransmissionDetector

FAULT_DETECTORS = [
    TcpRetransmissionDetector,
    TcpResetDetector,
    DnsFailureDetector,
    DuplicateIpDetector,
    ArpConflictDetector,
    MtuDetector,
    LatencyDetector,
]
