"""Limits and detection thresholds.

Everything tunable lives here so detectors contain logic, not magic numbers.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Limits:
    """Hard safety limits for reading untrusted capture files."""

    max_file_bytes: int = 500 * 1024 * 1024  # 500 MB
    max_packets: int = 5_000_000
    timeout_seconds: float = 300.0
    max_packet_bytes: int = 262_144  # libpcap max snaplen
    max_flows: int = 200_000  # LRU-capped state tables
    max_hosts: int = 100_000
    max_evidence_per_symptom: int = 50  # packet ids kept per finding
    max_state_items: int = 1_000_000
    max_memory_mb: int = 512
    max_incidents: int = 2_000


@dataclass(frozen=True)
class Thresholds:
    # TCP retransmissions
    retrans_min_count: int = 5
    retrans_min_ratio: float = 0.03  # 3% of data segments in a flow
    # TCP resets
    reset_min_count: int = 3
    # DNS
    dns_timeout_s: float = 2.0
    dns_failure_min: int = 3
    dns_failure_ratio: float = 0.25
    # Latency (robust outliers vs. the capture's own baseline)
    latency_mad_k: float = 6.0
    latency_min_abs_s: float = 0.25
    latency_min_samples: int = 3
    zero_window_min: int = 2
    # MTU
    mtu_blackhole_retries: int = 3
    # Port scan
    scan_window_s: float = 60.0
    scan_min_ports: int = 15
    scan_min_hosts: int = 10  # horizontal sweep
    scan_max_completion: float = 0.3  # share of probes that became real connections
    # ARP spoofing
    arp_unsolicited_min: int = 3
    arp_flood_rate: float = 0.2  # unsolicited replies per second
    # Duplicate IP
    dup_ip_min_packets: int = 3
    # ARP storm / sweep
    arp_storm_min_requests: int = 100  # requests from one device within 10 s
    arp_sweep_min_targets: int = 30
    # Unreachable devices
    unreachable_min_requests: int = 5  # ARP attempts with no answer at all
    # DHCP
    dhcp_fail_min_requests: int = 3
    dhcp_starvation_min_macs: int = 20  # distinct client MACs in 60 s


@dataclass(frozen=True)
class Settings:
    limits: Limits = field(default_factory=Limits)
    thresholds: Thresholds = field(default_factory=Thresholds)


DEFAULT_SETTINGS = Settings()
