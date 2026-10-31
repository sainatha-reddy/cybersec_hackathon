"""Small helpers shared across modules."""

from __future__ import annotations

import ipaddress
import re

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def safe_text(value: object, max_len: int = 255) -> str:
    """Turn an untrusted value from a capture (e.g. a DNS name) into a short,
    printable string. Control characters are replaced so they cannot mess up
    terminals or logs. HTML escaping is done separately at render time."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="replace")
    else:
        text = str(value)
    text = _CONTROL_CHARS.sub("?", text)
    if len(text) > max_len:
        text = text[: max_len - 3] + "..."
    return text


def normalize_dns_name(value: object) -> str:
    return safe_text(value).rstrip(".").lower()


# Addresses that only exist inside a site. Defined explicitly because Python's
# ``is_private`` also includes documentation/benchmark ranges that are routed
# like public addresses in lab setups.
_LOCAL_NETS = [
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",  # RFC 1918
        "100.64.0.0/10",  # carrier-grade NAT
        "127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/8",
        "fc00::/7", "fe80::/10", "::1/128",
    )
]


def is_private_ip(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr.version == net.version and addr in net for net in _LOCAL_NETS)


def is_unicast_ipv4(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (
        addr.version == 4
        and not addr.is_multicast
        and not addr.is_unspecified
        and ip != "255.255.255.255"
        and not ip.endswith(".255")
    )


def subnet24(ip: str) -> str:
    return ".".join(ip.split(".")[:3]) + ".0/24"


def fmt_duration(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    if seconds < 120:
        return f"{seconds:.1f} s"
    return f"{seconds / 60:.1f} min"
