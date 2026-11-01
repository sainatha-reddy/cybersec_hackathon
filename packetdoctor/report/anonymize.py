"""Pseudonymise IP and MAC addresses in a finished report.

Each address is replaced by a keyed hash (HMAC-SHA256 with a random key that
exists only in memory for this run), so the same address always maps to the
same label inside one report, but labels cannot be reversed or linked across
reports. Useful when sharing a report outside the organisation.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
import secrets

# not part of a longer dotted number, but a sentence-ending '.' is fine
IPV4 = re.compile(r"(?<!\d)(?<!\d\.)(?:\d{1,3}\.){3}\d{1,3}(?!\d)(?!\.\d)")
MAC = re.compile(r"(?<![0-9a-fA-F:])(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}(?![0-9a-fA-F:])")
IPV6 = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F:.]*(?:%[\w.-]+)?(?![\w:])")


class Anonymizer:
    def __init__(self, key: bytes | None = None):
        self.key = key or secrets.token_bytes(32)

    def _tag(self, value: str) -> str:
        return hmac.new(self.key, value.lower().encode(), hashlib.sha256).hexdigest()[:16]

    def _ip(self, m: re.Match) -> str:
        text = m.group(0)
        suffix = "." if text.endswith(".") else ""
        text = text.rstrip(".")
        try:
            addr = ipaddress.ip_address(text)
        except ValueError:
            return text
        if addr.is_unspecified or text == "255.255.255.255":
            return text
        kind = "lan" if addr.is_private else "net"
        return f"{kind}-{self._tag(addr.compressed)}{suffix}"

    def _mac(self, m: re.Match) -> str:
        text = m.group(0)
        if text.lower() in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            return text
        return f"mac-{self._tag(text)}"

    def text(self, value: str) -> str:
        return IPV4.sub(self._ip, IPV6.sub(self._ip, MAC.sub(self._mac, value)))

    def walk(self, obj):
        if isinstance(obj, str):
            return self.text(obj)
        if isinstance(obj, dict):
            return {(self.text(k) if isinstance(k, str) else k): self.walk(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [self.walk(v) for v in obj]
        return obj


def anonymize_report(report: dict) -> dict:
    out = Anonymizer().walk(report)
    out["capture"]["file_name"] = "capture"
    out["anonymized"] = True
    out["privacy_note"] = "IPv4, IPv6 and MAC addresses are pseudonymised. DNS names and other context remain. Pattern filters use pseudonyms; use exact packet filters with the original capture."
    return out
