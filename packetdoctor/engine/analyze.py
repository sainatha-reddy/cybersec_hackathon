"""End-to-end analysis: capture file in, report dictionary out."""

from __future__ import annotations

import os
from datetime import datetime, timezone

from .. import __version__
from ..config import DEFAULT_SETTINGS, Settings
from ..explain import FRIENDLY_KIND, Namer, explain
from ..ingest import read_capture
from ..models import Category, IngestStats, Symptom, Verdict
from ..pipeline import detect
from .correlate import Group, correlate, overlaps
from .health import health_score
from .verdict import decide

VERDICT_ORDER = {Verdict.ATTACK.value: 0, Verdict.UNCERTAIN.value: 1, Verdict.FAULT.value: 2}
MAX_IDS_PER_INCIDENT = 120
TIMELINE_POINTS = 300


def analyze(path: str | os.PathLike, settings: Settings = DEFAULT_SETTINGS, anonymize: bool = False) -> dict:
    result = detect(path, settings)
    state, stats = result.state, result.stats
    gw_ip, gw_mac = state.hosts.gateway()
    dns_servers = {ip for ip, n in state.dns.server_responses.items() if n >= 3}
    namer = Namer(gw_ip, gw_mac, dns_servers)
    t0 = state.first_ts or 0.0

    incidents = [_incident(g, namer, t0) for g in correlate(result.symptoms)]
    _cross_notes(incidents)
    incidents.sort(key=lambda i: (VERDICT_ORDER[i["verdict"]], -i["severity"], i["t_start"]))
    for n, inc in enumerate(incidents, 1):
        inc["id"] = f"INC-{n}"

    score, grade, summary = health_score(incidents, state.duration)
    evidence = _collect_evidence(path, settings, {i for inc in incidents for i in inc["packet_ids"]}, t0)

    report = {
        "tool": {"name": "PacketDoctor", "version": __version__},
        "analysed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "capture": _capture_info(stats),
        "network": {
            "gateway_ip": gw_ip,
            "gateway_mac": gw_mac,
            "dns_servers": sorted(dns_servers),
            "hosts": _hosts(state),
            "flows": state.flows.total_flows,
            "dns_queries": len(state.dns.queries),
        },
        "health": {"score": score, "grade": grade, "summary": summary},
        "summary": {
            "incidents": len(incidents),
            "attacks": sum(1 for i in incidents if i["verdict"] == "ATTACK"),
            "faults": sum(1 for i in incidents if i["verdict"] == "FAULT"),
            "uncertain": sum(1 for i in incidents if i["verdict"] == "UNCERTAIN"),
        },
        "incidents": incidents,
        "timeline": _timeline(state, incidents, t0),
        "protocols": dict(state.protocols.most_common()),
        "evidence": evidence,
        "detector_errors": result.detector_errors,
    }
    if anonymize:
        from ..report.anonymize import anonymize_report

        report = anonymize_report(report)
    return report


def _incident(g: Group, namer: Namer, t0: float) -> dict:
    root = g.root
    members = [root, *g.related]
    attack_ev = [e for s in members for e in s.attack_evidence]
    # A fault-type view folded into an attack (e.g. the ARP conflict created by
    # spoofing) keeps only its attack clues; its generic benign wording is
    # about honest conflicts and does not apply.
    benign_ev = [e for s in members if s is root or s.category == root.category for e in s.benign_evidence]
    # an attack among the consequences (e.g. DNS hijack caused by a rogue DHCP
    # server) is evidence that the whole chain is malicious
    for s, _ in g.consequences:
        if s.category == Category.ATTACK:
            attack_ev.extend(s.attack_evidence)
    verdict, confidence, a_score, b_score = decide(root.category, attack_ev, benign_ev)
    all_syms = members + [s for s, _ in g.consequences]
    ids = sorted({i for s in all_syms for i in s.packet_ids})
    if len(ids) > MAX_IDS_PER_INCIDENT:
        ids = ids[: MAX_IDS_PER_INCIDENT // 2] + ids[-MAX_IDS_PER_INCIDENT // 2 :]
    t_start = min(s.t_start for s in all_syms)
    t_end = max(s.t_end for s in all_syms)
    hosts = []
    for s in all_syms:
        for h in s.hosts:
            if h not in hosts:
                hosts.append(h)
    return {
        "id": "",
        "kind": root.kind,
        "label": FRIENDLY_KIND.get(root.kind, root.kind),
        "detector_category": root.category.value,
        "verdict": verdict.value,
        "confidence": confidence,
        "attack_score": a_score,
        "benign_score": b_score,
        "severity": max(s.severity for s in members),
        "title": root.title,
        "t_start": t_start,
        "t_end": t_end,
        "rel_start": round(t_start - t0, 3),
        "rel_end": round(t_end - t0, 3),
        "hosts": hosts[:40],
        "explanation": explain(root, namer).to_dict(),
        "evidence_for_attack": [_ev(e) for e in sorted(attack_ev, key=lambda e: -e.weight)],
        "evidence_for_fault": [_ev(e) for e in sorted(benign_ev, key=lambda e: -e.weight)],
        "related": [_brief(s, t0) for s in g.related],
        "consequences": [{**_brief(s, t0), "reason": reason, "what": explain(s, namer).what} for s, reason in g.consequences],
        "notes": [],
        "packet_ids": ids,
        "metrics": root.metrics,
    }


def _ev(e) -> dict:
    return {"text": e.text, "weight": round(e.weight, 2)}


def _brief(s: Symptom, t0: float) -> dict:
    return {
        "kind": s.kind,
        "label": FRIENDLY_KIND.get(s.kind, s.kind),
        "title": s.title,
        "severity": s.severity,
        "rel_start": round(s.t_start - t0, 3),
        "rel_end": round(s.t_end - t0, 3),
        "packet_ids": s.packet_ids[:20],
    }


def _cross_notes(incidents: list[dict]) -> None:
    """Explain to the user how the fault and attack incidents relate."""
    attacks = [i for i in incidents if i["verdict"] == Verdict.ATTACK.value]
    for inc in incidents:
        if inc["verdict"] == Verdict.ATTACK.value:
            inc["notes"].append("This is deliberate activity, not a broken device: restarting the router will not fix it.")
            continue
        related = [
            a for a in attacks
            if set(inc["hosts"]) & set(a["hosts"]) and _span_overlap(inc, a)
        ]
        if related:
            labels = ", ".join(sorted({a["label"] for a in related}))
            inc["notes"].append(f"This happened while an attack ({labels}) involving the same devices was active; it may be a side effect of it.")
        elif inc["verdict"] == Verdict.FAULT.value:
            inc["notes"].append("No signs of tampering (forged ARP, DNS or DHCP) were found for the devices involved: this looks like a genuine fault.")


def _span_overlap(a: dict, b: dict) -> bool:
    return a["t_start"] <= b["t_end"] + 5 and a["t_end"] >= b["t_start"] - 5


def _capture_info(stats: IngestStats) -> dict:
    start = datetime.fromtimestamp(stats.first_ts, timezone.utc).isoformat(timespec="seconds") if stats.first_ts else None
    return {
        "file_name": stats.file_name,
        "format": stats.file_format,
        "bytes": stats.file_bytes,
        "packets": stats.packets_read,
        "decoded": stats.packets_decoded,
        "malformed": stats.malformed,
        "truncated": stats.truncated,
        "timed_out": stats.timed_out,
        "packet_limit_hit": stats.packet_limit_hit,
        "duration_s": round(stats.duration, 3),
        "start": start,
        "warnings": stats.warnings,
    }


def _hosts(state) -> list[dict]:
    out = []
    for ip, macs in list(state.hosts.ip_macs.items())[:300]:
        if not state.hosts.is_local(ip):
            continue
        out.append({"ip": ip, "macs": sorted(macs), "packets": sum(u.ip_packets for u in macs.values())})
    return sorted(out, key=lambda h: tuple(int(p) for p in h["ip"].split(".")))


def _timeline(state, incidents: list[dict], t0: float) -> dict:
    if not state.per_second:
        return {"bucket_s": 1, "series": [], "events": []}
    start, end = min(state.per_second), max(state.per_second)
    span = end - start + 1
    bucket = max(1, -(-span // TIMELINE_POINTS))
    series = {}
    for sec, n in state.per_second.items():
        b = (sec - start) // bucket
        series[b] = series.get(b, 0) + n
    points = [{"t": round(start + b * bucket - t0, 3), "packets": series.get(b, 0)} for b in range(-(-span // bucket))]
    events = [
        {"id": i["id"], "start": i["rel_start"], "end": i["rel_end"], "verdict": i["verdict"], "label": i["label"], "severity": i["severity"]}
        for i in sorted(incidents, key=lambda x: x["t_start"])
    ]
    return {"bucket_s": bucket, "series": points, "events": events}


def _collect_evidence(path, settings: Settings, wanted: set[int], t0: float) -> dict:
    """Second, cheap pass over the file to describe only the packets cited as evidence."""
    if not wanted:
        return {}
    out = {}
    last = max(wanted)
    stats = IngestStats()
    try:
        for rec in read_capture(path, stats, settings):
            if rec.idx in wanted:
                out[str(rec.idx)] = {
                    "no": rec.idx,
                    "time": round(rec.ts - t0, 6),
                    "src": rec.src_ip or rec.src_mac or "",
                    "dst": rec.dst_ip or rec.dst_mac or "",
                    "src_mac": rec.src_mac or "",
                    "proto": _proto(rec),
                    "length": rec.length,
                    "info": rec.summary(),
                }
            if rec.idx >= last:
                break
    except Exception:
        pass  # evidence is best-effort; the analysis itself already succeeded
    return out


def _proto(rec) -> str:
    if rec.arp:
        return "ARP"
    if rec.dhcp:
        return "DHCP"
    if rec.dns:
        return "DNS"
    if rec.icmp_type is not None:
        return "ICMP" if rec.ip_version == 4 else "ICMPv6"
    if rec.is_tcp:
        return "TCP"
    if rec.sport is not None:
        return "UDP"
    return "-"
