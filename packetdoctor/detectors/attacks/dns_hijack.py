from __future__ import annotations

from collections import Counter, defaultdict

from ...models import Category, Evidence, Symptom
from ...utils import is_private_ip
from ..base import Detector

LOW_TTL = 30


class DnsHijackDetector(Detector):
    """Forged or redirected DNS answers.

    Indicators (each a weighted piece of evidence, grouped per suspect):
    * two answers to the same query that disagree (a race between a forger and
      the real server);
    * an answer 'from' the resolver's IP but sent by a different MAC than the
      resolver normally uses (spoofed source);
    * a public name answered with a local/private address, when the same name
      resolves to a public address elsewhere;
    * a local device that is not the network's normal resolver answering DNS
      and pointing names at itself."""

    name = "dns_hijack"

    def finalize(self, state):
        queries = state.dns.all_queries()
        if not queries:
            return []
        # Usual MAC for each resolver IP, and the network's main resolver
        resolver_macs: dict[str, Counter] = defaultdict(Counter)
        for q in queries:
            for r in q.responses:
                if r.src_mac:
                    resolver_macs[r.src_ip][r.src_mac] += 1
        usual_mac = {ip: c.most_common(1)[0][0] for ip, c in resolver_macs.items() if c}
        gw_ip, gw_mac = state.hosts.gateway()
        public_answers: dict[str, set] = defaultdict(set)
        # local, non-gateway resolvers: which names they map to which private address
        local_resolver_map: dict[str, dict[str, set]] = defaultdict(lambda: defaultdict(set))
        for q in queries:
            for r in q.responses:
                for a in r.answers:
                    if not _is_ip(a):
                        continue
                    if not is_private_ip(a):
                        public_answers[q.qname].add(a)
                    elif r.src_ip != gw_ip and state.hosts.is_local(r.src_ip):
                        local_resolver_map[r.src_ip][a].add(q.qname)

        suspects = defaultdict(lambda: {"evidence": {}, "ids": [], "t": [], "names": set(), "victims": set(), "forged": set(), "resolver": None})

        def flag(key, q, resp, reason, weight):
            s = suspects[key]
            s["evidence"][reason] = max(weight, s["evidence"].get(reason, 0))
            s["ids"].extend([q.idx, resp.idx])
            s["t"].append(resp.ts)
            s["names"].add(q.qname)
            s["victims"].add(q.client)
            s["forged"].update(a for a in resp.answers if _is_ip(a))
            s["resolver"] = resp.src_ip

        for q in queries:
            ok = [r for r in q.responses if r.rcode == 0 and r.answers]
            if len({r.answers for r in ok}) >= 2:
                # pick the odd one out: different MAC from usual, or private answer, or lower TTL
                odd = max(ok, key=lambda r: ((r.src_mac != usual_mac.get(r.src_ip)), any(is_private_ip(a) for a in r.answers if _is_ip(a)), -(r.min_ttl or 0)))
                flag(odd.src_mac or odd.src_ip, q, odd, "Two different answers came back for the same question: someone raced the real DNS server", 0.5)
            for r in ok:
                expected = usual_mac.get(r.src_ip)
                if expected and r.src_mac and r.src_mac != expected:
                    flag(r.src_mac, q, r, f"Answers claim to come from {r.src_ip} but were sent by a different device ({r.src_mac})", 0.4)
                private = [a for a in r.answers if _is_ip(a) and is_private_ip(a)]
                if private and public_answers.get(q.qname) and not any(is_private_ip(x) for x in public_answers[q.qname] if x not in private):
                    key = r.src_mac if (expected and r.src_mac != expected) or len({x.answers for x in ok}) > 1 else r.src_ip
                    flag(key, q, r, f"{q.qname} normally resolves to a public address but was answered with local address {private[0]}", 0.3)
                    if r.min_ttl is not None and r.min_ttl < LOW_TTL:
                        flag(key, q, r, f"The forged answers expire after only {r.min_ttl} s, so the attacker can quietly switch them back", 0.1)
                mapping = local_resolver_map.get(r.src_ip)
                if mapping:
                    for a in r.answers:
                        names_same_ip = mapping.get(a, set())
                        if a == r.src_ip:
                            flag(r.src_ip, q, r, f"{r.src_ip} is not the network's main DNS server (the gateway), yet it answers DNS and points names at itself", 0.4)
                        if len(names_same_ip) >= 2:
                            flag(r.src_ip, q, r, f"{len(names_same_ip)} different websites are all answered with the same local address {a}", 0.3)

        unsolicited = state.dns.unsolicited
        if len(unsolicited) >= 10:
            by_src = Counter(r.src_mac or r.src_ip for r in unsolicited)
            for key, n in by_src.items():
                if n >= 10:
                    s = suspects[key]
                    s["evidence"][f"{n} DNS answers arrived for questions nobody asked (cache-poisoning attempt)"] = 0.3
                    s["ids"].extend(r.idx for r in unsolicited if (r.src_mac or r.src_ip) == key)
                    s["t"].extend(r.ts for r in unsolicited if (r.src_mac or r.src_ip) == key)

        out = []
        for key, s in suspects.items():
            score = sum(s["evidence"].values())
            if score < 0.4:
                continue
            names = sorted(s["names"])
            sym = Symptom(
                kind=self.name,
                category=Category.ATTACK,
                severity=5 if score >= 0.8 else 4,
                title=f"Forged DNS answers redirect {', '.join(names[:3]) or 'names'}{'...' if len(names) > 3 else ''}",
                t_start=min(s["t"]),
                t_end=max(s["t"]),
                hosts=[key, *sorted(s["victims"]), *sorted(s["forged"])],
                packet_ids=self.ids(s["ids"]),
                metrics={
                    "suspect": key,
                    "claimed_resolver": s["resolver"],
                    "names": names,
                    "victims": sorted(s["victims"]),
                    "forged_addresses": sorted(s["forged"]),
                    "real_addresses": {n: sorted(public_answers.get(n, [])) for n in names},
                },
                attack_evidence=[Evidence(t, w) for t, w in s["evidence"].items()],
            )
            out.append(sym)
        return out


def _is_ip(text: str) -> bool:
    return text.count(".") == 3 and all(p.isdigit() for p in text.split(".")) or ":" in text
