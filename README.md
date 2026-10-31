# PacketDoctor

**Finds the faults and attacks hidden in a packet capture, tells you which is which, and explains each one in plain language with the likely cause, a fix and the exact packets as evidence.**

> Network track: *Diagnosing Network Problems from Packet Captures*. Cybersecurity Hackathon, IIITDM Kancheepuram, 31 Oct to 1 Nov 2026.

**Demo video:** _add the public link here before submitting_

---

## The problem

Small offices, labs and campus departments rarely have a network engineer. When "the network is broken", someone has to open a capture in Wireshark and read thousands of lines. That takes deep protocol knowledge. Worse, a **fault** (a DNS server crashing) and an **attack** (someone forging DNS answers) look identical to the user. So people restart the router and wait while the real problem goes on.

## The solution

PacketDoctor treats a capture the way a doctor treats a patient:

| Step | What PacketDoctor does |
|---|---|
| **Symptoms** | 11 detectors written by us read every packet and record specific observations, each tied to packet numbers. |
| **Diagnosis** | A correlation engine groups symptoms into incidents and works out cause and effect. For example: *"ARP spoofing is the cause; the 30 retransmissions after t=58 s are a consequence, not a separate problem."* |
| **Verdict** | Every incident is labelled **FAULT**, **ATTACK** or **UNCERTAIN**, with a confidence score and the list of clues for *both* sides. If the clues don't clearly point one way, the incident is marked UNCERTAIN instead of raising a false alarm. |
| **Prescription** | Beginner-friendly explanation: what happened, why it matters, the likely cause, and numbered steps to fix it. |
| **Health score** | One number (0 to 100) for the whole capture, plus a timeline of when each problem happened. |

It runs **fully offline**: no cloud, no AI service, no API keys. Captures never leave the machine.

### What makes it different from existing tools

- **Wireshark's "Expert Info"** lists thousands of individual events. PacketDoctor groups them into a handful of incidents and explains them.
- **IDS tools (Snort, Suricata, Zeek)** alert on signatures but don't diagnose ordinary faults, and they don't explain them to beginners.
- **Telling fault from attack** is a first-class output. Each verdict comes with weighted evidence for and against, and with explicit benign explanations that were checked. Examples: "a backup DHCP server with the same settings", "a router failover", "split-horizon DNS".
- **Root-cause chains** show *knock-on effects*: rogue DHCP leads to DNS hijacking, a duplicate IP leads to dropped connections, an MTU black hole leads to retransmissions. Fix the root and the rest goes away.
- **Relay detection** spots a man-in-the-middle *physically*: the same packet appears twice on the wire, re-sent by another device's MAC address within milliseconds.

---

## Features

### Faults detected

| Finding | How it is detected (our own logic) |
|---|---|
| TCP retransmissions | Per-flow relative sequence tracking. Each re-sent segment is classified as *fast* (after 3 duplicate ACKs), *timeout* or *spurious* (already acknowledged). Reported per client/server path only above both a count and a ratio threshold. |
| TCP resets | *Refused* (SYN answered by RST on the same service, several times) vs *aborted* (RST on an established connection after data). Clients probing many ports are left to the scan detector. |
| DNS failures | Query/response matching by (client, port, transaction ID). SERVFAIL, REFUSED and unanswered queries per server; NXDOMAIN (typos) is ignored. |
| Duplicate IP | Two MAC addresses that both *actively use* one IP (they start their own connections and ARP requests). Forged ARP replies alone don't count. |
| ARP conflicts | A gratuitous ARP contradicting a live binding, an RFC 5227 probe that gets answered, or one ARP request answered by two MACs. |
| MTU problems | ICMP "fragmentation needed" or "packet too big", with a check that the sender adapted; plus **PMTU black holes**, where full-size segments are retransmitted again and again while small ones get through. |
| Unusual delays | TCP handshake and DNS response times compared with the capture's *own* baseline (median + 6×MAD, with an absolute floor), grouped into episodes; plus TCP zero-window stalls. |

### Attacks detected

| Finding | How it is detected (our own logic) |
|---|---|
| Port scans | Sliding 60-second window for vertical scans (ports per host) and horizontal sweeps (hosts per port). *Completion rate* separates scanners from busy clients. Also detects stealth probe types (FIN, NULL, Xmas) and reports which open ports were found. |
| ARP spoofing / MITM | A MAC claiming an IP first owned by another MAC, unrequested replies, a clockwork timing pattern, one MAC holding several IPs, the gateway being targeted, and **observed traffic relaying**. |
| DNS hijacking | Two disagreeing answers to the same query (a race), answers "from" the resolver's IP but sent by a different MAC, public names answered with local addresses, very low TTLs, and a non-gateway local resolver pointing names at itself. |
| Rogue DHCP | More than one DHCP server. The real one is identified from the gateway, lease history and first sighting. Any other server is checked for a different gateway or DNS server, pointing clients at itself, answering faster, and clients accepting its offer. |

### Interfaces

- **CLI** with colour output: summary table, a panel per incident, evidence packets, `--json` and `--html` export.
- **Local web dashboard**: drag-and-drop upload, health gauge, interactive timeline (click a bar to jump to its explanation), incident cards with clue meters, cause-and-effect chain, evidence tables, filters, and downloads.
- **Standalone HTML report**: one offline file you can email. It contains a strict Content Security Policy and loads nothing from the network.
- **Anonymise mode** (`--anonymize` or a checkbox): IPs and MACs are replaced by keyed-hash pseudonyms before anything is shown or saved.

---

## Setup

Requires **Python 3.10 or newer**. No Wireshark, tshark, Npcap or libpcap is needed, because captures are read with Scapy's pure-Python reader.

```bash
git clone <this-repo-url> packetdoctor
cd packetdoctor
python -m venv .venv

# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
pip install -e .
```

### Run it on the samples

```bash
# the showcase: an outage and two attacks hidden in the same 90 seconds
packetdoctor analyze samples/mixed_fault_and_attack.pcap

# export reports
packetdoctor analyze samples/rogue_dhcp.pcap --json report.json --html report.html

# share safely: addresses pseudonymised
packetdoctor analyze samples/arp_spoofing.pcap --anonymize

# web dashboard, then open http://127.0.0.1:8000
packetdoctor serve
```

`python -m packetdoctor ...` works as well. Run `packetdoctor --help` for all options. `packetdoctor samples` lists the bundled captures.

### Run the tests

```bash
pytest
```

105 tests cover every detector on every sample, benign look-alikes (backup DHCP server, router failover, busy client, split-horizon DNS), the verdict and correlation logic, the CLI, the web API and its security headers, fuzzed and truncated captures, an address-flood capture against the memory limits, hostile strings in packets, and a scan for committed secrets.

---

## Sample captures

All samples are **synthetic**. `samples/generate.py` builds them in memory with Scapy and writes them to disk. No packet was ever sent on a network, and no real traffic was captured. Regenerate them with `python samples/generate.py`.

| File | What is inside | PacketDoctor's diagnosis |
|---|---|---|
| `clean.pcap` / `clean.pcapng` | Normal office traffic, plus harmless noise: 2 mistyped domains and 1 lost packet | **100/100**, no findings (no false alarms) |
| `tcp_retransmissions.pcap` | Lossy path to a file server | FAULT: packet loss |
| `tcp_resets.pcap` | Printer service down; web API aborting transfers | FAULT: service unreachable; FAULT: connections dropped |
| `dns_failure.pcap` | DNS forwarder failing for 25 s | FAULT: DNS outage → slow DNS (consequence) |
| `duplicate_ip.pcap` | New device configured with the desktop's IP | FAULT: duplicate IP (+ ARP conflict) → dropped connections |
| `mtu_problems.pcap` | ICMP frag-needed (handled) and a PMTU black hole | FAULT: MTU black hole → retransmissions; FAULT: MTU mismatch |
| `high_latency.pcap` | Congested link for 20 s; a stalled printer | FAULT: slow DNS; FAULT: slow connection setup; FAULT: zero window |
| `port_scan.pcap` | Vertical scan of the desktop and an SSH sweep of the subnet | ATTACK: port scan (open ports 22, 80, 445) |
| `arp_spoofing.pcap` | MITM of the laptop and the gateway | ATTACK: ARP spoofing (gateway impersonated, 174 packets relayed) |
| `dns_hijack.pcap` | Forged DNS answers racing the real resolver | ATTACK: DNS hijacking (bank and mail sites redirected) |
| `rogue_dhcp.pcap` | Rogue DHCP server handing out itself as gateway and DNS | ATTACK: rogue DHCP → DNS hijacking (consequence) |
| `mixed_fault_and_attack.pcap` | **Showcase:** port scan, DNS outage and ARP-spoofing MITM with packet loss | 2× ATTACK + 1× FAULT, with the MITM's retransmissions linked to the attack |

---

## Architecture

```mermaid
flowchart LR
    A[pcap / pcapng] --> B[Safe loader<br/>magic bytes, size,<br/>time and packet caps]
    B --> C[Decoder<br/>header-only PacketRecord]
    C --> D[Network state<br/>flows, DNS transactions,<br/>ARP/host table, relay tracker]
    D --> E1[7 fault detectors]
    D --> E2[4 attack detectors]
    E1 --> F[Correlation engine<br/>same-problem merges,<br/>cause-and-effect rules]
    E2 --> F
    F --> G[Verdict scorer<br/>noisy-OR of weighted clues<br/>FAULT / ATTACK / UNCERTAIN]
    G --> H[Explainer<br/>plain-language knowledge base]
    H --> I[Report + evidence pass]
    I --> J1[CLI]
    I --> J2[Web dashboard]
    I --> J3[JSON / HTML]
```

- **One streaming pass.** Each packet is decoded once and handed to every detector, and memory stays flat whatever the file size. A second, cheap pass fetches only the packets cited as evidence.
- **Detectors never touch Scapy.** They see a small `PacketRecord` (header fields only, no payload), so all detection logic is ours and independent of the parsing library.
- **The verdict maths.** Each clue has a weight from 0 to 1, and clues are combined as `1 − Π(1 − w)`. An incident is an ATTACK only when attack clues reach 0.6 *and* beat the benign clues by 0.25. A clear benign margin makes it a FAULT; anything in between is UNCERTAIN.
- **Health score.** The score starts at 100. Each incident subtracts points by severity, scaled up for attacks and for how much of the capture it covers.

```
packetdoctor/
  ingest/      loader.py (safe reading), decoder.py (PacketRecord)
  state/       flows.py, dns.py, hosts.py, relay.py, lru.py
  detectors/   faults/ (7 detectors), attacks/ (4 detectors), base.py
  engine/      correlate.py, verdict.py, health.py, analyze.py
  explain/     knowledge.py (plain-language explanations and fixes)
  report/      html.py (standalone report), anonymize.py
  web/         app.py (FastAPI), static/ (renderer, styles), templates/
  cli.py
samples/       generate.py + 13 sample captures
tests/         105 tests
```

---

## Security of the solution

The full details are in [SECURITY.md](SECURITY.md). In short:

- **Untrusted input.** The file type is identified by magic bytes, never by extension. File size, packet count, packet size and wall-clock time are all capped. Captures are streamed, never loaded whole. A malformed packet is skipped and counted; a truncated or corrupt file ends the analysis cleanly. All of this is fuzz-tested.
- **Bounded memory.** Every flow, host and DNS table has an LRU size cap, so an address-flood capture cannot exhaust RAM (tested).
- **No data leaks.** Payloads are never stored, only header fields. Nothing is sent anywhere. Reports are written owner-readable only where the OS supports it. Error messages never include stack traces or full paths. Anonymise mode uses keyed-hash pseudonyms with a per-run random key.
- **Web dashboard.** It binds to 127.0.0.1 by default. Uploads are streamed to a randomly named file in a private temp directory with a size cap, then deleted. Samples are served from an allow-list (no path traversal). A strict Content Security Policy with no inline scripts is set, along with `X-Frame-Options: DENY`, `nosniff` and `no-store`. API docs are disabled. Concurrent analyses are limited.
- **No injection.** Strings from packets (DNS names and so on) are stripped of control characters, so they can't hijack terminals. The browser renderer uses `textContent` only, never `innerHTML` (enforced by a test). JSON embedded in HTML reports is escaped so it cannot close its `<script>` tag (tested with a hostile payload).
- **No secrets.** There are no keys, tokens or passwords anywhere; a test scans the repository. `pip-audit` found no known vulnerabilities in the pinned dependencies.

---

## Limitations and honest notes

- **Throughput** is about 4–5k packets per second on a laptop (Scapy's dissector is the bottleneck), so a 100k-packet capture takes roughly 25 s. The time limit and packet limit are configurable.
- **Coverage.** Detection is IPv4-focused. IPv6 TCP/UDP traffic and ICMPv6 "packet too big" are handled, but NDP spoofing is not yet detected.
- **Encrypted traffic.** Application-layer problems inside encrypted traffic (TLS/QUIC) are out of scope; the tool diagnoses the network layers below.
- **Vantage point matters.** Relay detection needs a capture point (mirror/SPAN port or the victim itself) that sees both legs of the relayed traffic.
- **Thresholds.** These live in `packetdoctor/config.py` and are tuned for small networks.

---

## Libraries used

| Library | Licence | Used for |
|---|---|---|
| [Scapy](https://scapy.net) | GPL-2.0 | Reading pcap/pcapng and dissecting headers (also used by the sample generator) |
| [FastAPI](https://fastapi.tiangolo.com) + [Starlette](https://www.starlette.io) | MIT / BSD-3 | Local web dashboard API |
| [Uvicorn](https://www.uvicorn.org) | BSD-3 | ASGI server for the dashboard |
| [python-multipart](https://github.com/Kludex/python-multipart) | Apache-2.0 | File-upload parsing |
| [Typer](https://typer.tiangolo.com) | MIT | Command-line interface |
| [Rich](https://github.com/Textualize/rich) | MIT | Coloured terminal output |
| [pytest](https://pytest.org), [httpx](https://www.python-httpx.org) | MIT / BSD-3 | Tests |

All detection, correlation, verdict, explanation and visualisation code (including the SVG timeline and the report renderer) was written by the team during the hackathon. No external APIs or AI services are used at runtime.

## Responsible use

PacketDoctor only *reads* capture files and never sends packets. Analyse only captures from networks you own or have permission to monitor. The bundled samples are synthetic.

## Licence

PacketDoctor's own code is MIT (see [LICENSE](LICENSE)). It depends on Scapy, which is GPL-2.0; redistributing a bundle that includes Scapy is subject to Scapy's licence.
