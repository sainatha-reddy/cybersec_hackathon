# Completed hackathon improvements

Implemented on 1 November 2026 following the historical findings in [HACKATHON_REVIEW.md](HACKATHON_REVIEW.md). The video was excluded as requested. This document records changes and observed verification; it does not award an official judging score.

## Finding resolution

| Review finding | Implemented change | Verification |
|---|---|---|
| IPv6 privacy leak | Canonical IPv4/IPv6/MAC pseudonyms, including mapped/scoped IPv6; 64-bit tags reduce identity collisions; remaining DNS/context disclosure is explicit | End-to-end IPv6 capture regression; dashboard privacy check |
| Timestamp crash | Finite/range validation before state updates; portable date formatting; malformed counts and insufficient-data output | Maximum pcapng timestamp regression |
| Fragment ID false attacks | Expiry, completion detection, and assembly retirement allow legitimate ID reuse | Legal fragment-ID reuse regression; existing fragment attack tests; public teardrop sample |
| Incomplete resource protections | Bounded reads before allocation, collection insertion/entry budgets, worker process supervision, whole-job deadlines, memory checks, pre-parser body limits and admission bounds | Host-flood tests, state budget/entry tests, oversized pcapng block, chunked/declared request limits, worker memory/deadline tests |
| DNS transaction collisions | Resolver, protocol, client/server ports, question identity, and lifetime participate in matching; completed identifier reuse starts a new transaction | Three independent queries with the same client port/ID produce three lookups and no incident |
| Misleading health summaries | Complete/partial/insufficient coverage; unusable captures have no numeric health score; uncertainty explicitly needs review | Empty/timeout captures, uncertain ARP sweep, actual browser empty-capture upload |
| Incorrect causal timing | Time checks added to same-path, address-change, ARP and rogue-DNS predicates; stronger identity requirements for starvation/rogue links | Non-overlapping incidents remain separate; existing chain tests pass |
| Optimistic benchmark scorer | One-to-one planted packet matching; independent linked verdicts; unmatched root and linked findings retained; per-case results published | Wrong-verdict and unrelated-instance regressions; independent 300-case run |
| Mobile report overflow | Zero-minimum grid tracks and constrained grid children keep scrolling inside tables/timeline | Browser document width equals viewport width at 1440, 768 and 390 px |
| Timeline/filter conflict | Timeline navigation reconciles filters and moves focus to the revealed incident | Browser click and Enter flows reveal the incident and update pressed state |
| Accessibility gaps | Contrasting light/dark tokens, reduced-motion support, skip link, status announcements, loading/error/result focus, pressed filter state and SVG link semantics | Real-browser keyboard, motion and contrast checks |
| IPv6 Wireshark filters | Protocol-aware address/source/destination helpers and explicit pseudonym filter caveat | IPv6 connection-refusal filter regression |

## Further work completed

- Reused TCP four-tuples start a separate connection generation. Compact retired-flow summaries preserve diagnostic evidence across reuse/eviction within bounded archive capacity. Exhaustion and eviction reduce reported coverage rather than silently claiming completeness.
- Reports cache bounded header-only evidence during the main pass, use the remaining deadline for a fallback pass, and disclose unresolved cited packets. Evidence export bounds reads/time and continues to preserve original bytes only when explicitly requested.
- Evidence scores are described as heuristics, not probabilities. Ambiguous attack-type findings use cautious titles, explanations and investigative fixes rather than instructions that presume malicious intent.
- Incident cards lead with one concrete first action. Verdict reasoning and technical detail are expandable while evidence and full fix steps remain available.
- The dashboard displays actual configured upload/time/memory limits, elapsed analysis time, cancellation, capacity errors and useful failure messages. Jobs have random capability IDs, expire in memory, and release results after delivery. Cancellation/shutdown waits for worker completion before upload cleanup.
- Public-capture source URLs, pinned SHA-256 hashes, expected checks and observed outcomes are reproducible. Capture bytes stay under ignored `tmp/` rather than being redistributed.
- The supplied GitHub URL replaces the clone placeholder. The wheel now includes all 17 synthetic capture files and the web assets.
- Thirty runtime/test dependencies are pinned transitively in `requirements.lock`; the direct package metadata agrees with the runtime pins. The lock reflects the evaluated Windows/Python environment and is not a fully hashed cross-platform supply-chain lock.
- Existing unrelated ignore rules are preserved. Temporary environments, browser output and non-curated capture files are ignored.

## Verification results

### Python tests

The final complete suite passed: **140 passed in 63.80 seconds** on Windows with Python 3.12.14. An earlier focused engine/regression run also passed: **48 passed**. After tightening false-attack accounting, the affected benchmark/regression tests passed again: **18 passed**. The final suite includes 17 new regression tests in addition to the original 123 tests. Framing validation additionally checks record/block boundaries, lengths and pcapng trailers before dissection so a truncated tail cannot silently become complete coverage.

The Git ownership exception used by the secret-pattern test was process-local; no persistent global Git configuration was changed. The pattern test scans tracked working-tree files and is not a full historical secret audit.

### Corrected synthetic benchmark

Command: `python benchmark/run.py --cases 300 --seed 94000`.

| Metric | Observed result |
|---|---:|
| Cases | 300 |
| Planted problems detected | 320/320 |
| Matched problems with correct independent verdict | 320/320 |
| Cases with an unmatched or incorrectly classified ATTACK finding | 0/300 |
| Problem-free cases reported completely clean | 58/63 |
| Elapsed runtime | 356 seconds |

Unmatched findings are retained, including ordinary fault/consequence findings and one extra UNCERTAIN DHCP finding. Some look-alike cases contain a genuine address conflict, so “no planted problem” does not imply “no possible fault”. The benchmark shares synthetic traffic primitives with development samples; the separate seed is additional synthetic validation, not a production accuracy estimate or a calibrated probability.

Detailed type metrics are in [EVALUATION.md](EVALUATION.md). All case outcomes are in [evaluation-results.json](evaluation-results.json). Linked findings receive no unconditional correctness credit.

### Public captures

`python benchmark/real_captures.py --fetch` reproduces four checks using [the pinned manifest](../benchmark/public-captures.json):

| Public capture | Observed result |
|---|---|
| `teardrop.cap` | `fragment_attack / ATTACK` |
| `arp-storm.pcap` | `arp_storm / FAULT` |
| `dhcp.pcap` | No findings |
| `dns.cap` | No findings |

All four checks passed with complete coverage and no detector errors. Source content is checked by SHA-256 on subsequent runs. Results are saved in [public-capture-results.json](public-capture-results.json).

### Dependency audit

`pip-audit` checked the 30 explicitly pinned dependency versions on 1 November 2026 and reported **no known vulnerabilities**. [dependency-audit.json](dependency-audit.json) contains the machine-readable result. Public advisories can change; this does not establish the absence of undiscovered issues.

### Installation and browser behaviour

A wheel was built, installed with the lock file into a new virtual environment, and exercised from outside the source directory. `pip check` reported no broken requirements. The installed package included 17 captures; its mixed-sample analysis returned two attacks and one fault, and both dashboard and sample API requests succeeded. The installed CLI produced the expected summary through an isolated worker.

Playwright CLI's reusable checklist passed against the actual dashboard in Chrome at 1440, 768 and 390 px, with real sample/invalid/empty uploads, JSON and offline HTML downloads, keyboard/timeline/filter flows, evidence expansion, privacy, and cancellation. There were no JavaScript page errors. It confirmed no document overflow, revealed filtered targets, correct diagnosis/error focus, disabled spinner motion under reduced motion, and a dark primary-button contrast ratio of approximately **8.64:1**. The earlier IPv6-specific upload check also confirmed original IPv6 addresses are absent. The reusable assertion checklist is [scripts/browser_check.js](../scripts/browser_check.js), and inspected screenshots are generated under `tmp/ui-checks/`.

## Scope and remaining boundaries

- The video is intentionally unchanged. Mandatory submission steps still include a genuine public 2–5 minute demo and submission by the team leader before the organiser's deadline.
- The supplied repository URL is used in setup documentation. Public access and remote publication could not be independently confirmed through the available web tool. These are local working-tree changes; no commit, branch, push, repository-visibility change or form submission was performed.
- A full 80/80 for the non-video criteria cannot be established by automated tests: novelty, real-world breadth and judging remain panel decisions. The observed defects and the reproducibility gaps identified in the review have been addressed with code, checks and evidence.
- Supervised memory usage is sampled on Windows and can briefly exceed its threshold; Linux adds an address-space limit where available. This worker isolation is not a hostile-code OS sandbox. Local-only binding remains the default, and external hosting needs its own authentication/TLS controls.
- Detection remains focused on the documented network protocols. NDP spoofing, TLS/QUIC application problems and other unsupported attack classes are not claimed. Hand-tuned weights and rule-based correlation need broader independent evaluation before stronger accuracy claims are justified.
- Bounded state/evidence retention can produce partial results. The product now exposes these limits rather than treating missing observations as proof that the network is healthy.
