# PacketDoctor hackathon review

This is the historical pre-change assessment. The fixes and subsequent verification are recorded in [HACKATHON_IMPROVEMENTS.md](HACKATHON_IMPROVEMENTS.md).

Reviewed on 1 November 2026 against all four pages of `pdf&rendition=1.pdf` and the attached WhatsApp image.

## Assessment

PacketDoctor substantially implements the stated challenge. Its strongest work is the complete path from a capture to a diagnosis, weighted clues, practical fixes, packet evidence, a timeline, and usable offline exports. Detection logic is implemented in the project, rather than delegated to tshark or an existing IDS. The modular separation between decoding, state, detectors, correlation, explanation, and presentation is appropriate.

The main weaknesses are false positives outside the supplied scenarios, incomplete resource protections, an IPv6 privacy leak, misleading health summaries, and an unfinished submission package. Prioritise these before adding detectors or redesigning the interface.

## Estimated rubric score

These are review estimates, not official judging results. The exact weights are from page 4 of the supplied PDF.

| Criterion | Available | Estimate | Reason |
|---|---:|---:|---|
| Novelty | 20 | 16 | Combining faults and attacks with explanations, uncertainty, correlation, and a Wireshark hand-off is useful differentiation. The individual detection techniques are established heuristics, and broader novelty is not independently established. |
| Technical implementation | 30 | 22 | Broad coverage, clear architecture, original logic, working interfaces, extensive tests. DNS and fragment lifecycle errors, incorrect causal links, and an optimistic benchmark scorer reduce confidence beyond the samples. |
| Security of the solution | 20 | 14 | Offline operation, signature validation, safe DOM rendering, temporary files, loopback default, and security headers are valuable. IPv6 anonymisation fails; crafted timestamps crash analysis; state and upload limits have gaps. |
| Feasibility | 10 | 8 | The app, samples, CLI, and standalone report work. The mobile report overflows, setup still contains a clone placeholder, and large-file guarantees need correction. |
| Video presentation | 20 | Unassessed | No video was supplied or found in the project; the README still asks for a public link. |
| **Assessed project subtotal** | **80** | **60** | **75% of the assessable non-video criteria.** |

With no submitted video, the evidence currently supports 60/100 if the entry is accepted for scoring. The PDF makes the 2–5 minute public demo mandatory, so the submission is incomplete until that is supplied. A video earning 18/20 would make the same project approximately 78/100; that is a scenario, not a prediction. Correcting the high-priority issues would improve the technical and security assessment.

## What was actually checked

- Read the rules, challenge requirements, submission requirements, rubric, and attached message; visually inspected the rendered rubric page.
- Reviewed the Python package, detector and state architecture, analysis/correlation/verdict/health logic, CLI, exports, web API, browser renderer and styles, sample generator, benchmark, tests, README, and security/evaluation documents.
- Ran the existing test suite: **122 passed, 1 skipped, 1 warning in 80.39 seconds**. The skipped secret scan was subsequently rerun with a process-local Git ownership setting: **1 passed**. All 123 existing tests therefore passed across those runs.
- Used the bundled Python 3.12 runtime with the project's installed dependencies. The existing `.venv` launcher points to an unavailable Windows Store Python. No dependency upgrades were installed and the environment was not repaired.
- Ran independent synthetic probes, with generated captures confined to `tmp/audit/`. No packets were sent onto a network.
- Ran the actual FastAPI dashboard and used Playwright CLI in Chrome at **1440, 768, and 390 pixels**, inspecting screenshots of upload and report screens.
- Exercised sample analysis, a keyboard-triggered analysis, filtering, timeline navigation, evidence expansion, JSON and HTML downloads, opening the downloaded HTML from disk, invalid uploads, IPv6 anonymised uploads, clean pcapng, dark mode, and reduced-motion preference.
- Confirmed the mixed sample produces three incidents: two ATTACK and one FAULT. The downloaded standalone HTML also renders three incidents. Clean pcapng produces no incidents. No JavaScript page exceptions occurred during these flows.
- Did not rerun the full 300-case benchmark, independently reproduce the documented public-capture evaluation, perform an exhaustive penetration test, install into a clean machine, inspect a video, or verify a public GitHub repository. No Git remote is configured in this checkout.

The UI review used the installed `design-taste-frontend`, `web-design-guidelines`, and `playwright-cli` guidance. The taste skill's marketing-page composition rules were not imposed on this diagnostic dashboard. Accessibility review also used the current [Web Interface Guidelines](https://raw.githubusercontent.com/vercel-labs/web-interface-guidelines/main/command.md).

## Submission requirements

| Requirement | Evidence / action |
|---|---|
| Public GitHub repository | Not verified; this checkout has no remote. Ensure judges can clone the final public repository without signing in. |
| 2–5 minute publicly accessible video | **Missing from reviewed material.** Replace `README.md:7` with the actual public link and check it while signed out. |
| README: problem, solution, features, setup, libraries/APIs | Substantially present. Replace the clone placeholder at `README.md:83`; distinguish measured evidence from unverified claims. |
| Sample captures | Present: 17 capture files, including pcap and pcapng. The synthetic generator and expected outcomes are documented. |
| Own detection/diagnosis logic | Supported by source inspection. Scapy handles parsing; the repository implements the diagnostic logic. Authorship itself cannot be proven from code. |
| Built during the event | Local commit timestamps run from 31 October 22:23 to 1 November 00:39 IST, within the stated event window. Local history does not prove authorship or push times. |
| Safe testing | The supplied samples and this review's captures are synthetic. No active network testing was performed. |
| No hardcoded secrets | The existing tracked-file secret-pattern test passed on its separate rerun. This is a scoped check, not proof that no possible secret exists in Git history. |
| Team and deadline | Team size must be 1–3; only the leader submits. Submit through the supplied form before **1 November 2026, 21:00 IST**. Team membership and final submission were not verified. |

## Findings to fix before submission

### 1. High: IPv6 addresses survive anonymisation

**Location:** `packetdoctor/report/anonymize.py:46`.

`Anonymizer.text()` replaces IPv4 and MAC patterns only. A real end-to-end capture with IPv6 connection refusals, analysed with `anonymize=True`, still exposes `2001:db8::10` and `2001:db8::20` in report content and filters. The same addresses remain visible when uploading that capture with the dashboard's hide-addresses checkbox enabled.

**Impact:** Someone can share an allegedly anonymised report containing original addresses. This directly affects the security rubric.

**Improvement:** Pseudonymise IPv6 as well as IPv4 in structured fields, nested strings, dictionary keys, and display filters. Handle compressed, expanded, and embedded-IPv4 forms consistently. Add an end-to-end IPv6 privacy regression case and explain that DNS names and other contextual identifiers remain unless separately redacted.

### 2. High: a crafted capture timestamp crashes the CLI

**Location:** `packetdoctor/engine/analyze.py:218`; `packetdoctor/cli.py:66`.

A small pcapng with an otherwise ordinary packet and the maximum 64-bit timestamp reaches `datetime.fromtimestamp()` without a range check. Analysis raises `OSError: [Errno 22] Invalid argument` on this Windows runtime. `CliRunner` exits with code 1 and an uncaught `OSError`. The CLI only catches `CaptureError`.

**Impact:** The promise to handle hostile or broken captures without crashing does not hold for timestamps. A web upload is caught by the broad API handler, but still fails analysis.

**Improvement:** Validate timestamp finiteness and supported display range, report invalid timestamps as malformed input or retain relative timing with a warning, and translate expected input errors to `CaptureError`. Also guard timestamp conversion and shared-state updates outside the detector exception handlers.

### 3. High: legitimate reuse of a fragment ID becomes an ATTACK

**Location:** `packetdoctor/detectors/attacks/ip_fragments.py:31`.

Fragment state is keyed by source, destination, protocol, and IP ID, but is never retired on completion or expiry. Two separately valid fragmented UDP datagrams using ID 123, **180 seconds apart**, were compared against one another because their fragment sizes differed. The output was `fragment_attack / ATTACK` despite no overlapping fragments within either datagram.

**Impact:** Longer normal captures can produce false attack verdicts, undermining the challenge's low-false-alarm requirement.

**Improvement:** Track an individual datagram lifecycle, retire completed assemblies, expire incomplete assemblies after a bounded interval, and distinguish duplicate capture frames from conflicting fragment content. Include reuse-after-expiry negatives in evaluation.

### 4. High: resource bounds do not cover all state or the entire processing path

**Locations:** `packetdoctor/detectors/attacks/ip_fragments.py:26`, `packetdoctor/state/hosts.py:47`, `packetdoctor/ingest/loader.py:85`, `packetdoctor/web/app.py:90`.

Several collections have no configured global cap: fragment `findings`, ARP claims/conflicts, host `_askers`, and portions of DHCP and scan state. A probe with `max_hosts=10` and 1,000 fragment sources retained **1,000 finding entries**. The existing address-flood test only checks the flow and host tables, so its success does not establish a bound for the complete analysis.

The upload endpoint's size check runs after FastAPI has parsed the `UploadFile`. Starlette can already have spooled the complete multipart file to disk. The analysis semaphore also starts after upload copying and allows an unbounded number of waiting requests.

The packet-size check runs after Scapy reads/dissects the record. In the installed Scapy version, pcapng block bodies are read using their declared block length before the application's packet cap is applied. The analysis clock starts after reader construction, checks between packets, and does not bound finalisation, correlation, or the evidence pass as a whole.

**Impact:** The current claims of flat memory, capped uploads, and a hard overall processing deadline are stronger than the implementation. A local default binding reduces exposure but does not remove hostile-file risks.

**Improvement:** Apply global budgets to every state collection; bound request bytes before multipart parsing and limit queued work; validate pcapng lengths before allocation; use a worker process with a whole-job timeout for untrusted parsing. Report evictions and lost coverage. No destructive memory-exhaustion or disk-exhaustion test was attempted in this review.

### 5. Medium: unrelated DNS queries are treated as one transaction

**Location:** `packetdoctor/state/dns.py:66`.

The query key contains only client IP, client port, and transaction ID. It excludes server, protocol, query name/type, and transaction lifetime. A completed query is retained and any reuse is treated as a retry.

Three successful queries for different names, 30 seconds apart, reusing a port and transaction ID were reported as **one lookup** and produced an UNCERTAIN DNS-hijack incident. Its title still asserted “Forged DNS answers”.

**Improvement:** Match the full transaction context, check question identity, and expire or replace completed transactions when identifiers are reused. Keep genuine retries attached only while that transaction is active. Test same-ID queries across names, resolvers, TCP/UDP, and time.

### 6. Medium: incomplete and uncertain analyses produce reassuring health text

**Locations:** `packetdoctor/engine/health.py:29`, `packetdoctor/engine/analyze.py:40`.

A timeout before reading any packet returns **100/100 Healthy** and says the network looks healthy. An empty capture does the same. Although timeout warnings are present elsewhere, the headline is misleading. The bundled `arp_sweep.pcap` yields one UNCERTAIN incident while the summary says “none of them malicious”.

**Improvement:** Separate analysis coverage from observed network health. Show “insufficient data” for zero coverage, a prominent partial-result status for cutoffs or detector failures, and “requires investigation” when uncertainty remains. Avoid interpreting absence of detected attacks as proof of safety.

### 7. Medium: correlation links events with no plausible timing relationship

**Location:** `packetdoctor/engine/correlate.py:84`.

`_same_path()` compares addresses without checking time. A symptom-level reproduction merged an MTU black hole at seconds 0–5 with retransmissions at seconds 3600–3610. The later loss vanished as a separate incident and received the earlier MTU explanation. Other predicates also omit temporal checks or use broad time-only matching.

**Improvement:** Require a plausible time relationship and relevant flow, host, or network-segment identity for each rule. Prefer “possibly related” when the capture supports association but not a cause. Test repeated, independent incidents on the same hosts.

### 8. Medium: benchmark correctness is overstated

**Location:** `benchmark/run.py:365`.

The scorer counts a finding as correct whenever it is linked, regardless of verdict. A controlled scorer probe with an expected ATTACK DNS-hijack finding linked beneath a FAULT incident returned `correct`.

It also matches by kind, rather than the planted instance's hosts and time interval, and only checks unexpected root kinds for false attacks. An unrelated finding of an expected kind can hide a miss or extra alert. The synthetic generator shares primitives with the samples used during development; the evaluation document acknowledges this dependence, which is good, but it limits the headline's meaning.

**Improvement:** Measure detection, classification, and correlation separately. Match planted instances one-to-one using kind, devices, and time. Account for unmatched root and linked findings. Use a held-out seed set after tuning, and publish case outcomes. Replace the headline “correct verdict” claim until the scorer is corrected and rerun. This review does not establish how many of the existing 305 results would change.

### 9. Medium: mobile report creates page-level horizontal overflow

**Locations:** `packetdoctor/web/static/style.css:78`, `packetdoctor/web/static/report.js:335`.

At a 390-pixel viewport, the mixed report's document width becomes **561 pixels**. The network overview table's grid item retains its intrinsic minimum width, so its supposed scroll container expands the grid track. Desktop and tablet had no document-level overflow; all upload viewports passed.

**Improvement:** Use zero-minimum grid tracks such as `minmax(0, 1fr)`, apply `min-width: 0` to relevant grid children, and contain table scrolling within the card. Keep deliberate timeline scrolling local to its own region. Verify long filenames, multiple MAC addresses, and IPv6 strings as well as the showcase sample.

### 10. Medium: timeline navigation fails for filtered incidents

**Location:** `packetdoctor/web/static/report.js:186`.

After choosing “Faults (1)”, clicking an attack in the timeline leaves its target card hidden. `focusIncident()` only scrolls and flashes the card; it does not reconcile the active filter. The user is offered an action that cannot reveal its destination.

**Improvement:** Reveal the target and update the filter, or visibly explain that the incident is filtered out. Move keyboard focus to the revealed incident heading and keep it clear of the sticky header.

### 11. Medium: accessibility needs contrast, focus, and status fixes

**Locations:** `packetdoctor/web/static/style.css:29`, `packetdoctor/web/static/style.css:107`, `packetdoctor/web/templates/index.html:41`, `packetdoctor/web/static/app.js:31`, `packetdoctor/web/static/report.js:299`.

- White text on the dark-mode teal primary button measures approximately **2.14:1**, below the 4.5:1 normal-text target. The light-theme amber token on white measures approximately 4.24:1 before further opacity effects.
- With reduced motion requested, the spinner still has the `spin` animation. Timeline navigation always requests smooth scrolling.
- Keyboard users can tab from upload to the checkbox and activate a sample with Enter, but focus falls back to `BODY` when the selected view is hidden. Loading and successful results have no live status announcement.
- Filter buttons expose their selection only through CSS classes; add appropriate selected/pressed semantics. Timeline SVG targets need clear interactive roles and names. Add a skip link.

**Improvement:** Use accessible foreground/background pairs, respect reduced motion, announce async state changes, and deliberately move focus between upload, loading/error, and diagnosis states. The existing error alert and visible focus styles are useful foundations.

### 12. Medium: several generated Wireshark filters are invalid for IPv6

**Location:** `packetdoctor/explain/wireshark.py:26`.

The IPv6 connection-refusal probe generated `ip.addr == 2001:db8::20 && tcp.port == 80 ...`. IPv6 requires the appropriate IPv6 fields. The module already has an `_ip()` helper, but only some branches use it.

**Improvement:** Use protocol-aware address helpers consistently for every supported diagnosis, including source/destination filters, MTU, DNS, and scans. Clarify that pseudonymised display filters are descriptive and cannot be pasted against the original capture.

## Additional improvements

These are useful follow-up work after the submission blockers and reproduced bugs.

- **State eviction and flow reuse:** Most TCP/DNS diagnoses are computed from state remaining at finalisation. LRU eviction can remove early evidence without a coverage warning. TCP state also needs a new connection generation when a closed four-tuple is reused. Aggregate sufficient statistics as flows expire and expose degraded coverage.
- **Confidence wording:** Noisy-OR combines manually chosen, often correlated clues. A displayed 92% confidence is not a calibrated 92% probability of an attack. Label it an evidence score or explicitly explain its heuristic meaning until independently calibrated.
- **Evidence completeness:** `_collect_evidence()` suppresses exceptions and ignores its own cutoff warnings. Missing evidence should be disclosed, especially if reports cite exact packet numbers. Avoid a second full decoding pass when possible; record compact evidence rows during the primary pass.
- **Clearer first action:** Incident cards are informative but long. Put one short recommended next action and affected device beside each incident summary, leaving technical reasoning and additional fixes expandable. Preserve the full explanation and evidence.
- **Progress and cancellation:** Large uploads show only a spinner. Display the configured file limit before selection, explain analysis cutoffs, and provide cancellation with bounded worker cleanup. Do not manufacture progress percentages.
- **Real-capture reproducibility:** Add exact public source URLs, hashes, versions, expected outcomes, and a reproducible retrieval procedure where redistribution is not allowed. The current narrative cannot independently substantiate the real-world claims.
- **Setup and packaging:** Replace the clone placeholder. Validate documented setup in a fresh virtual environment. Source-checkout samples work; packaged installations do not automatically include the top-level `samples/` directory. Document that distinction or package the examples.
- **Documentation consistency:** The README says 16 detectors while the registry contains 15 detector classes, some producing multiple finding types. Explain the distinction. Avoid absolute “payloads never exported” wording when evidence-pcap export deliberately preserves original packet bytes; the CLI warning is appropriate.
- **Dependency evidence:** The direct requirements are pinned, while `pyproject.toml` permits later versions and transitive packages are not locked. A prior `pip-audit` claim does not establish the security of every future installation. Record the audited dependency set and date; no new vulnerability audit was performed here.

## Suggested order of work

1. Complete the public repository, clone command, and genuine public demo video. These determine whether judges can evaluate the entry.
2. Fix IPv6 anonymisation and the timestamp crash; add focused regression coverage.
3. Fix fragment and DNS transaction lifetimes, the incomplete/uncertain health messages, and causal time checks.
4. Correct the benchmark scoring and rerun it before recording accuracy claims in the demo.
5. Close resource-budget gaps, then fix mobile overflow, timeline/filter behaviour, contrast, and keyboard state transitions.
6. Run a clean-install rehearsal and record the final demonstration using that exact checkout.

## Suggested genuine demo, approximately 3 minutes 45 seconds

| Time | What to demonstrate |
|---|---|
| 0:00–0:25 | Describe the small-office problem: a fault and an attack can look like the same outage. State the tool's input and output. |
| 0:25–0:50 | Start the app from the documented command. Show a clean capture as a negative control. |
| 0:50–2:00 | Analyse the mixed capture live. Explain the two attacks and one fault, then one root-cause chain and the suggested next action. |
| 2:00–2:35 | Open actual evidence packets and show the exact Wireshark filter or exported evidence capture. |
| 2:35–3:00 | Demonstrate anonymisation, JSON download, and the offline HTML report opening from disk. |
| 3:00–3:25 | Briefly explain the original detector/correlation logic and the measured evaluation after scorer corrections. |
| 3:25–3:45 | State supported traffic, practical limits, and one honest future improvement. |

Do not claim the benchmark proves universal accuracy, a health score proves the network is safe, or an UNCERTAIN finding proves malicious intent. The PDF explicitly warns that fake or misleading demonstrations can disqualify an entry.

## Review artifacts and scope

`tmp/audit/probes.py` reproduces the independent capture probes and writes `tmp/audit/probe-results.json`. `tmp/audit/browser-review.js` contains the browser interaction checks. Screenshots and downloaded reports are also under `tmp/audit/`; Playwright's own session artifacts are under `.playwright-cli/`.

Application source files were not changed as part of this review. The pre-existing `.gitignore` modification was left intact. Review artifacts are local evidence and do not need to be included in the hackathon submission.
