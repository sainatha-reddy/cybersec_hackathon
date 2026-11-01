# Security design

PacketDoctor reads files that may come from anywhere, and they may be deliberately malicious. This page lists each threat and the defence in the code.

| Threat | Defence | Where | Test |
|---|---|---|---|
| Non-capture file disguised as `.pcap` | The format is identified by magic bytes only (pcap µs/ns in both byte orders, pcapng) | `ingest/loader.py` `validate_capture` | `test_rejects_wrong_magic_even_with_pcap_extension` |
| Huge file / memory exhaustion | File-size cap (default 500 MB; 200 MB for uploads); streaming reader, never `rdpcap` | `config.Limits`, `loader.read_capture` | `test_rejects_oversized_file`, `test_upload_size_limit` |
| Endless processing | Wall-clock time limit and packet-count limit; partial results are reported with a warning | `loader.read_capture` | `test_timeout_stops_cleanly`, `test_packet_limit` |
| Malformed / truncated / corrupt packets | Per-packet decode in try/except (counted and skipped); a corrupt record header stops the read cleanly; oversized records are rejected | `loader.read_capture` | `test_fuzzed_captures_never_crash` (60 mutated files), `test_truncated_capture_is_handled` |
| State-table flooding | Shared collection item budget, capped state tables, partial-result warnings and supervised worker memory monitoring | `state/budget.py`, `pipeline.py`, `worker.py` | `test_address_flood_respects_memory_caps`, `test_state_budget_stops_with_partial_results` |
| A crashing detector taking down the analysis | Each detector runs in isolation; errors are reported, not raised | `pipeline.detect` | covered by the fuzz test |
| Terminal-escape injection from packet strings | Control characters are replaced and length capped for every string taken from a packet | `utils.safe_text`, decoder | `test_hostile_strings_are_neutralised` |
| HTML/JS injection in the dashboard | DOM built with `textContent` / `createElement` only; no `innerHTML`, `eval` or `document.write` | `web/static/report.js` | `test_renderer_never_uses_innerhtml` |
| Breaking out of the JSON embedded in HTML reports | `<`, `>`, `&`, U+2028/2029 escaped as `\uXXXX`; `</` in inlined JS escaped | `report/html.py` | `test_html_report_cannot_be_broken_by_hostile_capture_strings` |
| Report loading remote content / tracking | Standalone reports carry `default-src 'none'` CSP; the dashboard uses `default-src 'self'` with no inline scripts and no CDN | `report/html.py`, `web/app.py` | `test_html_report_is_self_contained`, `test_security_headers` |
| Path traversal via sample names or upload names | Samples are looked up in an allow-list dict; uploads are saved under a random name; the client file name is sanitised and used for display only | `web/app.py` | `test_sample_path_traversal_rejected`, `test_upload_filename_is_sanitised` |
| Uploaded captures left on disk | Private `TemporaryDirectory`, deleted after every request (also on errors) | `web/app.py` | `test_temp_files_are_deleted` |
| Dashboard exposed to the network | Binds to `127.0.0.1` by default; warns if another interface is chosen | `cli.serve` | manual (`netstat` shows 127.0.0.1 only) |
| Clickjacking / MIME sniffing / caching of results | `frame-ancestors 'none'`, `X-Frame-Options: DENY`, `nosniff`, `Cache-Control: no-store` on the API, `Referrer-Policy: no-referrer` | `web/app.py` | `test_security_headers` |
| Information disclosure in errors | User-facing `CaptureError` messages contain only the file's base name; temp names are never echoed; API docs/OpenAPI disabled | `loader`, `web/app.py` | `test_error_message_does_not_leak_full_path`, `test_no_api_docs_exposed` |
| Sharing reports leaks addresses | IPv4, IPv6 and MAC addresses use canonicalised, 64-bit HMAC tags with a random per-run key. DNS names and other contextual identifiers remain and are explicitly disclosed | `report/anonymize.py` | `test_ipv6_anonymization_is_canonical_and_complete`, `test_upload_anonymized` |
| Sensitive application payloads | Reports retain selected header metadata only. DNS TXT data is excluded. Original capture bytes are preserved only when the user requests evidence-pcap export | `models.PacketRecord`, decoder, `report/export.py` | hostile-string and evidence-export tests |
| Evidence export leaking payloads | `--export-evidence` copies only the cited packets, warns that they contain original bytes, writes them owner-readable, and refuses to run together with `--anonymize` | `report/export.py`, `cli.analyze` | `test_cli_refuses_export_with_anonymize` |
| Hard-coded secrets | None exist; `.gitignore` excludes `.env`, keys and stray captures; repository scanned by a test | `.gitignore` | `test_no_secrets_committed` |
| Vulnerable dependencies | Runtime and transitive test dependencies pinned in `requirements.lock`; machine-readable advisory audit retained with the evaluation artifacts | `requirements.lock`, `docs/dependency-audit.json` | `pip-audit -r requirements.lock --no-deps --disable-pip` |

## Additional protections and limits

- The ASGI upload guard caps declared and chunked request bodies before multipart parsing. The file-copy stage independently enforces the file limit. At most two starting/running analyses are admitted; additional requests receive HTTP 429. Multipart overhead has a bounded 64 KiB allowance.
- CLI and web analyses use a spawned subprocess, supervised for the full job duration, including report assembly. Cancellation terminates and joins the worker before temporary upload cleanup. The memory supervisor checks resident/committed usage on Windows and resident usage on Linux at approximately 50 ms intervals; allocations can transiently exceed the sampled threshold. Linux workers additionally use an address-space limit where supported. This is not an OS security sandbox.
- Capture reads reject allocations larger than the packet budget plus 64 KiB metadata allowance before calling the underlying file reader. Invalid, non-finite, and unsupported timestamps are skipped and counted. Empty or wholly unusable captures receive an insufficient-data result, without a health score.
- Collection budgets count cumulative retained insertions conservatively, so repeated churn may stop before the process memory budget is reached. Evicted or reused TCP flows retain compact diagnostic summaries in a bounded archive; archive limits, LRU evictions and budget stops are disclosed as incomplete coverage. Programmatic callers of `engine.analyze` get these input/state checks; callers needing enforced whole-job termination should use `worker.analyze_isolated` as the interfaces do.
- Browser background jobs use random capability IDs, retain results in memory for at most two minutes after completion, and support explicit cancellation/release. The dashboard releases the server copy after receiving the report. Files and results are not durable server-side storage.
- Evidence collection uses a bounded header cache and only the remaining time budget for a fallback pass. Missing cited rows produce an explicit warning. Evidence export separately bounds reads and elapsed time.
- A health score describes observed supported traffic. Partial capture coverage, unavailable evidence, or detector errors prevent an unconditional healthy result; UNCERTAIN findings require investigation. Evidence scores are heuristic and do not establish malicious intent with a calibrated probability.

The defaults target a local diagnostic tool. Binding it to an external interface does not add authentication, TLS, or tenant isolation; deploy it only behind appropriate controls if network access is required.

## Reporting a problem

Please open an issue on the repository.
