# Security design

PacketDoctor reads files that may come from anywhere, and they may be deliberately malicious. This page lists each threat and the defence in the code.

| Threat | Defence | Where | Test |
|---|---|---|---|
| Non-capture file disguised as `.pcap` | The format is identified by magic bytes only (pcap µs/ns in both byte orders, pcapng) | `ingest/loader.py` `validate_capture` | `test_rejects_wrong_magic_even_with_pcap_extension` |
| Huge file / memory exhaustion | File-size cap (default 500 MB; 200 MB for uploads); streaming reader, never `rdpcap` | `config.Limits`, `loader.read_capture` | `test_rejects_oversized_file`, `test_upload_size_limit` |
| Endless processing | Wall-clock time limit and packet-count limit; partial results are reported with a warning | `loader.read_capture` | `test_timeout_stops_cleanly`, `test_packet_limit` |
| Malformed / truncated / corrupt packets | Per-packet decode in try/except (counted and skipped); a corrupt record header stops the read cleanly; oversized records are rejected | `loader.read_capture` | `test_fuzzed_captures_never_crash` (60 mutated files), `test_truncated_capture_is_handled` |
| State-table flooding (millions of fake hosts/flows) | Every table is an LRU dict with a hard cap; per-flow and per-host sub-tables are capped too | `state/lru.py`, `state/*` | `test_address_flood_respects_memory_caps` |
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
| Sharing reports leaks addresses | `--anonymize`: IPs/MACs replaced by HMAC-SHA256 pseudonyms with a random per-run key (consistent within a report, not reversible, not linkable across reports) | `report/anonymize.py` | `test_anonymize_removes_addresses`, `test_upload_anonymized` |
| Sensitive payloads (passwords, cookies) | Only header fields are kept; payload bytes are never stored, shown or exported | `models.PacketRecord`, decoder | by design |
| Hard-coded secrets | None exist; `.gitignore` excludes `.env`, keys and stray captures; repository scanned by a test | `.gitignore` | `test_no_secrets_committed` |
| Vulnerable dependencies | Versions pinned in `requirements.txt`; audited with `pip-audit`, no known vulnerabilities at submission time | `requirements.txt` | `pip-audit -r requirements.txt` |

## Reporting a problem

Please open an issue on the repository.
