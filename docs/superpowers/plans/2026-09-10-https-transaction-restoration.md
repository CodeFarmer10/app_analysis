# HTTPS Transaction Restoration Implementation Plan

**Goal:** Restore HTTPS URLs, request bodies, and response bodies as HTTP transactions by running eCapture pcapng capture and network-library Frida hooks in parallel.

**Architecture (updated 2026-11-10):** eCapture v1.5.2 pcapng is the default packet source. Tshark decodes embedded TLS secrets and emits packet metadata; the backend correlates HTTP/1 request/response frame references and HTTP/2 TCP/stream IDs within the packet source. eCapture and Frida network hooks remain independent: HTTPS packet transactions go to `ecapture_logs`, and HTTPS Hook events go to `frida_http_logs`. There is no cross-source matching or field supplementation. Both tables retain `event_time` as `DATETIME(6)`; collector event timestamps are normalized to Unix seconds before mapping independently to operation windows `[start_time, next_start_time)`. The pcapng artifact continues to upload to MinIO.

**Constraints:** Do not implement mitmproxy, PCAPdroid, text/hex fallback, or report display. Per-operation HTTPS URL display is enabled by the updated requirements. Do not add `pid`, `raw_event_json`, `capture_file_path`, or `body_sha256`.

**Controller inference and display (updated 2026-11-11):** Remove IP scoring and IP-based fallback inference. For each operation, combine the eCapture and Frida HTTPS URLs and deduplicate exact full URL strings after trimming whitespace. Preserve path, query parameters, and URL-embedded ports. Send this URL-only list to the model as `https_urls`, without collector IP/port/time metadata. Candidates include non-whitelist domains and direct-IP HTTPS endpoints as `IP:port` or `[IPv6]:port` (default port 443); bare IPs in ordinary traffic do not generate candidates. Retain the `candidate_domains`/`c2_domains`/`domain` field names for compatibility, allowing endpoint identifiers as values. Tag direct-IP HTTPS URL rows only when their endpoint matches the selected candidate, keeping different ports separate. Reuse the same URL projection in the dynamic-result API as `step_https_urls` and show it in each operation's expansion alongside the traffic table. Collector rows and timestamps remain independently stored for operation mapping.

## Task 1: Transaction parser

- [x] Add failing tests for HTTP/1 request-response correlation, HTTP/2 stream correlation, body decoding, and partial transactions.
- [x] Replace frame-oriented tshark output with EK JSON packet output.
- [x] Build one transaction per HTTP request while retaining request-direction IP/port data.
- [x] Preserve incomplete captures with an explicit partial status.

## Task 2: Parallel network hooks

- [x] Add tests for independent Frida HTTPS collection and operation mapping.
- [x] Add bounded OkHttp request/response extraction to the Frida agent.
- [x] Keep hook transactions separate from generic Frida events at collection time.
- [x] Keep matching URLs from different collectors as separate records, without copying fields.
- [x] Assign a stable ID to each Frida HTTP transaction for independent persistence.
- [x] Use OkHttp 3/4 as the single underlying HTTP adapter; Retrofit traffic is covered through its default OkHttp call factory.
- [x] Skip response-body reads for static resources and coalesce identical OkHttp events within a short window.
- [x] Keep one `NETWORK_HOOK_ENABLED` master switch for both generic Frida rules and HTTP network hooks.
- [x] Remove the legacy HTTP/WebView rules from the generic rule file while retaining the generic-rule event mechanism for future non-HTTP rules.

## Task 3: Capture lifecycle and defaults

- [x] Add failing tests proving capture starts before APP execution and spawn resume.
- [x] Make eCapture enabled by default with the v1.5.2 binary and Android 15 BoringSSL template.
- [x] Start packet capture before launching or resuming the APP.
- [x] Enable the network hook by default and keep failures fail-open.

## Task 4: Persistence

- [x] Add failing persistence tests for transaction columns.
- [x] Evolve `ecapture_logs` with request/response fields, source, completeness, and timestamps.
- [x] Persist Hook transactions in `frida_http_logs` even when IP/port data is unavailable.
- [x] Persist only eCapture transactions in `ecapture_logs` and remove merge markers from new writes.
- [x] Filter both sources for HTTPS before mapping and again at the storage boundary. HTTP/2 or port 443 alone does not establish HTTPS.
- [x] Preserve collector event time separately from database insertion time; do not substitute `created_at`.
- [x] Keep the existing pcapng MinIO upload path unchanged.

## Task 5: Verification

- [x] Rebuild the Frida bundle.
- [x] Run focused unit tests and the dynamic tracing regression suite.
- [x] Parse the known v1.5.2 capture and inspect representative HTTP/1 and HTTP/2 rows.
- [x] Run repository status and diff checks without modifying unrelated files.
