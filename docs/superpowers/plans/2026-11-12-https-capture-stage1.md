# HTTPS Capture Stage 1 Implementation Plan

User approved implementation of priority 1 from the coverage analysis. Work in the existing HTTPS feature checkout and preserve unrelated pending edits.

**Goal:** Recover URLs hidden by late PCAPNG secrets and strengthen the existing Java network adapters without adding collectors or switches.

**Design:** PCAPNG files remain self-contained. Build a private temporary normalized copy per parse, move each section's DSB blocks before its packet data, and preserve all other blocks byte-for-byte. Validate lengths/endian/section boundaries; never combine secrets across sections or modify the original. Stream copies to bound memory, keep temporary paths private, clean up on success/failure/cancellation. Plain PCAP and files without secrets keep existing behavior.

Java adapters emit request metadata independently of body extraction; callbacks must always preserve original APP behavior. Response preview reads a bounded copy. Skip one-shot/duplex/unknown/large request bodies and static resource bodies. Expand existing adapters with concrete class handling and bounded, idempotent delayed installation. Keep generic rules and the single existing Frida switch.

**Constraints:** Existing HTTPS-only filtering, independent ecapture_logs/frida_http_logs, event timestamps and operation mapping remain. No libcurl, Native TLS, Flutter, schema, frontend, report rendering or production deployment in this change.

## Tasks

- [x] DSB: write failing binary-fixture tests for late secrets, multiple sections, both endian formats, unchanged packet data, corrupt/truncated inputs, plain PCAP, cleanup; implement section-local normalization and parser integration.
- [x] Java: executable regression tests for metadata surviving body failures, response extraction, streaming body safety, request observation and concrete/delayed adapters; implement and rebuild bundle. Response previews copy only already-buffered bytes rather than calling peekBody, following review evidence of possible upstream blocking.
- [x] Verify known real captures, existing Python integration tests, Java behavior tests, relevant broader checks. Review complete diff and preserve unrelated files.

## Validation / review focus

Multi-section secrets must not leak across sections; large captures must not be loaded into memory; malformed length fields must fail before tshark starts; temporary files must be removed even if the consumer stops; Java instrumentation must not alter return values/throw new errors/consume original response streams.

Progress and validation evidence are recorded in the final stage 1 report.
