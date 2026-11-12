# Android eCapture Runtime

The default collector uses the bundled Android arm64 v1.5.2 executable:

`ecapture-v1.5.2-android-arm64/ecapture`

SHA-256: `0f74a252344365fbf200f9fcd347061438bfa8bbae35810432d78620896fbae4`

Upstream project: <https://github.com/gojue/ecapture>

The upstream Apache-2.0 license is included alongside the executable.

The collector requires a rooted Android device with BPF capabilities. The
default template is `boringssl_a_15`; template compatibility affects TLS
decryption coverage. PCAPNG artifacts may contain only partially decrypted
connections. Network-library Hooks collect independent HTTPS observations.

Override `ECAPTURE_BINARY_PATH` and `ECAPTURE_SSL_VERSION` when using another
validated runtime or device template. Development archives and alternative
binaries in this directory are not part of the default runtime.

Before HTTP parsing, the application validates PCAPNG block boundaries and
prepares a private temporary copy with each section's embedded Decryption
Secrets Blocks before its packet data. This avoids missing sessions whose
secrets were appended after the TLS records; `tshark -2` alone is insufficient
for some captures. The original MinIO artifact stays unchanged and no external
keylog file is required. Temporary copies are removed after parsing, failure,
or cancellation. Classic PCAP and captures without secrets use the original
path. Missing or incompatible secrets still require collector investigation.

Run parser regression tests from `backend`:

```sh
.venv/bin/python -m unittest discover -s tests -p 'test_pcapng_secrets.py'
.venv/bin/python -m unittest discover -s tests -p 'test_ecapture_integration.py'
node --test tests/frida_http_hooks.test.cjs
```

The Java HTTP adapters record URL observations before response/body processing.
Response previews copy only bytes already present in the Okio buffer (at most
64 KiB); they never call `peekBody`, request upstream data or consume the original
stream. An empty buffer keeps the observation partial instead of blocking.
Static resources and known streaming responses (SSE/gRPC) keep metadata without
reading body previews. Small built-in OkHttp byte-array request bodies can be
read without replay; custom, one-shot, duplex, oversized or unknown bodies stay
partial. Factory hooks only discover concrete objects and carry configuration;
they no longer emit HTTP records for construction alone. Requests are observed
at public execution APIs and response callbacks. Internal `Response.Builder.build`
is not hooked. An execution attempt is not proof of a completed network transfer;
`parse_status` and `hook_method` distinguish partial observations.

Network hook installation retries for a bounded startup window and discovers
class loaders and concrete connection/client implementations. Diagnostic
messages distinguish Java initialization pending/timeout from installed hooks.
Classes loaded after that window, obfuscated adapters and other processes still
require separate verification. Generic rule events retain the existing switch.
