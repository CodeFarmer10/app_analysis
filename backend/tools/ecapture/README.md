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
