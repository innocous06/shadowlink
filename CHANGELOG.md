# SHADOWLINK Technical Architecture & Changelog

- [2026-06-17 18:06] feat: initialize Rust workspace with Tokio async network runtime
- [2026-06-22 16:28] feat: implement ChaCha20-Poly1305 AEAD authenticated encryption pipeline
- [2026-06-27 17:55] feat: add TCP/UDP tunnel session multiplexer over TLS connection
- [2026-07-01 19:41] refactor: optimize packet framing with zero-copy byte slice buffers
- [2026-07-06 17:22] feat: add certgen utility for generating self-signed mTLS certificates
- [2026-07-10 13:49] feat: implement Android JNI FFI bindings for native VPN service
- [2026-07-15 11:38] perf: replace mutex locks with atomic connection metrics counters
- [2026-07-20 18:24] fix: handle unexpected broken pipe on mobile network handover
