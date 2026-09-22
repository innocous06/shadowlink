# shadowlink

[![Status: Active Prototype](https://img.shields.io/badge/STATUS-BETA_PROTOTYPE-c9654a?style=for-the-badge)](https://github.com/innocous06/shadowlink)
[![Language: Rust](https://img.shields.io/badge/LANGUAGE-RUST_2021-18181f?style=for-the-badge)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/LICENSE-MIT-18181f?style=for-the-badge)](LICENSE)

> [!IMPORTANT]
> **Active Research & Development (Beta)**
> shadowlink is an ongoing systems engineering project. Cryptographic primitives, framing formats, and crate interfaces are actively being refined and tested.

A high-performance, memory-safe TLS tunneling and censorship-resistant networking utility engineered in Rust. Designed as a modular workspace providing encrypted proxies, point-to-point VPN tunnels, and Android integration.

## Overview

shadowlink delivers low-overhead, secure packet encapsulation using modern cryptographic primitives. It features automated key management, active probe resistance, TLS 1.3 traffic camouflage, and cross-platform network drivers.

The project supports both local SOCKS5 proxying (with full RFC 1928 TCP Connect and UDP Associate handling) and full VPN routing on Windows via the kernel Wintun driver.

## Runtime Output

### Key Generation

```
$ shadowlink-keygen both
==========================================
       ShadowLink - Key Generator
==========================================

Generating server keypair (Curve25519)...
Enter passphrase for server.key.json: 
Confirm passphrase: 
Server public key: 9hD8K3+uQ1F0aBCvVw7sP2mK5jL8nB7yX1tZ0eW3rQ4=
Saved encrypted server key to server.key.json

Generating client keypair (Curve25519)...
Enter passphrase for client.key.json: 
Confirm passphrase: 
Client public key: 2mK5jL8nB7yX1tZ0eW3rQ49hD8K3+uQ1F0aBCvVw7sP=
Saved encrypted client key to client.key.json
```

### Client Startup

```
$ shadowlink-client client-config.toml
==========================================
      ShadowLink - Secure Tunnel
==========================================

Key passphrase: 
2026-09-22T15:30:10Z  INFO shadowlink: Client public key: 2mK5jL8nB7yX1tZ0eW3rQ49hD8K3+uQ1F0aBCvVw7sP=
2026-09-22T15:30:10Z  INFO shadowlink: Connecting to profile 'OCI Mumbai' at 152.67.x.x:443 (SNI: www.microsoft.com)...
2026-09-22T15:30:10Z  INFO shadowlink: Handshake verified, session established
2026-09-22T15:30:10Z  INFO shadowlink: SOCKS5 proxy listening on 127.0.0.1:1080
2026-09-22T15:30:12Z DEBUG shadowlink: SOCKS5 CONNECT stream 1 -> 1.1.1.1:443
2026-09-22T15:30:14Z DEBUG shadowlink: SOCKS5 UDP ASSOCIATE stream 2 bound on 127.0.0.1:54321
```

## Architecture & Pipeline

```
Client Application (Browser, Discord, Games)
  │
  ├─► SOCKS5 Proxy (127.0.0.1:1080)   [TCP Connect / UDP Associate]
  │   or
  └─► Windows Wintun Adapter          [0.0.0.0/1, 128.0.0.0/1]
        │
        ▼
  Stream Multiplexer (32-bit Stream ID)
        │
        ▼
  Padding & Framing (64-byte boundary padding + Poisson dummy frames)
        │
        ▼
  ChaCha20-Poly1305 AEAD Encryption (BLAKE3 in-band rekeying every 500k frames)
        │
        ▼
  TLS 1.3 Transport (SNI Camouflage)
        │
     [Network]
        │
        ▼
  ShadowLink Server (Port 443)
        │
        ├─► [Unauthenticated] ──► Fallback Web Server (127.0.0.1:80)
        │
        └─► [Authenticated]
                 │
                 ▼
            Token-Bucket QoS Rate Limiter
                 │
                 ▼
            Demultiplexer ──► Outbound TCP / UDP Relay ──► Internet
```

## Features

- **Traffic Obfuscation**: Camouflaged as standard TLS 1.3 traffic using configurable SNI hostnames (e.g., Microsoft or Google).
- **Packet Padding**: Dynamic PKCS#7 padding to 64-byte boundaries on sensitive frames to prevent size-distribution fingerprinting.
- **Idle Jitter**: Background injection of randomized dummy frames (`FRAME_TYPE_DUMMY`) at 10 to 25 second intervals to disrupt idle timing analysis.
- **Probe Defense**: Unauthenticated connections are proxied to a local web server (Nginx/Caddy) or returned a static HTTP 200 decoy page.
- **SOCKS5 Proxy**: Implements standard SOCKS5 with both `CMD_CONNECT` (TCP) and `CMD_UDP_ASSOCIATE` (RFC 1928 UDP relay).
- **Full VPN Mode**: Native Windows virtual adapter support using the Wintun driver (`wintun.dll`), with split tunneling and LAN bypass (RFC 1918).
- **Cryptography**: Ephemeral X25519 key exchange, HMAC-SHA256 handshake authentication, ChaCha20-Poly1305 AEAD, zeroized memory keys, and in-band BLAKE3 key ratcheting.
- **Multi-Server Failover**: Client configuration supports multiple server profiles with automatic 3-strike failover.
- **Bandwidth Shaping**: Server-side token-bucket rate limiter for per-client bandwidth control.
- **Desktop GUI**: Standalone `egui`/`eframe` interface with real-time ping latency probing, throughput monitoring, and mode switching.
- **Android Support**: Android client implementation utilizing `VpnService` with a Jetpack Compose interface.

## Architecture & Crates

The project is structured as a unified Cargo workspace:

- `shadowlink-core`: Core protocol framing, session state machine, cryptography, and TUN/SOCKS5 network drivers.
- `shadowlink-client`: Desktop client managing route tables, failover loop, and encrypted tunnel connections.
- `shadowlink-server`: High-concurrency async daemon powered by Tokio, QoS rate limiting, and web fallback.
- `shadowlink-gui`: Native desktop GUI (egui/eframe) with latency probing and speed monitoring.
- `shadowlink-keygen`: Cryptographic token and Argon2id passphrase key derivation utility.
- `certgen`: Standalone X.509 TLS certificate and private key generator.
- `shadowlink-android`: Android client implementation with Rust JNI/FFI bindings and Jetpack Compose UI.

## Tech Stack

- **Language:** Rust (2021 Edition)
- **Async Runtime:** Tokio, Bytes
- **Cryptography:** x25519-dalek, ChaCha20-Poly1305, BLAKE3, Argon2, Rustls, zeroize
- **Networking:** Linux TUN, Wintun FFI, SOCKS5 Proxy (RFC 1928), Custom DNS Resolver
- **Desktop UI:** eframe, egui
- **Mobile Integration:** Android NDK, JNI, Kotlin, Jetpack Compose

## Supported Target Architectures

- `x86_64-unknown-linux-gnu` (Linux Servers / OCI VPS)
- `x86_64-pc-windows-msvc` (Windows Desktop via Wintun)
- `aarch64-linux-android` (Android via JNI & `libshadowlink_core.so`)

## Quick Start

### 1. Key Generation

```bash
cargo run --release -p shadowlink-keygen -- both
```

This creates `server.key.json` and `client.key.json`, and outputs the respective public keys.

### 2. Server Setup

Create `server-config.toml`:

```toml
listen_addr = "0.0.0.0:443"
tls_cert_path = "/etc/shadowlink/cert.pem"
tls_key_path = "/etc/shadowlink/key.pem"
server_key_path = "server.key.json"
allowed_clients = ["<CLIENT_PUBLIC_KEY_BASE64>"]
enable_logging = true

# Optional: bandwidth limit in Mbps
# client_rate_limit_mbps = 100.0

# Optional: redirect probe traffic to local web server
# fallback_addr = "127.0.0.1:80"
```

Start the server:
```bash
cargo build --release -p shadowlink-server
./target/release/shadowlink-server server-config.toml
```

### 3. Client Setup

Create `client-config.toml`:

```toml
server_addr = "YOUR_SERVER_IP:443"
sni_hostname = "www.microsoft.com"
socks5_listen = "127.0.0.1:1080"
client_key_path = "client.key.json"
server_public_key = "<SERVER_PUBLIC_KEY_BASE64>"
verify_tls_cert = true
auto_reconnect = true
enable_full_vpn_mode = false
bypass_lan = true

# Additional server endpoints for automatic failover (optional)
[[servers]]
name = "Primary"
server_addr = "198.51.100.1:443"
sni_hostname = "www.microsoft.com"
server_public_key = "<SERVER_PUBKEY_1>"

[[servers]]
name = "Secondary"
server_addr = "203.0.113.2:443"
sni_hostname = "www.google.com"
server_public_key = "<SERVER_PUBKEY_2>"
```

Start the CLI client:
```bash
cargo run --release -p shadowlink-client -- client-config.toml
```

Or launch the desktop GUI:
```bash
cargo run --release -p shadowlink-gui
```

## Testing

```bash
# Run unit and integration tests across the workspace
cargo test --workspace

# Run strict clippy checks
cargo clippy --workspace -- -D warnings
```

## License

Released under the [MIT License](LICENSE).

Copyright (c) 2026 innocous06. All rights reserved.