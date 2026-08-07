# shadowlink

[![Status: Active Prototype](https://img.shields.io/badge/STATUS-BETA_PROTOTYPE-c9654a?style=for-the-badge)](https://github.com/innocous06/shadowlink)
[![Language: Rust](https://img.shields.io/badge/LANGUAGE-RUST_2021-18181f?style=for-the-badge)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/LICENSE-MIT-18181f?style=for-the-badge)](LICENSE)

> [!IMPORTANT]
> **Active Research & Development (Beta)**
> shadowlink is an ongoing systems engineering project. Cryptographic primitives, framing formats, and crate interfaces are actively being refined and tested.

A high-performance, memory-safe TLS tunneling and censorship-resistant networking utility engineered in Rust. Designed as a modular workspace providing encrypted proxies, point-to-point VPN tunnels, and Android integration.

## Overview

shadowlink delivers low-overhead, secure packet encapsulation using modern cryptographic primitives. It features automated certificate generation, active probe resistance, TLS traffic camouflage, and cross-platform network drivers.

## Architecture & Crates

The project is structured as a unified Cargo workspace:

- shadowlink-core: Core protocol framing, session state machine, cryptography, and TUN/SOCKS5 network drivers.
- shadowlink-server: High-concurrency async daemon powered by Tokio and Rustls.
- shadowlink-client: Desktop client managing route tables and encrypted tunnel connections.
- shadowlink-keygen: Cryptographic token and key management utility.
- certgen: Standalone X.509 TLS certificate and private key generator.
- shadowlink-android: Android client implementation with Rust JNI/FFI bindings and Jetpack Compose UI.

## Tech Stack

- **Language:** Rust (2021 Edition)
- **Async Runtime:** Tokio, Bytes
- **Cryptography:** x25519-dalek, ChaCha20-Poly1305, BLAKE2, Argon2, Rustls
- **Networking:** Linux TUN, Wintun FFI, SOCKS5 Proxy, Custom DNS Resolver
- **Mobile Integration:** Android NDK, JNI, Kotlin, Jetpack Compose

## Usage

`ash
# Build the workspace in release mode
cargo build --release

# Generate TLS certificates
cargo run --bin certgen

# Run server
cargo run --bin shadowlink-server -- -c server-config.toml

# Run client
cargo run --bin shadowlink-client -- -c client-config.toml
`

## License

Released under the [MIT License](LICENSE).

Copyright (c) 2026 innocous06. All rights reserved.\n