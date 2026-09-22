# Changelog

## [2.0.0] - 2026-09-22

### Fixed
- Windows full VPN mode: interface alias mismatch (ShadowLinkTUN vs ShadowLink)
- Multi-client TUN routing: replaced single-client pointer with per-IP routing table
- Nonce replay protection: sliding window replaces strict sequential check
- Session close: clean close frame sent before disconnect
- SOCKS5 + TUN double encapsulation: modes are now mutually exclusive
- Connection timeout: 15-second timeout on TLS + handshake
- TLS cert verification: now enabled by default

### Changed
- Passphrase no longer stored in config file (interactive prompt or env var)
- Default TLS cert verification: true (was false)
- Frame max size: 65535 (was 16384)

### Added
- Exponential backoff reconnection
- Session keepalive (25s default interval)
- Kill switch (Windows + Android)
- Traffic statistics (bytes/sec rolling average)
- Multi-server profile support in config
- Windows GUI (egui-based)
- Structured file logging
- Decoy HTML page for probe resistance
- Split tunneling (bypass CIDRs)
- Session key rotation trigger (1M frames)
- Packet padding wired into send path
- CI/CD pipeline (GitHub Actions)
- Android: Complete UI (Connect/Disconnect, Settings, Server list)
- Android: VPN permission flow
- Systemd service with security hardening
- Test suite (unit + integration)

## [1.0.0] - 2026-07-01

Initial release (prototype).
