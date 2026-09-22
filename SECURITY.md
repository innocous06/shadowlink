# Security Policy

## Threat Model
ShadowLink is designed to protect your internet traffic against:
- **Deep Packet Inspection (DPI)**: Traffic is camouflaged as standard TLS 1.3 HTTPS.
- **Passive Monitoring**: Full ChaCha20-Poly1305 AEAD encryption secures the payload.
- **Active Probing**: Unauthorized connections (without the correct client private key) are served a decoy HTML website, preventing active scanners from identifying the proxy.

### What it does NOT protect against:
- Endpoint compromise (malware on your PC/phone).
- Metadata timing analysis (advanced adversaries analyzing packet arrival times).
- Legal risks of accessing censored content.

## Key Rotation Procedure
1. Run `shadowlink-keygen client` to generate a new keypair.
2. Replace the old client key file on your device.
3. Update the server's `/etc/shadowlink/config.toml` with the new public key.
4. Restart the server service: `systemctl restart shadowlink`.

## Vulnerability Reporting
Please report any security vulnerabilities by opening a private security advisory on GitHub or emailing the maintainer.
