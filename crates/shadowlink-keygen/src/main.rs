//! # ShadowLink Key Generator
//!
//! Generates server and client keypairs for ShadowLink.
//!
//! ## Usage:
//! ```
//! shadowlink-keygen server    # Generate server keypair
//! shadowlink-keygen client    # Generate client keypair
//! shadowlink-keygen both      # Generate both (recommended for first setup)
//! ```
//!
//! Keys are encrypted with a passphrase before saving to disk.

use anyhow::{Context, Result};
use shadowlink_core::crypto::keys::{EncryptedKeyFile, KeyPair};
use std::io::Write;
use std::path::Path;

fn main() -> Result<()> {
    let mode = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "both".to_string());

    println!("╔══════════════════════════════════════════╗");
    println!("║    ShadowLink — Key Generator            ║");
    println!("╚══════════════════════════════════════════╝");
    println!();

    match mode.as_str() {
        "server" => generate_keypair("server")?,
        "client" => generate_keypair("client")?,
        "both" => {
            generate_keypair("server")?;
            println!();
            println!("────────────────────────────────────────────");
            println!();
            generate_keypair("client")?;

            println!();
            println!("════════════════════════════════════════════");
            println!("  SETUP INSTRUCTIONS:");
            println!("════════════════════════════════════════════");
            println!();
            println!("  1. Copy 'server.key.json' to your VPS at:");
            println!("     /etc/shadowlink/server.key.json");
            println!();
            println!("  2. Add the CLIENT public key to your server's");
            println!("     config.toml under 'allowed_clients'");
            println!();
            println!("  3. Add the SERVER public key to your client's");
            println!("     client-config.toml under 'server_public_key'");
            println!();
            println!("  4. Keep your passphrases SAFE — you need them");
            println!("     every time the server/client starts");
            println!();
        }
        _ => {
            eprintln!("Usage: shadowlink-keygen [server|client|both]");
            eprintln!("  server  — Generate server keypair only");
            eprintln!("  client  — Generate client keypair only");
            eprintln!("  both    — Generate both (recommended)");
            std::process::exit(1);
        }
    }

    Ok(())
}

fn generate_keypair(role: &str) -> Result<()> {
    println!("  Generating {} keypair...", role.to_uppercase());

    // Generate the keypair
    let keypair = KeyPair::generate();
    let public_key_b64 = keypair.public_key_base64();

    println!("  ✓ Keypair generated");
    println!();
    println!("  {} PUBLIC KEY (share this):", role.to_uppercase());
    println!("  {}", public_key_b64);
    println!();

    // Get passphrase
    let passphrase = get_passphrase(role)?;

    // Encrypt and save
    let filename = format!("{}.key.json", role);
    let encrypted = keypair
        .export_encrypted(passphrase.as_bytes())
        .context("Failed to encrypt keypair")?;

    encrypted
        .save_to_file(Path::new(&filename))
        .context("Failed to save key file")?;

    println!("  ✓ Encrypted key saved to: {}", filename);
    println!("  ✓ This file is safe to store — it's encrypted with your passphrase");

    Ok(())
}

fn get_passphrase(role: &str) -> Result<String> {
    eprint!("  Enter passphrase for {} key: ", role);
    std::io::stderr().flush()?;
    let mut pass1 = String::new();
    std::io::stdin().read_line(&mut pass1)?;
    let pass1 = pass1.trim().to_string();

    if pass1.is_empty() {
        return Err(anyhow::anyhow!("Passphrase cannot be empty"));
    }

    if pass1.len() < 8 {
        eprintln!("  ⚠ WARNING: Passphrase is very short. Use at least 8 characters.");
    }

    eprint!("  Confirm passphrase: ");
    std::io::stderr().flush()?;
    let mut pass2 = String::new();
    std::io::stdin().read_line(&mut pass2)?;
    let pass2 = pass2.trim().to_string();

    if pass1 != pass2 {
        return Err(anyhow::anyhow!("Passphrases do not match"));
    }

    Ok(pass1)
}
