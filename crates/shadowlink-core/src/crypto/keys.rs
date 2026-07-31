//! # ShadowLink Key Management
//!
//! Handles generation, storage, and exchange of cryptographic keys.
//! 
//! ## Security Properties:
//! - Keys are generated using OS CSPRNG (via `rand::rngs::OsRng`)
//! - Private keys are encrypted on disk with Argon2id + XChaCha20-Poly1305
//! - All key material is zeroized from memory when dropped
//! - No plaintext private key ever touches persistent storage

use anyhow::{anyhow, Context, Result};
use argon2::{Argon2, Algorithm, Version, Params};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng as AeadOsRng},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Size of the salt for Argon2id key derivation
const ARGON2_SALT_LEN: usize = 32;
/// Size of the nonce for XChaCha20-Poly1305
const XCHACHA_NONCE_LEN: usize = 24;
/// Argon2id memory cost (64 MiB) — resistant to GPU/ASIC attacks
const ARGON2_MEM_COST: u32 = 65536;
/// Argon2id time cost (3 iterations)
const ARGON2_TIME_COST: u32 = 3;
/// Argon2id parallelism
const ARGON2_PARALLELISM: u32 = 4;

/// A keypair consisting of a private (static secret) and public key.
/// Private key is automatically zeroized from memory when this struct is dropped.
#[derive(ZeroizeOnDrop)]
pub struct KeyPair {
    /// The Curve25519 static secret (private key)
    #[zeroize(skip)] // x25519-dalek handles its own zeroization
    secret: StaticSecret,
    /// The corresponding public key
    #[zeroize(skip)]
    public: PublicKey,
}

impl KeyPair {
    /// Generate a new random keypair using the OS cryptographic random number generator.
    /// This is the ONLY way to create keys — no user-supplied randomness.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Get the public key bytes (safe to share)
    pub fn public_key_bytes(&self) -> [u8; 32] {
        *self.public.as_bytes()
    }

    /// Get the public key as a base64 string (for config files and sharing)
    pub fn public_key_base64(&self) -> String {
        BASE64.encode(self.public.as_bytes())
    }

    /// Get a reference to the static secret (for Diffie-Hellman operations)
    pub fn secret(&self) -> &StaticSecret {
        &self.secret
    }

    /// Get a reference to the public key
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// Perform Diffie-Hellman key exchange with a peer's public key.
    /// Returns the shared secret (32 bytes).
    pub fn diffie_hellman(&self, peer_public: &PublicKey) -> [u8; 32] {
        *self.secret.diffie_hellman(peer_public).as_bytes()
    }

    /// Export the keypair to an encrypted file.
    /// The private key is encrypted using a passphrase via Argon2id + XChaCha20-Poly1305.
    pub fn export_encrypted(&self, passphrase: &[u8]) -> Result<EncryptedKeyFile> {
        // Generate a random salt for Argon2id
        let mut salt = [0u8; ARGON2_SALT_LEN];
        rand::rngs::OsRng.fill_bytes(&mut salt);

        // Derive encryption key from passphrase using Argon2id
        let mut derived_key = [0u8; 32];
        let params = Params::new(ARGON2_MEM_COST, ARGON2_TIME_COST, ARGON2_PARALLELISM, Some(32))
            .map_err(|e| anyhow!("Argon2 params error: {}", e))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        argon2
            .hash_password_into(passphrase, &salt, &mut derived_key)
            .map_err(|e| anyhow!("Argon2 hash error: {}", e))?;

        // Encrypt the private key with XChaCha20-Poly1305
        let mut nonce_bytes = [0u8; XCHACHA_NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        let cipher = XChaCha20Poly1305::new_from_slice(&derived_key)
            .map_err(|e| anyhow!("Cipher init error: {}", e))?;

        // Get raw secret key bytes
        let secret_bytes = self.secret.to_bytes();
        let encrypted_secret = cipher
            .encrypt(nonce, secret_bytes.as_ref())
            .map_err(|e| anyhow!("Encryption error: {}", e))?;

        // Zeroize the derived key
        derived_key.zeroize();

        Ok(EncryptedKeyFile {
            version: 1,
            public_key: BASE64.encode(self.public.as_bytes()),
            encrypted_secret: BASE64.encode(&encrypted_secret),
            salt: BASE64.encode(&salt),
            nonce: BASE64.encode(&nonce_bytes),
            argon2_mem_cost: ARGON2_MEM_COST,
            argon2_time_cost: ARGON2_TIME_COST,
            argon2_parallelism: ARGON2_PARALLELISM,
        })
    }

    /// Import a keypair from an encrypted key file using a passphrase.
    pub fn import_encrypted(file: &EncryptedKeyFile, passphrase: &[u8]) -> Result<Self> {
        if file.version != 1 {
            return Err(anyhow!("Unsupported key file version: {}", file.version));
        }

        let salt = BASE64
            .decode(&file.salt)
            .context("Invalid salt encoding")?;
        let nonce_bytes = BASE64
            .decode(&file.nonce)
            .context("Invalid nonce encoding")?;
        let encrypted_secret = BASE64
            .decode(&file.encrypted_secret)
            .context("Invalid encrypted secret encoding")?;

        // Derive key from passphrase
        let mut derived_key = [0u8; 32];
        let params = Params::new(
            file.argon2_mem_cost,
            file.argon2_time_cost,
            file.argon2_parallelism,
            Some(32),
        )
        .map_err(|e| anyhow!("Argon2 params error: {}", e))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        argon2
            .hash_password_into(passphrase, &salt, &mut derived_key)
            .map_err(|e| anyhow!("Argon2 hash error: {}", e))?;

        // Decrypt
        let nonce = XNonce::from_slice(&nonce_bytes);
        let cipher = XChaCha20Poly1305::new_from_slice(&derived_key)
            .map_err(|e| anyhow!("Cipher init error: {}", e))?;

        let mut secret_bytes = cipher
            .decrypt(nonce, encrypted_secret.as_ref())
            .map_err(|_| anyhow!("Decryption failed — wrong passphrase or corrupted file"))?;

        derived_key.zeroize();

        // Reconstruct keypair
        let mut key_array = [0u8; 32];
        if secret_bytes.len() != 32 {
            secret_bytes.zeroize();
            return Err(anyhow!("Invalid secret key length"));
        }
        key_array.copy_from_slice(&secret_bytes);
        secret_bytes.zeroize();

        let secret = StaticSecret::from(key_array);
        key_array.zeroize();

        let public = PublicKey::from(&secret);

        // Verify public key matches
        let expected_public = BASE64
            .decode(&file.public_key)
            .context("Invalid public key encoding")?;
        if public.as_bytes() != expected_public.as_slice() {
            return Err(anyhow!(
                "Public key mismatch — file may be corrupted"
            ));
        }

        Ok(Self { secret, public })
    }

    /// Create a keypair from raw 32-byte secret key bytes.
    /// Used internally for key exchange results.
    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Parse a public key from base64 string.
    pub fn parse_public_key(b64: &str) -> Result<PublicKey> {
        let bytes = BASE64
            .decode(b64)
            .context("Invalid base64 public key")?;
        if bytes.len() != 32 {
            return Err(anyhow!("Public key must be 32 bytes, got {}", bytes.len()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(PublicKey::from(arr))
    }
}

/// Encrypted key file format — safe to store on disk.
/// Contains the encrypted private key and all parameters needed to decrypt it.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EncryptedKeyFile {
    /// File format version (currently 1)
    pub version: u32,
    /// Public key (base64) — not encrypted, safe to share
    pub public_key: String,
    /// Encrypted private key (base64)
    pub encrypted_secret: String,
    /// Argon2id salt (base64)
    pub salt: String,
    /// XChaCha20-Poly1305 nonce (base64)
    pub nonce: String,
    /// Argon2id memory cost parameter
    pub argon2_mem_cost: u32,
    /// Argon2id time cost parameter
    pub argon2_time_cost: u32,
    /// Argon2id parallelism parameter
    pub argon2_parallelism: u32,
}

impl EncryptedKeyFile {
    /// Save encrypted key file to disk as JSON
    pub fn save_to_file(&self, path: &std::path::Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)
            .context("Failed to serialize key file")?;
        std::fs::write(path, json)
            .context("Failed to write key file")?;
        Ok(())
    }

    /// Load encrypted key file from disk
    pub fn load_from_file(path: &std::path::Path) -> Result<Self> {
        let json = std::fs::read_to_string(path)
            .context("Failed to read key file")?;
        let file: Self = serde_json::from_str(&json)
            .context("Failed to parse key file")?;
        Ok(file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let kp = KeyPair::generate();
        let pub_bytes = kp.public_key_bytes();
        // Public key should not be all zeros
        assert_ne!(pub_bytes, [0u8; 32]);
    }

    #[test]
    fn test_diffie_hellman() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();

        let shared_alice = alice.diffie_hellman(bob.public_key());
        let shared_bob = bob.diffie_hellman(alice.public_key());

        // Both sides should derive the same shared secret
        assert_eq!(shared_alice, shared_bob);
    }

    #[test]
    fn test_encrypt_decrypt_keypair() {
        let original = KeyPair::generate();
        let passphrase = b"test-passphrase-strong-123!@#";

        // Export encrypted
        let encrypted = original.export_encrypted(passphrase).unwrap();

        // Import back
        let recovered = KeyPair::import_encrypted(&encrypted, passphrase).unwrap();

        // Keys should match
        assert_eq!(
            original.public_key_bytes(),
            recovered.public_key_bytes()
        );

        // DH should produce same results
        let peer = KeyPair::generate();
        let dh1 = original.diffie_hellman(peer.public_key());
        let dh2 = recovered.diffie_hellman(peer.public_key());
        assert_eq!(dh1, dh2);
    }

    #[test]
    fn test_wrong_passphrase_fails() {
        let kp = KeyPair::generate();
        let encrypted = kp.export_encrypted(b"correct-password").unwrap();
        let result = KeyPair::import_encrypted(&encrypted, b"wrong-password");
        assert!(result.is_err());
    }

    #[test]
    fn test_public_key_base64_roundtrip() {
        let kp = KeyPair::generate();
        let b64 = kp.public_key_base64();
        let parsed = KeyPair::parse_public_key(&b64).unwrap();
        assert_eq!(kp.public_key_bytes(), *parsed.as_bytes());
    }

    #[test]
    fn test_encrypted_keyfile_serialization() {
        let kp = KeyPair::generate();
        let encrypted = kp.export_encrypted(b"test").unwrap();
        let json = serde_json::to_string(&encrypted).unwrap();
        let deserialized: EncryptedKeyFile = serde_json::from_str(&json).unwrap();
        assert_eq!(encrypted.public_key, deserialized.public_key);
        assert_eq!(encrypted.version, deserialized.version);
    }
}
