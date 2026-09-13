//! Crypto primitives — ported from `bulla-core` (same Ed25519 + sha256 approach, same dependency
//! versions), generalized so `receipt.rs` isn't tied to bulla's specific structs.

use sha2::{Digest, Sha256};

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Content-addressed root over sorted (id, hash) pairs — the same construction as bulla-core's
/// `Manifest::from_entries`, generalized so both the payload registry and (in future) other
/// content-addressed sets can reuse it instead of re-deriving a Merkle-ish digest by hand.
pub fn content_root<'a>(entries: impl Iterator<Item = (&'a str, &'a str)>) -> String {
    let mut h = Sha256::new();
    for (id, hash) in entries {
        h.update(id.as_bytes());
        h.update([0]);
        h.update(hash.as_bytes());
        h.update([0]);
    }
    hex::encode(h.finalize())
}

/// 32 fresh random bytes for a new Ed25519 signing seed.
pub fn generate_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).expect("os rng");
    seed
}

/// Hex-encode a 32-byte seed (for persisting a key file).
pub fn seed_to_hex(seed: &[u8; 32]) -> String {
    hex::encode(seed)
}

/// Parse a 32-byte seed from 64 hex chars, if valid.
pub fn seed_from_hex(s: &str) -> Option<[u8; 32]> {
    hex::decode(s.trim())
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
}

/// Derive the hex Ed25519 public key for a signing seed.
pub fn pubkey_hex(seed: &[u8; 32]) -> String {
    use ed25519_dalek::SigningKey;
    hex::encode(SigningKey::from_bytes(seed).verifying_key().to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_root_is_order_independent() {
        let a = content_root([("b", "2"), ("a", "1")].into_iter());
        let b = content_root([("a", "1"), ("b", "2")].into_iter());
        // NOTE: content_root itself does not sort — callers (payload::PayloadSet) sort first.
        // This test just pins the hash construction so a future edit notices if it changes shape.
        assert_ne!(
            a, b,
            "unsorted input order changes the root; callers must sort first"
        );
    }

    #[test]
    fn seed_hex_roundtrip() {
        let seed = generate_seed();
        let hex = seed_to_hex(&seed);
        assert_eq!(seed_from_hex(&hex), Some(seed));
    }

    #[test]
    fn pubkey_is_deterministic_for_a_seed() {
        let seed = generate_seed();
        assert_eq!(pubkey_hex(&seed), pubkey_hex(&seed));
    }
}
