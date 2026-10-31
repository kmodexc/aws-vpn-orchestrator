//! Small shared helpers: randomness, hashing, constant-time comparison, clocks and locks.

use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// The operating system's CSPRNG failed. This is fatal for the current operation.
#[derive(Debug, thiserror::Error)]
#[error("the operating system random number generator failed")]
pub struct RandomError;

/// Fill an array with bytes from the operating system CSPRNG.
pub fn random_bytes<const N: usize>() -> Result<[u8; N], RandomError> {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).map_err(|_| RandomError)?;
    Ok(buf)
}

/// 256 random bits, base64url without padding (43 characters).
pub fn random_token() -> Result<String, RandomError> {
    Ok(b64url(&random_bytes::<32>()?))
}

pub fn b64url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub fn b64std(data: &[u8]) -> String {
    STANDARD.encode(data)
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Constant-time string equality. Both sides are hashed first so that the comparison does not
/// even leak the length of the expected value.
pub fn ct_eq_str(a: &str, b: &str) -> bool {
    sha256(a.as_bytes()).ct_eq(&sha256(b.as_bytes())).into()
}

/// Current wall-clock time in unix seconds.
pub fn unix_now() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

/// Current wall-clock time in unix milliseconds.
pub fn unix_now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// Lock a std mutex, recovering from poisoning. The protected data structures in this crate are
/// always left consistent between statements, so continuing after a panic elsewhere is safe and
/// keeps the server available.
pub fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Clamp an x25519 private scalar as WireGuard and Xray do when generating keys.
pub fn clamp_x25519(mut key: [u8; 32]) -> [u8; 32] {
    key[0] &= 248;
    key[31] &= 127;
    key[31] |= 64;
    key
}

/// Derive the x25519 public key for a private key.
pub fn x25519_public(private: [u8; 32]) -> [u8; 32] {
    let secret = x25519_dalek::StaticSecret::from(private);
    x25519_dalek::PublicKey::from(&secret).to_bytes()
}

/// Remove control characters and truncate to `max_chars` characters.
pub fn sanitize_text(input: &str, max_chars: usize) -> String {
    input
        .chars()
        .filter(|c| !c.is_control())
        .take(max_chars)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_works() {
        assert!(ct_eq_str("abc", "abc"));
        assert!(!ct_eq_str("abc", "abd"));
        assert!(!ct_eq_str("abc", "abcd"));
        assert!(!ct_eq_str("", "a"));
    }

    #[test]
    fn random_token_shape() {
        let t = random_token().unwrap();
        assert_eq!(t.len(), 43);
        assert_ne!(t, random_token().unwrap());
    }

    #[test]
    fn sanitize_strips_controls() {
        assert_eq!(sanitize_text("a\nb\u{0}c", 10), "abc");
        assert_eq!(sanitize_text("abcdef", 3), "abc");
    }
}
