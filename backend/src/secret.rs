//! A wrapper for secret values that never prints its content.

use std::fmt;

use zeroize::Zeroize;

/// Holds a secret. `Debug` prints `[REDACTED]`, and the value is wiped from memory on drop.
/// There is deliberately no `Display` and no `Serialize` implementation.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret<T: Zeroize>(T);

impl<T: Zeroize> Secret<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// Access the secret value. Call sites should be easy to audit, so keep the name explicit.
    pub fn expose(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T: Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl From<String> for Secret<String> {
    fn from(value: String) -> Self {
        Self(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let s = Secret::new("hunter2".to_string());
        assert_eq!(format!("{s:?}"), "[REDACTED]");
        assert_eq!(s.expose(), "hunter2");
    }
}
