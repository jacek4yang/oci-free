use std::fmt;

/// A configuration value that must never appear in logs, diagnostics, or error
/// messages.
///
/// `Debug` and `Display` are implemented so that accidentally formatting a
/// secret cannot leak it. The plaintext is only reachable through the explicit
/// [`Secret::expose`] accessor.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

/// Placeholder rendered in place of secret material.
pub const REDACTED: &str = "<redacted>";

impl Secret {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Read the underlying plaintext.
    ///
    /// Call sites should be short-lived and must not forward the value into
    /// logging or serialization.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

#[cfg(test)]
mod tests {
    use super::{REDACTED, Secret};

    #[test]
    fn debug_and_display_never_reveal_the_value() {
        let secret = Secret::new("correct horse battery staple");
        assert_eq!(format!("{secret:?}"), REDACTED);
        assert_eq!(format!("{secret}"), REDACTED);
        assert!(!format!("{secret:#?} {secret}").contains("battery"));
    }

    #[test]
    fn explicit_accessor_returns_the_value() {
        let secret = Secret::new("s3cret");
        assert_eq!(secret.expose(), "s3cret");
    }
}
