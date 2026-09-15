use thiserror::Error;

/// Errors surfaced by the Cerberus core.
///
/// Deliberately coarse: an attacker probing the unlock path must not be able to
/// tell *why* a decryption failed. Every cryptographic failure collapses into
/// [`CoreError::Decrypt`].
#[derive(Debug, Error)]
pub enum CoreError {
    #[error("unable to decrypt the vault: wrong factors, or the file has been altered")]
    Decrypt,

    #[error("the file is not a Cerberus vault")]
    BadMagic,

    #[error("unsupported vault format version: {0}")]
    UnsupportedVersion(u16),

    #[error("malformed vault header")]
    MalformedHeader,

    #[error("unknown cipher identifier: {0:#04x}")]
    UnknownCipher(u8),

    #[error("invalid cascade: {0}")]
    InvalidCascade(&'static str),

    #[error("invalid authentication factor: {0}")]
    InvalidFactor(String),

    #[error("no authentication factor supplied")]
    NoFactors,

    #[error("key derivation failed")]
    Kdf,

    #[error("serialization failed: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("entropy source unavailable: {0}")]
    Random(String),
}

pub type Result<T> = std::result::Result<T, CoreError>;
