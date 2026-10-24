use thiserror::Error;

/// Result type used throughout 2Secret.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// All errors produced by the core library.
#[derive(Debug, Error)]
pub enum Error {
    #[error("incorrect master password or Secret Key")]
    WrongPassword,
    #[error("the Secret Key is not valid: {0}")]
    InvalidSecretKey(String),
    #[error("decryption failed: the data is corrupt or was tampered with")]
    Decryption,
    #[error("encryption failed")]
    Encryption,
    #[error("unsupported format or version: {0}")]
    Unsupported(String),
    #[error("invalid input: {0}")]
    Invalid(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("permission denied: {0}")]
    PermissionDenied(String),
    /// Another account's public keys are not the ones this device knew
    /// (see `Session::recipient`).
    #[error("{0}")]
    KeyChanged(crate::profile::KeyChange),
    #[error("key derivation failed: {0}")]
    Kdf(String),
    #[error("import failed: {0}")]
    Import(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl Error {
    pub fn invalid(msg: impl Into<String>) -> Self {
        Error::Invalid(msg.into())
    }
    pub fn not_found(msg: impl Into<String>) -> Self {
        Error::NotFound(msg.into())
    }
}
