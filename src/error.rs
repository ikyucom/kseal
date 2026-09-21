#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("AEAD failure: wrong key, tampered ciphertext, or secret-name mismatch")]
    Aead,
    #[error("secret name must not be empty")]
    EmptySecretName,
    #[error("RSA wrap/unwrap failed: {0}")]
    Rsa(String),
    #[error("public key PEM parse failed: {0}")]
    Pem(String),
    #[error("KMS provider failed: {0}")]
    Provider(String),
    #[error("JSON (de)serialization failed: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("unexpected data-encryption-key length: expected 32, got {0}")]
    DekLen(usize),
}

pub type Result<T> = std::result::Result<T, Error>;
