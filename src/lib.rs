//! kseal: asymmetric-KMS envelope encryption for secrets stored in git.
//!
//! A value is sealed with AES-256-GCM under a fresh random data key; the data
//! key is then wrapped with a KMS *public* key via RSA-OAEP. Sealing needs only
//! the public key, so it runs offline with no credentials. Opening requires the
//! KMS private key (asymmetricDecrypt), which never leaves the KMS. The secret
//! name is bound as AEAD associated data, so a sealed body cannot be replayed
//! under another name. The environment (dev, prod, …) is *not* part of the
//! associated data: a value's isolation between environments rests entirely on
//! giving each environment its own KMS key, never on the sealed file. Sealing
//! the same secret name under one key that several environments can decrypt
//! removes that isolation.

mod envelope;
mod error;
mod format;
mod key;
mod provider;

/// Built-in local private-key unwrapper, for self-tests and offline decrypt.
/// Real deployments use a KMS-backed unwrapper so the private key never leaves
/// the KMS.
pub mod local;

pub use envelope::{open, rewrap, seal};
pub use error::{Error, Result};
pub use format::{KmsRef, SealedFile};
pub use key::PublicKey;
pub use provider::DekUnwrapper;
