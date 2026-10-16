use rsa::{Oaep, RsaPublicKey, pkcs8::DecodePublicKey as _};
use sha2::Sha256;

use crate::{
    error::{Error, Result},
    format::KmsRef,
};

/// The encrypt side: an RSA public key plus the KMS key version it belongs to.
/// Sealing wraps the data key with this and records the version; it needs no KMS
/// access or credentials. Any provider (the local one, Google Cloud, ...)
/// supplies the PEM and a matching [`KmsRef`]. There is only ever this one
/// encrypt shape, so it is a concrete type, not a trait.
pub struct PublicKey {
    key: RsaPublicKey,
    kms_ref: KmsRef,
}

impl PublicKey {
    /// Build from an SPKI PEM (`-----BEGIN PUBLIC KEY-----`), such as the one
    /// Google Cloud KMS `GetPublicKey` returns.
    pub fn from_pem(pem: &str, kms_ref: KmsRef) -> Result<Self> {
        let key = RsaPublicKey::from_public_key_pem(pem).map_err(|e| Error::Pem(e.to_string()))?;
        Ok(Self { key, kms_ref })
    }

    /// Wrap a data key with this public key via RSA-OAEP(SHA-256).
    pub fn wrap(&self, dek: &[u8]) -> Result<Vec<u8>> {
        let mut rng = rand::thread_rng();
        self.key
            .encrypt(&mut rng, Oaep::new::<Sha256>(), dek)
            .map_err(|e| Error::Rsa(e.to_string()))
    }

    /// The key version to record in the sealed file.
    pub fn kms_ref(&self) -> KmsRef {
        self.kms_ref.clone()
    }
}
