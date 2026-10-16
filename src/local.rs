use rsa::{Oaep, RsaPrivateKey, pkcs1::DecodeRsaPrivateKey as _, pkcs8::DecodePrivateKey as _};
use sha2::Sha256;

use crate::{
    error::{Error, Result},
    provider::DekUnwrapper,
};

/// A private key held locally, no KMS. Decrypt side, for self-tests and
/// fully-offline use. Real deployments use a KMS unwrapper so the private key
/// never leaves the KMS.
///
/// Decryption here uses the `rsa` crate, whose RSA decryption is not constant
/// time (RUSTSEC-2023-0071, the Marvin attack; no release fixes it). Do not put
/// this behind anything an attacker can time, such as a network decryption
/// service; a local run on a machine you trust is fine.
pub struct LocalPrivateKey {
    key: RsaPrivateKey,
}

impl LocalPrivateKey {
    pub fn new(key: RsaPrivateKey) -> Self {
        Self { key }
    }

    /// Parse an RSA private key from PEM. Accepts both PKCS#8
    /// (`-----BEGIN PRIVATE KEY-----`) and PKCS#1
    /// (`-----BEGIN RSA PRIVATE KEY-----`, the shape ssh-keygen `-m PEM` emits).
    pub fn from_pem(pem: &str) -> Result<Self> {
        let key = RsaPrivateKey::from_pkcs8_pem(pem)
            .or_else(|_| RsaPrivateKey::from_pkcs1_pem(pem))
            .map_err(|e| Error::Pem(e.to_string()))?;
        Ok(Self { key })
    }
}

impl DekUnwrapper for LocalPrivateKey {
    async fn unwrap(&self, wrapped: &[u8]) -> Result<Vec<u8>> {
        self.key
            .decrypt(Oaep::new::<Sha256>(), wrapped)
            .map_err(|e| Error::Rsa(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use rsa::{
        RsaPrivateKey,
        pkcs1::EncodeRsaPrivateKey as _,
        pkcs8::{EncodePrivateKey as _, LineEnding},
    };

    use super::LocalPrivateKey;

    #[test]
    fn from_pem_accepts_pkcs8_and_pkcs1() {
        let mut rng = rand::thread_rng();
        let key = RsaPrivateKey::new(&mut rng, 2048).expect("generate RSA key");
        let pkcs8 = key.to_pkcs8_pem(LineEnding::LF).expect("pkcs8 pem");
        let pkcs1 = key.to_pkcs1_pem(LineEnding::LF).expect("pkcs1 pem");
        assert!(LocalPrivateKey::from_pem(&pkcs8).is_ok());
        assert!(LocalPrivateKey::from_pem(&pkcs1).is_ok());
    }

    #[test]
    fn from_pem_rejects_garbage() {
        assert!(LocalPrivateKey::from_pem("not a pem").is_err());
    }
}
