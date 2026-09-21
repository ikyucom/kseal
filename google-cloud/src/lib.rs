//! Google Cloud KMS provider for kseal.
//!
//! Decrypt side: [`Unwrapper`] calls Cloud KMS `asymmetricDecrypt`; the private
//! key never leaves the KMS and the caller needs a decrypt identity (Workload
//! Identity Federation in CI). Encrypt side: [`fetch_public_key`] reads the key
//! version's public PEM once, so sealing can then run offline with
//! `kseal::PublicKey`. Everything here is async and runs on the caller's tokio
//! runtime; the crate creates no runtime of its own.

use google_cloud_kms_v1::{
    client::KeyManagementService, model::crypto_key_version::CryptoKeyVersionAlgorithm,
};
use kseal::{DekUnwrapper, Error, KmsRef, Result};

/// A parsed Google Cloud KMS crypto key *version* resource name,
/// `projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/N`. Parsing
/// rejects any other shape, so a truncated or malformed name never reaches KMS
/// nor gets recorded in a sealed file, and callers compare structural parents
/// (the key ring) by value instead of matching a substring — a prefix check
/// treats `projects/p` as a prefix of `projects/p-evil`, an exact parent does
/// not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoKeyVersionName {
    pub project: String,
    pub location: String,
    pub key_ring: String,
    pub crypto_key: String,
    pub version: String,
}

impl std::str::FromStr for CryptoKeyVersionName {
    type Err = Error;

    /// Parse the fixed resource form; any other shape, or an empty segment, is an
    /// error.
    fn from_str(name: &str) -> Result<Self> {
        let segments: Vec<&str> = name.split('/').collect();
        match segments.as_slice() {
            [
                "projects",
                project,
                "locations",
                location,
                "keyRings",
                key_ring,
                "cryptoKeys",
                crypto_key,
                "cryptoKeyVersions",
                version,
            ] if ![project, location, key_ring, crypto_key, version]
                .iter()
                .any(|s| s.is_empty()) =>
            {
                Ok(CryptoKeyVersionName {
                    project: (*project).to_owned(),
                    location: (*location).to_owned(),
                    key_ring: (*key_ring).to_owned(),
                    crypto_key: (*crypto_key).to_owned(),
                    version: (*version).to_owned(),
                })
            }
            _ => Err(Error::Provider(format!(
                "not a fully-qualified crypto key version: {name}\n  expected projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/N"
            ))),
        }
    }
}

impl CryptoKeyVersionName {
    /// The key ring resource this version belongs to.
    pub fn key_ring(&self) -> KeyRingName {
        KeyRingName {
            project: self.project.clone(),
            location: self.location.clone(),
            key_ring: self.key_ring.clone(),
        }
    }
}

impl std::fmt::Display for CryptoKeyVersionName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "projects/{}/locations/{}/keyRings/{}/cryptoKeys/{}/cryptoKeyVersions/{}",
            self.project, self.location, self.key_ring, self.crypto_key, self.version
        )
    }
}

/// A parsed Google Cloud KMS key ring resource name,
/// `projects/P/locations/L/keyRings/R` — the parent of a crypto key version.
/// `verify --expect-key-ring` parses its argument into one and compares by
/// value, so a mistyped resource is a distinct "not a key ring" error and a
/// look-alike project cannot slip through as it would with a substring prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRingName {
    pub project: String,
    pub location: String,
    pub key_ring: String,
}

impl std::str::FromStr for KeyRingName {
    type Err = Error;

    /// Parse the fixed resource form; any other shape, or an empty segment, is an
    /// error.
    fn from_str(name: &str) -> Result<Self> {
        let segments: Vec<&str> = name.split('/').collect();
        match segments.as_slice() {
            [
                "projects",
                project,
                "locations",
                location,
                "keyRings",
                key_ring,
            ] if ![project, location, key_ring].iter().any(|s| s.is_empty()) => Ok(KeyRingName {
                project: (*project).to_owned(),
                location: (*location).to_owned(),
                key_ring: (*key_ring).to_owned(),
            }),
            _ => Err(Error::Provider(format!(
                "not a key ring resource: {name}\n  expected projects/P/locations/L/keyRings/R"
            ))),
        }
    }
}

impl std::fmt::Display for KeyRingName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "projects/{}/locations/{}/keyRings/{}",
            self.project, self.location, self.key_ring
        )
    }
}

/// Unwraps data keys by calling Cloud KMS `asymmetricDecrypt` on a crypto key
/// *version* resource (`projects/.../cryptoKeyVersions/N`).
pub struct Unwrapper {
    version: String,
    client: KeyManagementService,
}

impl Unwrapper {
    /// Build an unwrapper for the given crypto key version. Creates the KMS
    /// client using Application Default Credentials (WIF in CI).
    pub async fn new(version: impl Into<String>) -> Result<Self> {
        let version = version.into();
        let client = KeyManagementService::builder()
            .build()
            .await
            .map_err(provider_err)?;
        Ok(Self { version, client })
    }
}

impl DekUnwrapper for Unwrapper {
    async fn unwrap(&self, wrapped: &[u8]) -> Result<Vec<u8>> {
        let response = self
            .client
            .asymmetric_decrypt()
            .set_name(&self.version)
            .set_ciphertext(wrapped.to_vec())
            .send()
            .await
            .map_err(provider_err)?;
        Ok(response.plaintext.to_vec())
    }
}

/// Read a crypto key version's public key. Returns the SPKI PEM and a matching
/// [`KmsRef`], for building a `kseal::PublicKey` on the encrypt side. Rejects
/// any key whose algorithm is not RSA-OAEP-SHA256, which is what the kseal
/// envelope wraps with.
pub async fn fetch_public_key(version: impl Into<String>) -> Result<(String, KmsRef)> {
    let version = version.into();
    // Reject a malformed name before any network call, so a sealed file never
    // records a non-fully-qualified key.
    version.parse::<CryptoKeyVersionName>()?;
    let client = KeyManagementService::builder()
        .build()
        .await
        .map_err(provider_err)?;
    let public_key = client
        .get_public_key()
        .set_name(&version)
        .send()
        .await
        .map_err(provider_err)?;
    check_algorithm(&public_key.algorithm)?;
    Ok((public_key.pem, KmsRef::GoogleCloud { key: version }))
}

fn check_algorithm(algorithm: &CryptoKeyVersionAlgorithm) -> Result<()> {
    use CryptoKeyVersionAlgorithm as A;
    if matches!(
        algorithm,
        A::RsaDecryptOaep2048Sha256 | A::RsaDecryptOaep3072Sha256 | A::RsaDecryptOaep4096Sha256
    ) {
        Ok(())
    } else {
        Err(Error::Provider(format!(
            "unsupported KMS key algorithm {algorithm:?}; kseal needs RSA_DECRYPT_OAEP_*_SHA256"
        )))
    }
}

fn provider_err(e: impl std::fmt::Display) -> Error {
    Error::Provider(e.to_string())
}

#[cfg(test)]
mod tests {
    use google_cloud_kms_v1::model::crypto_key_version::CryptoKeyVersionAlgorithm as A;

    use super::{CryptoKeyVersionName, KeyRingName, check_algorithm};

    const FQ: &str = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1";

    #[test]
    fn parses_a_fully_qualified_version_and_round_trips() {
        let parsed: CryptoKeyVersionName = FQ.parse().unwrap();
        assert_eq!(parsed.project, "p");
        assert_eq!(parsed.version, "1");
        assert_eq!(
            parsed.key_ring().to_string(),
            "projects/p/locations/l/keyRings/r"
        );
        assert_eq!(parsed.to_string(), FQ);
    }

    #[test]
    fn key_ring_parses_and_rejects_non_key_rings() {
        let ring: KeyRingName = "projects/p/locations/l/keyRings/r".parse().unwrap();
        assert_eq!(ring, FQ.parse::<CryptoKeyVersionName>().unwrap().key_ring());
        for bad in [
            "",
            "projects/p/locations/l/keyRings/r/",
            "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
            "projects/p/locations/l/keyRings",
        ] {
            assert!(bad.parse::<KeyRingName>().is_err(), "{bad}");
        }
    }

    #[test]
    fn rejects_non_fully_qualified_names() {
        for bad in [
            "",
            "projects/p/locations/l/keyRings/r/cryptoKeys/k",
            "projects//locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
            "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1/extra",
            "projects/p/regions/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
        ] {
            assert!(bad.parse::<CryptoKeyVersionName>().is_err(), "{bad}");
        }
    }

    #[test]
    fn key_ring_distinguishes_look_alike_projects() {
        // The reason exact-parent beats a prefix check: `p` is a prefix of
        // `p-evil`, but their key rings are different resources.
        let ours = FQ.parse::<CryptoKeyVersionName>().unwrap().key_ring();
        let evil = "projects/p-evil/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"
            .parse::<CryptoKeyVersionName>()
            .unwrap()
            .key_ring();
        assert_ne!(ours, evil);
    }

    #[test]
    fn accepts_rsa_oaep_sha256() {
        for algorithm in [
            A::RsaDecryptOaep2048Sha256,
            A::RsaDecryptOaep3072Sha256,
            A::RsaDecryptOaep4096Sha256,
        ] {
            assert!(check_algorithm(&algorithm).is_ok());
        }
    }

    #[test]
    fn rejects_other_algorithms() {
        for algorithm in [
            A::RsaDecryptOaep2048Sha1,
            A::RsaDecryptOaep4096Sha512,
            A::GoogleSymmetricEncryption,
        ] {
            assert!(check_algorithm(&algorithm).is_err());
        }
    }
}
